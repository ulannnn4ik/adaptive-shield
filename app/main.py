"""
Adaptive Shield — DDoS & Brute Force Protection System
Main application entry point.
"""

import asyncio
import time
import httpx
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from fastapi.responses import Response
from starlette.requests import Request

from app.middleware.shield import ShieldMiddleware
from app.api.routes import app_router, dashboard_api
from app.core import close_redis
from app.core.alerts import close_session
from app.core.database import init_db, Database
from app.detectors.ip_reputation import IPReputation


async def decay_task():
    """Every 60s applies decay to all flagged IPs."""
    while True:
        try:
            await asyncio.sleep(60)
            flagged = await IPReputation.get_all_flagged()
            for ip_info in flagged:
                ip = ip_info["ip"]
                score = await IPReputation.get_score(ip)
                if score > 0:
                    from app.core import get_redis
                    r = await get_redis()
                    await r.hset(f"shield:rep:{ip}", mapping={
                        "score": str(score),
                        "last_update": str(time.time()),
                    })
        except Exception:
            pass


async def metrics_snapshot_task():
    """Every hour saves metrics snapshot to SQLite."""
    while True:
        try:
            await asyncio.sleep(3600)
            from app.core.logger import EventLogger
            metrics = await EventLogger.get_metrics()
            await Database.save_metrics_snapshot(metrics)
        except Exception:
            pass


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    decay = asyncio.create_task(decay_task())
    snapshots = asyncio.create_task(metrics_snapshot_task())
    yield
    # Shutdown — save final snapshot
    try:
        from app.core.logger import EventLogger
        metrics = await EventLogger.get_metrics()
        await Database.save_metrics_snapshot(metrics)
    except Exception:
        pass
    decay.cancel()
    snapshots.cancel()
    await close_redis()
    await close_session()


app = FastAPI(
    title="Adaptive Shield",
    description="DDoS & Brute Force Protection System",
    version="1.0.0",
    lifespan=lifespan,
)

app.add_middleware(ShieldMiddleware)
app.include_router(app_router)
app.include_router(dashboard_api)

templates = Jinja2Templates(directory="app/dashboard/templates")


@app.get("/dashboard")
async def dashboard(request: Request):
    from app.core.auth import get_token_from_request, decode_token
    from fastapi.responses import RedirectResponse

    # Extract and validate JWT token
    token = get_token_from_request(request)
    if not token:
        return RedirectResponse(url="/site/login.html")

    payload = decode_token(token)
    if not payload:
        # Token invalid or expired
        return RedirectResponse(url="/site/login.html")

    if payload.get("role") != "admin":
        # Not admin — redirect to account page
        return RedirectResponse(url="/site/account.html")

    return templates.TemplateResponse("dashboard.html", {"request": request})




@app.get("/admin")
async def admin_panel(request: Request):
    """Admin panel — user management. Requires admin role."""
    from app.core.auth import get_token_from_request, decode_token
    from fastapi.responses import RedirectResponse, FileResponse

    token = get_token_from_request(request)
    if not token:
        return RedirectResponse(url="/site/login.html")

    payload = decode_token(token)
    if not payload or payload.get("role") != "admin":
        return RedirectResponse(url="/site/login.html")

    return FileResponse("app/dashboard/templates/admin.html")

@app.get("/health")
async def health():
    return {"status": "ok"}


# ── REVERSE PROXY ─────────────────────────────────────────────
# Проксирует все запросы на TARGET_URL из .env
# Использование: добавь в .env → PROXY_TARGET=http://httpbin.org
# Доступ: http://shield.local:8000/proxy/anything

@app.api_route(
    "/proxy/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]
)
async def reverse_proxy(request: Request, path: str):
    from config.settings import settings

    target = settings.proxy_target
    if not target:
        return Response(
            content='{"error": "Proxy не настроен. Добавьте PROXY_TARGET в .env"}',
            status_code=503,
            media_type="application/json"
        )

    # Строим целевой URL
    target_url = f"{target.rstrip('/')}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    # Копируем заголовки — убираем hop-by-hop
    skip_headers = {"host", "connection", "transfer-encoding", "keep-alive"}
    headers = {
        k: v for k, v in request.headers.items()
        if k.lower() not in skip_headers
    }

    # Добавляем Shield заголовки
    headers["X-Forwarded-By"] = "Adaptive-Shield"
    headers["X-Real-IP"] = request.client.host if request.client else "unknown"

    # Читаем тело запроса
    body = await request.body()

    try:
        async with httpx.AsyncClient(timeout=15.0, follow_redirects=True) as client:
            proxy_response = await client.request(
                method=request.method,
                url=target_url,
                headers=headers,
                content=body,
            )

        # Убираем проблемные заголовки из ответа
        response_headers = dict(proxy_response.headers)
        for h in ["transfer-encoding", "connection", "content-encoding"]:
            response_headers.pop(h, None)

        return Response(
            content=proxy_response.content,
            status_code=proxy_response.status_code,
            headers=response_headers,
            media_type=proxy_response.headers.get("content-type"),
        )

    except httpx.ConnectError:
        return Response(
            content=f'{{"error": "Не удалось подключиться к {target}"}}',
            status_code=502,
            media_type="application/json"
        )
    except httpx.TimeoutException:
        return Response(
            content='{"error": "Таймаут соединения с целевым сервером"}',
            status_code=504,
            media_type="application/json"
        )


app.mount(
    "/site",
    StaticFiles(directory="app/dashboard/templates/site", html=True),
    name="site",
)
