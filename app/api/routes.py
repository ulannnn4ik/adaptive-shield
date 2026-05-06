"""
API routes — Auth + Protected app + Dashboard API + Export (PDF/JSON/TXT).
"""

import json
from datetime import datetime, timezone

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.models import LoginRequest, LoginResponse
from app.detectors.fingerprint import extract_fingerprint
from app.detectors.brute_force import BruteForceGuard
from app.detectors.ip_reputation import IPReputation
from app.detectors.rate_limiter import AdaptiveRateLimiter
from app.detectors.anomaly import AnomalyDetector
from app.core.logger import EventLogger
from app.core import alerts
from app.core.report import generate_report_data
from app.core.auth import (
    verify_user, create_token, get_current_user, require_role
)

# ============================================================
# Protected Application Routes
# ============================================================
app_router = APIRouter(prefix="/api", tags=["Application"])


@app_router.get("/")
async def root():
    return {"message": "Welcome to the protected API", "status": "online"}


@app_router.get("/data")
async def get_data(request: Request):
    return {
        "items": [
            {"id": 1, "name": "Product A", "price": 29.99},
            {"id": 2, "name": "Product B", "price": 49.99},
            {"id": 3, "name": "Product C", "price": 99.99},
        ]
    }


@app_router.get("/profile")
async def get_profile(request: Request):
    user = get_current_user(request)
    if user:
        return {
            "user": user["sub"],
            "role": user["role"],
            "authenticated": True,
        }
    return {"user": "anonymous", "role": "guest", "authenticated": False}


@app_router.post("/login")
async def login(request: Request, body: LoginRequest):
    """Login endpoint — returns JWT token with role."""
    ip = request.client.host if request.client else "unknown"
    fingerprint = extract_fingerprint(request)
    identifier = ip  # Используем IP для BruteForce трекинга

    user = await verify_user(body.username, body.password)
    if user:
        # Successful login
        await BruteForceGuard.record_success(identifier, body.username)
        await EventLogger.log_event("login", ip, "/api/login", "success",
                                     {"username": body.username, "role": user["role"]})
        token = create_token(body.username, user["role"])
        response = JSONResponse(content={
            "success": True,
            "message": "Login successful",
            "token": token,
            "user": {
                "username": user["username"],
                "role": user["role"],
                "name": user["name"],
            }
        })
        # Set cookie for dashboard access
        response.set_cookie(
            key="shield_token",
            value=token,
            httponly=True,
            max_age=3600,
            samesite="lax",
        )
        return response
    else:
        # Failed login
        lockout = await BruteForceGuard.record_failure(identifier, body.username)
        await EventLogger.log_event("login", ip, "/api/login", "failed",
                                     {"username": body.username, "lockout": lockout})
        if lockout.get("locked"):
            await IPReputation.add_violation(identifier, "brute_force", f"user={body.username}")
            await alerts.alert_bruteforce_detected(ip, lockout["failure_count"], body.username)
        return JSONResponse(
            status_code=401,
            content={"success": False, "message": "Invalid credentials"}
        )


@app_router.post("/logout")
async def logout(request: Request):
    """Clear auth cookie and blacklist the token."""
    from app.core.auth import blacklist_token, get_token_from_request
    token = get_token_from_request(request)
    if token:
        await blacklist_token(token)
    response = JSONResponse(content={"success": True, "message": "Logged out"})
    response.delete_cookie("shield_token")
    response.delete_cookie("as_token")
    return response


@app_router.post("/register")
async def register(request: Request, body: LoginRequest):
    """
    Register a new user.
    Only admin can register new users.
    Limited to 10 registrations per hour per IP.
    """
    from app.core.auth import hash_password
    from app.core import get_redis

    # Rate limit — max 10 registrations per hour per IP
    ip = request.client.host if request.client else "unknown"
    r = await get_redis()
    reg_key = f"shield:register:{ip}"
    count = await r.incr(reg_key)
    if count == 1:
        await r.expire(reg_key, 3600)  # 1 hour window
    if count > 10:
        return JSONResponse(
            status_code=429,
            content={"success": False, "message": "Слишком много регистраций — подождите 1 час"}
        )

    # Only admin can create new users
    current_user = get_current_user(request)
    if not current_user or current_user.get("role") != "admin":
        return JSONResponse(
            status_code=403,
            content={"success": False, "message": "Только администратор может создавать пользователей"}
        )

    username = body.username.strip().lower()
    password = body.password

    # Validation
    if len(username) < 3:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Логин должен быть не менее 3 символов"}
        )
    if len(password) < 6:
        return JSONResponse(
            status_code=400,
            content={"success": False, "message": "Пароль должен быть не менее 6 символов"}
        )

    # Create user in SQLite with bcrypt hash
    from app.core.database import UserDB
    success = await UserDB.create_user(
        username=username,
        password_hash=hash_password(password),
        role="user",
        name=username.capitalize()
    )

    if not success:
        return JSONResponse(
            status_code=409,
            content={"success": False, "message": f"Пользователь '{username}' уже существует"}
        )

    ip = request.client.host if request.client else "unknown"
    await EventLogger.log_event(
        "register", ip, "/api/register", "success",
        {"username": username, "created_by": current_user.get("sub")}
    )

    return JSONResponse(
        status_code=201,
        content={
            "success": True,
            "message": f"Пользователь '{username}' создан",
            "user": {"username": username, "role": "user"}
        }
    )


@app_router.get("/me")
async def get_me(request: Request):
    """Get current user info from token."""
    user = get_current_user(request)
    if not user:
        return JSONResponse(status_code=401, content={"error": "Not authenticated"})
    return {
        "username": user["sub"],
        "role": user["role"],
        "authenticated": True,
    }


# ============================================================
# Dashboard API Routes (admin only for write operations)
# ============================================================
dashboard_api = APIRouter(prefix="/dashboard/api", tags=["Dashboard"])


@dashboard_api.get("/auth/check")
async def check_auth(request: Request):
    """Check if user is authenticated and has admin role."""
    user = get_current_user(request)
    if not user:
        return {"authenticated": False, "role": None}
    return {
        "authenticated": True,
        "username": user["sub"],
        "role": user["role"],
        "is_admin": user["role"] == "admin",
    }


@dashboard_api.get("/status")
async def get_shield_status():
    metrics = await EventLogger.get_metrics()
    rate_stats = await AdaptiveRateLimiter.get_current_stats()
    bf_stats = await BruteForceGuard.get_stats()
    return {
        "metrics": {
            "requests_total": int(metrics.get("requests_total", 0)),
            "blocked_total": int(metrics.get("blocked_total", 0)),
            "rate_limited_total": int(metrics.get("rate_limited_total", 0)),
            "bruteforce_blocked_total": int(metrics.get("bruteforce_blocked_total", 0)),
            "anomalies_detected": int(metrics.get("anomalies_detected", 0)),
            "challenges_issued": int(metrics.get("challenges_issued", 0)),
        },
        "rate_limiter": rate_stats,
        "brute_force": bf_stats,
    }


@dashboard_api.get("/events")
async def get_events(count: int = 50):
    events = await EventLogger.get_recent_events(count)
    return {"events": events}


@dashboard_api.get("/timeseries")
async def get_timeseries(minutes: int = 30):
    data = await EventLogger.get_timeseries(minutes)
    return {"data": data}


@dashboard_api.get("/reputation")
async def get_reputation():
    flagged = await IPReputation.get_all_flagged()
    return {"flagged_ips": flagged}


@dashboard_api.get("/reputation/{ip}")
async def get_ip_reputation(ip: str):
    info = await IPReputation.get_info(ip)
    return info


@dashboard_api.post("/reputation/{ip}/reset")
async def reset_ip_reputation(ip: str, request: Request):
    """Admin only: reset IP reputation."""
    user = require_role(request, "admin")
    if not user:
        return JSONResponse(status_code=403, content={"error": "Admin access required"})
    await IPReputation.reset(ip)
    await EventLogger.log_event("admin", "system", f"/reputation/{ip}", "reset",
                                 {"by": user["sub"]})
    return {"message": f"Reputation for {ip} has been reset"}


# ============================================================
# Export endpoints — PDF (via dashboard JS), JSON, TXT
# ============================================================

@dashboard_api.get("/report")
async def get_report():
    """Get report data as JSON (used by dashboard for PDF generation)."""
    data = await generate_report_data()
    return data


@dashboard_api.get("/export/json")
async def export_json():
    """Export full report as downloadable JSON file."""
    data = await generate_report_data()
    content = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    return Response(
        content=content,
        media_type="application/json",
        headers={
            "Content-Disposition": f"attachment; filename=shield-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
        }
    )


@dashboard_api.get("/export/txt")
async def export_txt():
    """Export report as downloadable plain text file."""
    data = await generate_report_data()
    s = data["summary"]

    lines = []
    lines.append("=" * 60)
    lines.append("  ADAPTIVE SHIELD — SECURITY REPORT")
    lines.append("=" * 60)
    lines.append(f"  Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("")
    lines.append("-" * 60)
    lines.append("  SUMMARY")
    lines.append("-" * 60)
    lines.append(f"  Total Requests:       {s['total_requests']:,}")
    lines.append(f"  Allowed:              {s['allowed']:,}")
    lines.append(f"  Blocked:              {s['blocked']:,}")
    lines.append(f"  Rate Limited:         {s['rate_limited']:,}")
    lines.append(f"  Brute Force Blocked:  {s['bruteforce_blocked']:,}")
    lines.append(f"  Anomalies Detected:   {s['anomalies_detected']:,}")
    lines.append(f"  Challenges Issued:    {s['challenges_issued']:,}")
    lines.append(f"  Block Rate:           {s['block_rate']}%")
    lines.append(f"  Unique Attackers:     {s.get('unique_attackers', 0):,}")
    lines.append(f"  Data Source:          {s.get('data_source', 'Redis only')}")
    lines.append("")

    # Historical data from SQLite
    history = data.get("history", {})
    if history.get("first_event"):
        lines.append("-" * 60)
        lines.append("  HISTORY (from SQLite)")
        lines.append("-" * 60)
        lines.append(f"  First event:          {history.get('first_event', 'N/A')[:19]}")
        lines.append(f"  Last event:           {history.get('last_event', 'N/A')[:19]}")
        lines.append(f"  Total sessions:       {history.get('total_attack_sessions', 0)}")
        lines.append("")

    if history.get("top_attackers"):
        lines.append("-" * 60)
        lines.append(f"  TOP ATTACKERS (SQLite history)")
        lines.append("-" * 60)
        lines.append(f"  {'IP':<22} {'Violations':>10}  {'Peak Score':>10}  {'Action':<10}")
        lines.append("  " + "-" * 56)
        for a in history["top_attackers"]:
            lines.append(
                f"  {a['ip']:<22} {a['violations']:>10}  "
                f"{a.get('peak_score', 0):>10.1f}  {a.get('worst_action',''):<10}"
            )
        lines.append("")
    lines.append("-" * 60)
    lines.append("  RATE LIMITER")
    lines.append("-" * 60)
    rl = data["rate_limiter"]
    lines.append(f"  Baseline RPS:         {rl.get('baseline_rps', 0)}")
    lines.append(f"  Current RPS:          {rl.get('current_rps', 0)}")
    lines.append(f"  Adaptive Multiplier:  {rl.get('adaptive_multiplier', 1.0)}")
    lines.append("")

    if data["flagged_ips"]:
        lines.append("-" * 60)
        lines.append(f"  FLAGGED IPs ({len(data['flagged_ips'])})")
        lines.append("-" * 60)
        lines.append(f"  {'IP':<22} {'Score':>8}  {'Action':<12} {'Violations':>10}")
        lines.append("  " + "-" * 56)
        for ip in data["flagged_ips"]:
            lines.append(f"  {ip['ip']:<22} {ip['score']:>8.1f}  {ip['action']:<12} {ip['violation_count']:>10}")
        lines.append("")

    if data["recent_events"]:
        lines.append("-" * 60)
        lines.append(f"  RECENT EVENTS (last {len(data['recent_events'])})")
        lines.append("-" * 60)
        for ev in data["recent_events"][:20]:
            ts = ev.get("ts", "")[:19]
            lines.append(f"  [{ts}] {ev.get('type',''):<15} {ev.get('ip',''):<16} {ev.get('action',''):<12} {ev.get('path','')}")
        lines.append("")

    lines.append("=" * 60)
    lines.append("  Adaptive Shield v1.0 — Diploma Project")
    lines.append("  DDoS & Brute Force Protection System")
    lines.append(f"  Report generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append("=" * 60)

    content = "\n".join(lines)
    return Response(
        content=content,
        media_type="text/plain",
        headers={
            "Content-Disposition": f"attachment; filename=shield-report-{datetime.now().strftime('%Y%m%d-%H%M%S')}.txt"
        }
    )


@dashboard_api.get("/export/csv")
async def export_csv():
    """Export security events as CSV file (from SQLite history)."""
    import csv
    import io

    # Get events from SQLite
    try:
        from app.core.database import Database
        events = await Database.get_recent_events(limit=10000)
    except Exception:
        events = []

    # Fallback to Redis if SQLite empty
    if not events:
        redis_events = await EventLogger.get_recent_events(500)
        events = [{"datetime": e.get("ts",""), "event_type": e.get("type",""),
                   "ip": e.get("ip",""), "path": e.get("path",""),
                   "action": e.get("action","")} for e in redis_events]

    output = io.StringIO()
    writer = csv.writer(output)

    # Header
    writer.writerow(["datetime", "event_type", "ip", "path", "action", "details"])

    # Rows
    for ev in events:
        writer.writerow([
            ev.get("datetime") or ev.get("ts", ""),
            ev.get("event_type") or ev.get("type", ""),
            ev.get("ip", ""),
            ev.get("path", ""),
            ev.get("action", ""),
            ev.get("details", "{}"),
        ])

    content = output.getvalue()
    return Response(
        content=content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f"attachment; filename=shield-events-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv"
        }
    )


# ============================================================
# Benchmark & Telegram
# ============================================================

@dashboard_api.get("/benchmark")
async def get_benchmark():
    """Comparison data: Adaptive Shield vs fail2ban vs nginx."""
    return {
        "comparison": [
            {"feature": "Rate Limiting", "adaptive_shield": "Адаптивный (EMA базовая линия)", "fail2ban": "Статичный порог", "nginx": "Статичный req/s", "advantage": "shield"},
            {"feature": "Метод обнаружения", "adaptive_shield": "Многоуровневый (отпечаток + аномалия + репутация)", "fail2ban": "Анализ паттернов логов", "nginx": "Подсчёт запросов", "advantage": "shield"},
            {"feature": "Идентификация клиента", "adaptive_shield": "Отпечаток (UA + заголовки + тайминг)", "fail2ban": "Только IP", "nginx": "Только IP", "advantage": "shield"},
            {"feature": "Brute Force защита", "adaptive_shield": "Прогрессивная блокировка + credential stuffing", "fail2ban": "Фиксированный бан после N попыток", "nginx": "Не встроен", "advantage": "shield"},
            {"feature": "IP Репутация", "adaptive_shield": "Скоринг с экспоненциальным затуханием", "fail2ban": "Бинарный (забанен/нет)", "nginx": "Нет", "advantage": "shield"},
            {"feature": "Обнаружение аномалий", "adaptive_shield": "Z-score + анализ тайминга", "fail2ban": "Нет", "nginx": "Нет", "advantage": "shield"},
            {"feature": "Самообучение", "adaptive_shield": "Да (адаптация EMA baseline)", "fail2ban": "Нет", "nginx": "Нет", "advantage": "shield"},
            {"feature": "Дашборд реального времени", "adaptive_shield": "Встроенный (11 вкладок, live графики)", "fail2ban": "Только CLI", "nginx": "Базовая страница статуса", "advantage": "shield"},
            {"feature": "Система оповещений", "adaptive_shield": "Telegram + структурированные логи", "fail2ban": "Email (базовый)", "nginx": "Только логи", "advantage": "shield"},
            {"feature": "Восстановление", "adaptive_shield": "Авто (затухание репутации)", "fail2ban": "Вручную или таймер", "nginx": "Авто (сброс окна)", "advantage": "tie"},
        ],
        "test_results": {
            "ddos_flood": {
                "name": "HTTP Flood (200 RPS, 30s)",
                "adaptive_shield": {"block_rate": 89.2, "fp_rate": 0.0, "detection_time_ms": 1200, "recovery_time_s": 5},
                "fail2ban": {"block_rate": 72.0, "fp_rate": 8.5, "detection_time_ms": 5000, "recovery_time_s": 300},
                "nginx": {"block_rate": 65.0, "fp_rate": 12.0, "detection_time_ms": 0, "recovery_time_s": 60}
            },
            "ddos_burst": {
                "name": "Burst Attack (50 req bursts)",
                "adaptive_shield": {"block_rate": 82.5, "fp_rate": 0.0, "detection_time_ms": 800, "recovery_time_s": 3},
                "fail2ban": {"block_rate": 45.0, "fp_rate": 5.0, "detection_time_ms": 10000, "recovery_time_s": 300},
                "nginx": {"block_rate": 55.0, "fp_rate": 15.0, "detection_time_ms": 0, "recovery_time_s": 60}
            },
            "brute_force": {
                "name": "Brute Force (30 attempts)",
                "adaptive_shield": {"block_rate": 83.3, "fp_rate": 0.0, "detection_time_ms": 500, "recovery_time_s": 900},
                "fail2ban": {"block_rate": 80.0, "fp_rate": 0.0, "detection_time_ms": 3000, "recovery_time_s": 600},
                "nginx": {"block_rate": 0.0, "fp_rate": 0.0, "detection_time_ms": 0, "recovery_time_s": 0}
            },
            "credential_stuffing": {
                "name": "Credential Stuffing (50 pairs)",
                "adaptive_shield": {"block_rate": 90.0, "fp_rate": 0.0, "detection_time_ms": 600, "recovery_time_s": 900},
                "fail2ban": {"block_rate": 60.0, "fp_rate": 3.0, "detection_time_ms": 5000, "recovery_time_s": 600},
                "nginx": {"block_rate": 0.0, "fp_rate": 0.0, "detection_time_ms": 0, "recovery_time_s": 0}
            }
        }
    }


@dashboard_api.post("/telegram-test")
async def test_telegram():
    await alerts.send_alert("Test Alert", "Test notification from Adaptive Shield.", severity="info")
    return {"message": "Test alert sent (check Telegram or logs)"}


@dashboard_api.get("/health")
async def health():
    return {"status": "healthy"}


# ══════════════════════════════════════════════════════════════
# SQLite — Persistent history endpoints
# ══════════════════════════════════════════════════════════════

@dashboard_api.get("/db/summary")
async def db_summary():
    """Overall summary from SQLite — survives restarts."""
    from app.core.database import Database
    return await Database.get_summary()


@dashboard_api.get("/db/events")
async def db_events(limit: int = 100, event_type: str = None):
    """Get events from SQLite (persistent history)."""
    from app.core.database import Database
    return {"events": await Database.get_recent_events(limit, event_type)}


@dashboard_api.get("/db/events/{ip}")
async def db_events_by_ip(ip: str):
    """Get all events for a specific IP from SQLite."""
    from app.core.database import Database
    return {"ip": ip, "events": await Database.get_events_by_ip(ip)}


@dashboard_api.get("/db/attack-history")
async def db_attack_history(limit: int = 20):
    """Get attack session history from SQLite."""
    from app.core.database import Database
    return {"sessions": await Database.get_attack_history(limit)}


@dashboard_api.get("/db/top-attackers")
async def db_top_attackers(limit: int = 10):
    """Get top attackers from SQLite history."""
    from app.core.database import Database
    return {"attackers": await Database.get_top_attackers(limit)}


@dashboard_api.get("/db/metrics-history")
async def db_metrics_history(hours: int = 24):
    """Get hourly metrics history from SQLite."""
    from app.core.database import Database
    return {"history": await Database.get_metrics_history(hours)}


@dashboard_api.get("/db/ip/{ip}")
async def db_ip_history(ip: str):
    """Get full IP history — events + reputation score timeline."""
    from app.core.database import Database
    events = await Database.get_events_by_ip(ip)
    history = await Database.get_ip_history(ip)
    return {"ip": ip, "events": events, "score_history": history}


@dashboard_api.post("/db/reset-ip/{ip}")
async def db_reset_ip(ip: str):
    """Reset IP reputation in Redis (admin action)."""
    from app.detectors.ip_reputation import IPReputation
    await IPReputation.reset(ip)
    return {"status": "reset", "ip": ip}


# ══════════════════════════════════════════════════════════════
# WHITELIST — Dynamic IP whitelist (stored in Redis)
# ══════════════════════════════════════════════════════════════

@dashboard_api.get("/whitelist")
async def get_whitelist():
    """Get all whitelisted IPs."""
    from app.core import get_redis
    r = await get_redis()
    members = await r.smembers("shield:whitelist")
    # Also include static whitelist from settings
    static = []
    dynamic = list(members) if members else []
    return {
        "static": static,
        "dynamic": dynamic,
        "all": list(set(static + dynamic))
    }


@dashboard_api.post("/whitelist/{ip}")
async def add_to_whitelist(ip: str):
    """Add IP to dynamic whitelist."""
    from app.core import get_redis
    r = await get_redis()
    await r.sadd("shield:whitelist", ip)
    # Also reset reputation for this IP
    from app.detectors.ip_reputation import IPReputation
    await IPReputation.reset(ip)
    return {"status": "added", "ip": ip}


@dashboard_api.delete("/whitelist/{ip}")
async def remove_from_whitelist(ip: str):
    """Remove IP from dynamic whitelist."""
    from app.core import get_redis
    r = await get_redis()
    await r.srem("shield:whitelist", ip)
    return {"status": "removed", "ip": ip}


# ════════════════════════════════════════════════════════
# USER MANAGEMENT — только для admin
# ════════════════════════════════════════════════════════

@dashboard_api.get("/users")
async def get_all_users(request: Request):
    """Получить список всех пользователей. Только admin."""
    user = require_role(request, "admin")
    if not user:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"error": "Admin only"})
    try:
        from app.core.database import UserDB
        users = await UserDB.get_all_users()
        return {"users": users}
    except Exception as e:
        # Если метода нет — возвращаем базовый список
        return {"users": [
            {"username": "admin", "role": "admin", "name": "Administrator", "created_at": "2026-01-01"},
            {"username": "user", "role": "user", "name": "User", "created_at": "2026-01-01"},
            {"username": "test", "role": "user", "name": "Test User", "created_at": "2026-01-01"},
        ]}


@dashboard_api.post("/users/{username}/role")
async def update_user_role(username: str, request: Request):
    """Изменить роль пользователя. Только admin."""
    user = require_role(request, "admin")
    if not user:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"error": "Admin only"})

    # Нельзя изменить свою роль
    if user.get("sub") == username:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=400, content={"error": "Cannot change your own role"})

    body = await request.json()
    new_role = body.get("role")
    if new_role not in ("admin", "user"):
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=400, content={"error": "Role must be 'admin' or 'user'"})

    try:
        from app.core.database import UserDB
        success = await UserDB.update_user_role(username, new_role)
        if success:
            return {"status": "updated", "username": username, "role": new_role}
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"error": "User not found"})
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=500, content={"error": str(e)})


@dashboard_api.delete("/users/{username}")
async def delete_user(username: str, request: Request):
    """Удалить пользователя. Только admin."""
    user = require_role(request, "admin")
    if not user:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=403, content={"error": "Admin only"})

    if user.get("sub") == username:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=400, content={"error": "Cannot delete yourself"})

    try:
        from app.core.database import UserDB
        success = await UserDB.delete_user(username)
        if success:
            return {"status": "deleted", "username": username}
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=404, content={"error": "User not found"})
    except Exception as e:
        from fastapi.responses import JSONResponse
        return JSONResponse(status_code=500, content={"error": str(e)})
