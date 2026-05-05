"""
Shield Middleware — main entry point for all request protection.
Updated: auth endpoints handled properly, role-based access support.
Added: Slowloris protection via request timeout.
Added: Bot/Scanner User-Agent detection.
Added: Suspicious path detection (scanners, probes).
Added: Global traffic counter for Distributed DDoS detection.
"""

import time
import asyncio
import re
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse
import structlog

from config.settings import settings
from app.detectors.fingerprint import extract_fingerprint, is_suspicious_fingerprint
from app.detectors.rate_limiter import AdaptiveRateLimiter
from app.detectors.ip_reputation import IPReputation
from app.detectors.anomaly import AnomalyDetector
from app.detectors.brute_force import BruteForceGuard
from app.core.logger import EventLogger
from app.core import alerts

log = structlog.get_logger()


class ShieldMiddleware(BaseHTTPMiddleware):
    AUTH_PATHS = {"/api/login", "/api/auth/login", "/login"}
    SKIP_PATHS = {
        "/health", "/docs", "/openapi.json", "/favicon.ico",
        "/api/logout", "/api/me", "/site/admin.html", "/admin",
    }
    SKIP_PREFIXES = {"/site/", "/static/"}

    # ── HONEYPOT PATHS ────────────────────────────────────────
    # Пути-ловушки: легитимный пользователь НИКОГДА сюда не зайдёт.
    # Кто зашёл — однозначно сканер или хакер → немедленный бан на 1 час.
    # Возвращаем 200 с фейковыми данными (не 403/404) — тратим время атакующего.
    HONEYPOT_PATHS = {
        "/.env",
        "/.git/config",
        "/wp-admin",
        "/wp-login.php",
        "/phpmyadmin",
        "/.aws/credentials",
        "/config.php",
        "/setup.php",
    }
    HONEYPOT_BAN_SECONDS = 3600  # 1 час бана за попытку

    # ── SLOWLORIS PROTECTION ──────────────────────────────────
    REQUEST_TIMEOUT = 10        # секунд — убиваем медленные соединения
    SLOW_REQUEST_THRESHOLD = 5  # секунд — помечаем как подозрительные
    MAX_CONNECTIONS_PER_IP = 20 # макс. одновременных соединений с одного IP

    # ── BOT / SCANNER DETECTION ───────────────────────────────
    # User-Agent паттерны известных хакерских инструментов и сканеров.
    # Легитимные браузеры никогда не используют эти строки.
    MALICIOUS_UA_PATTERNS = [
        r"sqlmap",           # SQL инъекция
        r"nikto",            # веб-сканер уязвимостей
        r"masscan",          # сканер портов
        r"nmap",             # сканер сети
        r"zgrab",            # сканер сертификатов
        r"dirbuster",        # перебор директорий
        r"gobuster",         # перебор директорий
        r"wfuzz",            # fuzzing инструмент
        r"hydra",            # brute force инструмент
        r"medusa",           # brute force инструмент
        r"python-requests/2\.[0-9]+\.[0-9]+ *$",  # голый python-requests
        r"curl/[0-9]",       # голый curl (скрипты атак)
        r"wget/[0-9]",       # голый wget
        r"scrapy",           # веб-скрепер
        r"libwww-perl",      # Perl HTTP клиент (часто в атаках)
        r"java/[0-9]",       # голый Java HTTP клиент
    ]
    # Компилируем паттерны один раз при старте — быстрее чем каждый раз re.search
    _ua_regex = re.compile("|".join(MALICIOUS_UA_PATTERNS), re.IGNORECASE)

    # ── SCANNER PATH DETECTION ────────────────────────────────
    # Сканеры автоматически проверяют эти пути в поисках уязвимостей.
    # Легитимный пользователь никогда не запросит /.env или /wp-admin.
    SCANNER_PATHS = {
        "/.env", "/.git", "/.htaccess", "/.htpasswd",
        "/wp-admin", "/wp-login.php", "/wp-config.php",
        "/phpmyadmin", "/pma", "/adminer",
        "/admin", "/administrator", "/panel",
        "/config", "/backup", "/db",
        "/shell", "/cmd", "/exec",
        "/etc/passwd", "/etc/shadow",
        "/.aws/credentials", "/.ssh/id_rsa",
        "/xmlrpc.php", "/setup.php", "/install.php",
    }

    # ── GLOBAL DDOS PROTECTION ────────────────────────────────
    # Защита от Distributed DDoS — когда атака идёт с тысяч разных IP.
    # Каждый IP по отдельности выглядит нормально, но суммарный трафик огромный.
    GLOBAL_RATE_WINDOW = 10       # секунд — окно подсчёта трафика
    GLOBAL_RATE_LIMIT = 500       # запросов за 10 сек — порог тревоги
    GLOBAL_RATE_LIMIT_HARD = 1000 # запросов за 10 сек — жёсткий порог

    # Локальный счётчик глобального трафика (в памяти процесса)
    _global_requests: list = []  # список временных меток запросов
    _attack_mode: bool = False    # флаг режима атаки
    _attack_mode_until: float = 0 # до какого времени режим атаки активен

    # Track concurrent connections per IP
    _connections: dict[str, int] = {}

    async def dispatch(self, request: Request, call_next):
        path = request.url.path

        # Пропускаем дашборд и внутренние пути без проверок
        if path.startswith("/dashboard") or path in self.SKIP_PATHS:
            return await call_next(request)

        # Пути сайта (/site/) — пропускаем без проверок (статические файлы)
        if any(path.startswith(p) for p in self.SKIP_PREFIXES):
            return await call_next(request)

        # ── IP EXTRACTION ─────────────────────────────────────
        real_ip = request.client.host if request.client else "unknown"
        TRUSTED_PROXIES = {"127.0.0.1", "::1"}
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for and real_ip in TRUSTED_PROXIES:
            candidate = forwarded_for.split(",")[0].strip()
            parts = candidate.split(".")
            if len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts):
                ip = candidate
            else:
                ip = real_ip
        else:
            ip = real_ip

        # ── HONEYPOT CHECK ────────────────────────────────────
        # Первым делом проверяем пути-ловушки — до всех остальных проверок.
        # Нормальный юзер никогда не зайдёт на /.env или /wp-admin.
        path_check = path.lower().rstrip("/")
        if path_check in {p.rstrip("/") for p in self.HONEYPOT_PATHS}:
            real_ip = request.client.host if request.client else "unknown"
            log.warning("honeypot_triggered", ip=real_ip, path=path)
            await EventLogger.log_event(
                "honeypot", real_ip, path, "banned",
                {"reason": "honeypot_path", "ban_seconds": self.HONEYPOT_BAN_SECONDS}
            )
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            # Немедленный бан через IP Reputation
            await IPReputation.add_violation(real_ip, "honeypot", f"path:{path}")
            try:
                from app.core import get_redis
                r = await get_redis()
                ban_key = f"shield:ip_reputation:{real_ip}"
                await r.setex(ban_key, self.HONEYPOT_BAN_SECONDS, "banned")
            except Exception:
                pass
            # Возвращаем 200 с фейковыми данными — не раскрываем что попался
            import json as _json
            from starlette.responses import Response as _Resp
            fake = _json.dumps({"status": "ok", "data": [], "version": "1.0"})
            return _Resp(content=fake, media_type="application/json", status_code=200)

        # ── BOT DETECTION ─────────────────────────────────────
        # Проверяем User-Agent до всех остальных проверок —
        # это самый быстрый фильтр, не требует обращения к Redis.
        user_agent = request.headers.get("user-agent", "")
        if not user_agent:
            # Пустой User-Agent — признак автоматизированного запроса
            await EventLogger.log_event(
                "bot_detected", ip, path, "blocked",
                {"reason": "empty_user_agent"}
            )
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            await IPReputation.add_violation(ip, "bot_pattern", "empty_ua")
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "reason": "bot_detected"},
            )

        ua_match = self._ua_regex.search(user_agent)
        if ua_match:
            # Совпадение с паттерном известного хакерского инструмента
            matched = ua_match.group(0)
            log.warning("bot_blocked", ip=ip, path=path, ua=user_agent[:80], matched=matched)
            await EventLogger.log_event(
                "bot_detected", ip, path, "blocked",
                {"reason": "malicious_user_agent", "matched": matched}
            )
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            await IPReputation.add_violation(ip, "bot_pattern", f"ua_match:{matched}")
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "reason": "bot_detected"},
            )

        # ── SCANNER PATH DETECTION ────────────────────────────
        # Проверяем путь на совпадение с известными путями сканеров.
        # Возвращаем 404 а не 403 — не раскрываем что система нашла паттерн.
        path_lower = path.lower().rstrip("/")
        if path_lower in self.SCANNER_PATHS or any(
            path_lower.startswith(sp + "/") or path_lower.startswith(sp + "?")
            for sp in self.SCANNER_PATHS if len(sp) > 1
        ):
            log.warning("scanner_blocked", ip=ip, path=path)
            await EventLogger.log_event(
                "scanner_detected", ip, path, "blocked",
                {"reason": "scanner_path"}
            )
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            await IPReputation.add_violation(ip, "ddos_pattern", f"scanner_path:{path}")
            return JSONResponse(
                status_code=404,
                content={"detail": "Not found"},
            )

        # ── GLOBAL DDOS PROTECTION ────────────────────────────
        # Считаем глобальный трафик за последние N секунд.
        now = time.time()
        window_start = now - self.GLOBAL_RATE_WINDOW

        # Удаляем устаревшие записи из временного окна
        self.__class__._global_requests = [
            t for t in self._global_requests if t > window_start
        ]
        self.__class__._global_requests.append(now)
        global_count = len(self._global_requests)

        # Жёсткий порог — возможно ботнет, временно блокируем
        if global_count >= self.GLOBAL_RATE_LIMIT_HARD:
            if not self._attack_mode:
                self.__class__._attack_mode = True
                self.__class__._attack_mode_until = now + 30
                log.error("global_ddos_detected", count=global_count)
                asyncio.create_task(
                    alerts.alert_ddos_detected(ip, global_count, global_count)
                )
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            return JSONResponse(
                status_code=503,
                content={"error": "Service temporarily unavailable", "reason": "ddos_protection"},
                headers={"Retry-After": "30"},
            )

        # Мягкий порог — включаем режим повышенной бдительности
        if global_count >= self.GLOBAL_RATE_LIMIT:
            self.__class__._attack_mode = True
            self.__class__._attack_mode_until = now + 15
            log.warning("global_traffic_high", count=global_count)

        # Снимаем режим атаки если время вышло
        if self._attack_mode and now > self._attack_mode_until:
            self.__class__._attack_mode = False
            log.info("attack_mode_cleared")

        # ── SLOWLORIS PROTECTION ──────────────────────────────
        current_conns = self._connections.get(ip, 0)
        if current_conns >= self.MAX_CONNECTIONS_PER_IP:
            await EventLogger.log_event(
                "slowloris", ip, path, "blocked",
                {"reason": "too_many_connections", "count": current_conns}
            )
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            await IPReputation.add_violation(ip, "ddos_pattern", "slowloris_connections")
            return JSONResponse(
                status_code=429,
                content={"error": "Too many connections", "reason": "slowloris_protection"},
            )

        self._connections[ip] = current_conns + 1
        request_start = time.time()

        try:
            response = await asyncio.wait_for(
                self._process_request(request, call_next, ip, path),
                timeout=self.REQUEST_TIMEOUT,
            )
            return response

        except asyncio.TimeoutError:
            elapsed = time.time() - request_start
            await EventLogger.log_event(
                "slowloris", ip, path, "timeout",
                {"elapsed_seconds": round(elapsed, 2), "timeout": self.REQUEST_TIMEOUT}
            )
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            await IPReputation.add_violation(ip, "ddos_pattern", f"slowloris_timeout_{elapsed:.1f}s")
            log.warning("slowloris_timeout", ip=ip, path=path, elapsed=elapsed)
            return JSONResponse(
                status_code=408,
                content={"error": "Request timeout", "reason": "slowloris_protection"},
            )

        finally:
            self._connections[ip] = max(0, self._connections.get(ip, 1) - 1)
            if self._connections[ip] == 0:
                self._connections.pop(ip, None)

    async def _process_request(self, request: Request, call_next, ip: str, path: str):
        """Core request processing with all protection layers."""

        # Whitelist check — static (settings) + dynamic (Redis)
        if ip in settings.whitelisted_ips:
            response = await call_next(request)
            await EventLogger.increment_metric("requests_total")
            return response

        try:
            from app.core import get_redis
            r = await get_redis()
            if await r.sismember("shield:whitelist", ip):
                response = await call_next(request)
                await EventLogger.increment_metric("requests_total")
                return response
        except Exception:
            pass

        # Fingerprint extraction
        fingerprint = extract_fingerprint(request)
        is_suspicious, fp_reasons = is_suspicious_fingerprint(fingerprint)

        identifier = ip if ip != "127.0.0.1" else fingerprint["fingerprint_id"]

        # Проверяем аутентификацию — залогиненный admin не получает violations
        is_admin = False
        try:
            from app.core.auth import get_token_from_request, decode_token
            token = get_token_from_request(request)
            if token:
                payload = decode_token(token)
                if payload and payload.get("role") == "admin":
                    is_admin = True
        except Exception:
            pass

        # Pre-check: is this identifier already banned?
        reputation_action = await IPReputation.get_action(identifier)
        if reputation_action == "ban":
            await EventLogger.log_event("blocked", ip, path, "banned_ip")
            await EventLogger.increment_metric("blocked_total")
            await EventLogger.increment_metric("requests_total")
            return JSONResponse(
                status_code=403,
                content={"error": "Access denied", "reason": "banned"},
            )

        # Rate limiting
        endpoint_type = "login" if path in self.AUTH_PATHS else "general"
        rate_result = await AdaptiveRateLimiter.check_rate(
            identifier=identifier,
            endpoint_type=endpoint_type,
        )

        if not rate_result["allowed"]:
            if not is_admin:
                await IPReputation.add_violation(identifier, "rate_limit", f"path={path}")
            await EventLogger.log_event(
                "rate_limited", ip, path, "blocked",
                {"count": rate_result["current_count"], "limit": rate_result["limit"]},
            )
            await EventLogger.increment_metric("rate_limited_total")
            await EventLogger.increment_metric("requests_total")
            return JSONResponse(
                status_code=429,
                content={
                    "error": "Too many requests",
                    "retry_after": rate_result["retry_after"],
                },
                headers={
                    "Retry-After": str(rate_result["retry_after"]),
                    "X-RateLimit-Limit": str(rate_result["limit"]),
                    "X-RateLimit-Remaining": str(rate_result["remaining"]),
                },
            )

        # Anomaly detection
        anomaly_result = await AnomalyDetector.analyze_request(identifier, path)
        if anomaly_result["is_anomaly"] and not is_admin:
            penalty_type = (
                "ddos_pattern"
                if "global_traffic_spike" in anomaly_result["reasons"]
                else "anomaly"
            )
            await IPReputation.add_violation(
                identifier, penalty_type,
                f"reasons={','.join(anomaly_result['reasons'])}",
            )
            await EventLogger.increment_metric("anomalies_detected")
            if anomaly_result["risk_level"] == "high":
                asyncio.create_task(
                    alerts.alert_ddos_detected(ip, anomaly_result["z_score"], 0)
                )

        # Suspicious fingerprint penalty
        if is_suspicious and not is_admin:
            await IPReputation.add_violation(
                identifier, "suspicious_fingerprint",
                f"reasons={','.join(fp_reasons)}",
            )

        # Brute force guard for auth endpoints
        if path in self.AUTH_PATHS and request.method == "POST":
            bf_check = await BruteForceGuard.check_login_allowed(identifier)
            if not bf_check["allowed"]:
                await EventLogger.log_event(
                    "brute_force", ip, path, "blocked",
                    {"reason": bf_check["reason"], "remaining": bf_check["lockout_remaining"]},
                )
                await EventLogger.increment_metric("bruteforce_blocked_total")
                await EventLogger.increment_metric("requests_total")
                return JSONResponse(
                    status_code=429,
                    content={
                        "error": "Too many login attempts",
                        "lockout_remaining": bf_check["lockout_remaining"],
                    },
                )

        # Challenge mode
        if reputation_action == "challenge":
            await EventLogger.log_event("challenged", ip, path, "challenge")
            await EventLogger.increment_metric("challenges_issued")

        # Process the actual request
        response = await call_next(request)

        # Post-processing
        await EventLogger.increment_metric("requests_total")

        # Security headers
        response.headers["X-Shield-Fingerprint"] = fingerprint["fingerprint_id"][:8]
        response.headers["X-Shield-Reputation"] = reputation_action
        response.headers["X-Shield-Attack-Mode"] = "1" if self._attack_mode else "0"
        if rate_result["remaining"] is not None:
            response.headers["X-RateLimit-Remaining"] = str(rate_result["remaining"])

        return response
