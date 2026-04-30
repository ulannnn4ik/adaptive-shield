import time
import json
from datetime import datetime, timezone
from typing import Any

import structlog
from app.core import get_redis

log = structlog.get_logger()


class EventLogger:
    """Centralized event logging to Redis streams + SQLite + structlog."""

    STREAM_KEY = "shield:events"
    METRICS_KEY = "shield:metrics"

    @staticmethod
    async def log_event(
        event_type: str,
        ip: str,
        path: str,
        action: str,
        details: dict[str, Any] | None = None,
    ):
        # 1. Redis stream (fast, real-time dashboard)
        r = await get_redis()
        event = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": event_type,
            "ip": ip,
            "path": path,
            "action": action,
            "details": json.dumps(details or {}),
        }
        await r.xadd(EventLogger.STREAM_KEY, event, maxlen=10000)
        log.info("shield_event", **event)

        # 2. SQLite (persistent, survives restarts)
        try:
            from app.core.database import Database
            await Database.save_event(
                event_type=event_type,
                ip=ip,
                path=path,
                action=action,
                details=details,
            )
        except Exception:
            pass  # never break real-time blocking because of DB write

    @staticmethod
    async def increment_metric(metric: str, amount: int = 1):
        r = await get_redis()
        pipe = r.pipeline()
        pipe.hincrby(EventLogger.METRICS_KEY, metric, amount)
        ts_key = f"shield:metrics:ts:{int(time.time()) // 60}"
        pipe.hincrby(ts_key, metric, amount)
        pipe.expire(ts_key, 3600)  # keep 1 hour of per-minute metrics
        await pipe.execute()

    @staticmethod
    async def get_metrics() -> dict:
        r = await get_redis()
        return await r.hgetall(EventLogger.METRICS_KEY)

    @staticmethod
    async def get_recent_events(count: int = 100) -> list[dict]:
        r = await get_redis()
        entries = await r.xrevrange(EventLogger.STREAM_KEY, count=count)
        events = []
        for entry_id, data in entries:
            data["id"] = entry_id
            if "details" in data:
                try:
                    data["details"] = json.loads(data["details"])
                except (json.JSONDecodeError, TypeError):
                    pass
            events.append(data)
        return events

    @staticmethod
    async def get_timeseries(minutes: int = 60) -> list[dict]:
        """Get per-minute metrics for the last N minutes."""
        r = await get_redis()
        now = int(time.time()) // 60
        result = []
        for i in range(minutes):
            ts = now - (minutes - 1 - i)
            key = f"shield:metrics:ts:{ts}"
            data = await r.hgetall(key)
            data["minute"] = ts
            result.append(data)
        return result
