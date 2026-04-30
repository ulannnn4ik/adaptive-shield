"""
Report Generator — gathers all data for export (PDF/JSON/TXT).
Now uses SQLite for persistent history + Redis for current session.
"""

import json
import time
from datetime import datetime, timezone
from app.core.logger import EventLogger
from app.detectors.rate_limiter import AdaptiveRateLimiter
from app.detectors.ip_reputation import IPReputation
from app.detectors.brute_force import BruteForceGuard


async def generate_report_data() -> dict:
    """
    Gather all data for the report.
    Combines Redis (current session) + SQLite (full history).
    """
    # ── Redis: current session data ──
    metrics = await EventLogger.get_metrics()
    rate_stats = await AdaptiveRateLimiter.get_current_stats()
    bf_stats = await BruteForceGuard.get_stats()
    flagged = await IPReputation.get_all_flagged()
    events = await EventLogger.get_recent_events(50)

    total = int(metrics.get("requests_total", 0))
    blocked = int(metrics.get("blocked_total", 0))
    rate_limited = int(metrics.get("rate_limited_total", 0))
    bf_blocked = int(metrics.get("bruteforce_blocked_total", 0))
    anomalies = int(metrics.get("anomalies_detected", 0))
    challenges = int(metrics.get("challenges_issued", 0))
    allowed = max(0, total - blocked - rate_limited - challenges)
    block_rate = (blocked / total * 100) if total > 0 else 0

    # ── SQLite: persistent history ──
    db_summary = {}
    db_top_attackers = []
    db_attack_history = []
    db_metrics_history = []

    try:
        from app.core.database import Database
        db_summary = await Database.get_summary()
        db_top_attackers = await Database.get_top_attackers(10)
        db_attack_history = await Database.get_attack_history(10)
        db_metrics_history = await Database.get_metrics_history(24)
    except Exception:
        pass

    # ── Merge: use SQLite totals if bigger (more complete history) ──
    db_total = db_summary.get("total_events", 0)
    db_blocked = db_summary.get("blocked", 0)

    # If SQLite has more data — use it (covers multiple sessions)
    if db_total > total:
        total = db_total
        blocked = db_blocked
        rate_limited = db_summary.get("rate_limited", 0)
        bf_blocked = db_summary.get("brute_force", 0)
        allowed = max(0, total - blocked - rate_limited)
        block_rate = (blocked / total * 100) if total > 0 else 0

    return {
        "generated_at": datetime.now(timezone.utc).isoformat(),

        # ── Main summary ──
        "summary": {
            "total_requests": total,
            "allowed": allowed,
            "blocked": blocked,
            "rate_limited": rate_limited,
            "bruteforce_blocked": bf_blocked,
            "anomalies_detected": anomalies,
            "challenges_issued": challenges,
            "block_rate": round(block_rate, 2),
            "false_positive_rate": 0,
            "unique_attackers": db_summary.get("unique_attackers", len(flagged)),
            "data_source": "SQLite + Redis" if db_total > 0 else "Redis only",
        },

        # ── Current session ──
        "rate_limiter": rate_stats,
        "brute_force": bf_stats,
        "flagged_ips": flagged[:20],
        "recent_events": events[:30],

        # ── Historical data from SQLite ──
        "history": {
            "top_attackers": db_top_attackers,
            "attack_sessions": db_attack_history,
            "metrics_by_hour": db_metrics_history,
            "first_event": db_summary.get("first_event"),
            "last_event": db_summary.get("last_event"),
            "total_attack_sessions": db_summary.get("attack_sessions", 0),
        },
    }
