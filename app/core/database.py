"""
SQLite Database — persistent storage for events, users, and attack history.

Works alongside Redis:
- Redis  → fast real-time blocking (milliseconds)
- SQLite → permanent history (survives restarts)

Tables:
- events          → every security event logged
- attack_sessions → grouped attack sessions
- ip_history      → IP reputation history over time
- metrics_snapshot → hourly snapshots of metrics
- users           → user accounts (persistent)
"""

import aiosqlite
import asyncio
import time
import json
from datetime import datetime, timezone
from pathlib import Path

DB_PATH = Path("shield.db")
_lock = asyncio.Lock()


async def init_db():
    """Create tables if they don't exist. Called on startup."""
    async with aiosqlite.connect(DB_PATH) as db:
        await db.executescript("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL NOT NULL,
                datetime    TEXT NOT NULL,
                event_type  TEXT NOT NULL,
                ip          TEXT NOT NULL,
                path        TEXT NOT NULL,
                action      TEXT NOT NULL,
                details     TEXT DEFAULT '{}',
                session_id  TEXT
            );

            CREATE TABLE IF NOT EXISTS attack_sessions (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id      TEXT UNIQUE NOT NULL,
                ip              TEXT NOT NULL,
                attack_type     TEXT NOT NULL,
                started_at      REAL NOT NULL,
                ended_at        REAL,
                total_requests  INTEGER DEFAULT 0,
                blocked_count   INTEGER DEFAULT 0,
                peak_rps        REAL DEFAULT 0,
                final_action    TEXT DEFAULT 'ongoing'
            );

            CREATE TABLE IF NOT EXISTS ip_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   REAL NOT NULL,
                ip          TEXT NOT NULL,
                score       REAL NOT NULL,
                action      TEXT NOT NULL,
                violation   TEXT
            );

            CREATE TABLE IF NOT EXISTS metrics_snapshot (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp       REAL NOT NULL,
                hour            TEXT NOT NULL UNIQUE,
                requests_total  INTEGER DEFAULT 0,
                blocked_total   INTEGER DEFAULT 0,
                rate_limited    INTEGER DEFAULT 0,
                bruteforce      INTEGER DEFAULT 0,
                anomalies       INTEGER DEFAULT 0
            );

            CREATE TABLE IF NOT EXISTS users (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                role          TEXT NOT NULL DEFAULT 'user',
                name          TEXT NOT NULL,
                created_at    REAL NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_ip        ON events(ip);
            CREATE INDEX IF NOT EXISTS idx_events_type      ON events(event_type);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_ip_history_ip    ON ip_history(ip);
        """)
        await db.commit()

    # Seed default users if table is empty
    await _seed_default_users()


async def _seed_default_users():
    """Insert default users if users table is empty."""
    from app.core.auth import hash_password
    async with aiosqlite.connect(DB_PATH) as db:
        cursor = await db.execute("SELECT COUNT(*) FROM users")
        count = (await cursor.fetchone())[0]
        if count == 0:
            now = time.time()
            default_users = [
                ("admin",  hash_password("admin123"), "admin", "Администратор", now),
                ("user",   hash_password("password"), "user",  "Пользователь",  now),
                ("test",   hash_password("test123"),  "user",  "Тест",          now),
            ]
            await db.executemany(
                "INSERT INTO users (username, password_hash, role, name, created_at) VALUES (?,?,?,?,?)",
                default_users
            )
            await db.commit()


class UserDB:
    """User management via SQLite."""

    @staticmethod
    async def get_user(username: str) -> dict | None:
        """Get user by username."""
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM users WHERE username=?", (username,)
            )
            row = await cursor.fetchone()
            return dict(row) if row else None

    @staticmethod
    async def create_user(username: str, password_hash: str, role: str = "user", name: str = "") -> bool:
        """Create a new user. Returns False if username already exists."""
        try:
            async with aiosqlite.connect(DB_PATH) as db:
                await db.execute(
                    "INSERT INTO users (username, password_hash, role, name, created_at) VALUES (?,?,?,?,?)",
                    (username, password_hash, role, name or username.capitalize(), time.time())
                )
                await db.commit()
            return True
        except aiosqlite.IntegrityError:
            return False

    @staticmethod
    async def get_all_users() -> list[dict]:
        """Get all users."""
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT id, username, role, name, created_at FROM users ORDER BY created_at"
            )
            rows = await cursor.fetchall()
            return [dict(r) for r in rows]


    @staticmethod
    async def update_user_role(username: str, role: str) -> bool:
        """Update user role. Returns False if user not found."""
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "UPDATE users SET role=? WHERE username=?", (role, username)
            )
            await db.commit()
            return cursor.rowcount > 0

    @staticmethod
    async def delete_user(username: str) -> bool:
        """Delete user by username. Returns False if not found."""
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "DELETE FROM users WHERE username=?", (username,)
            )
            await db.commit()
            return cursor.rowcount > 0

    @staticmethod
    async def user_exists(username: str) -> bool:
        """Check if username already exists."""
        async with aiosqlite.connect(DB_PATH) as db:
            cursor = await db.execute(
                "SELECT 1 FROM users WHERE username=?", (username,)
            )
            return (await cursor.fetchone()) is not None


class Database:
    """Main database interface."""

    @staticmethod
    async def save_event(event_type, ip, path, action, details=None, session_id=None):
        now = time.time()
        dt = datetime.now(timezone.utc).isoformat()
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """INSERT INTO events
                   (timestamp, datetime, event_type, ip, path, action, details, session_id)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (now, dt, event_type, ip, path, action, json.dumps(details or {}), session_id)
            )
            await db.commit()

    @staticmethod
    async def get_recent_events(limit=100, event_type=None):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            if event_type:
                cursor = await db.execute(
                    "SELECT * FROM events WHERE event_type=? ORDER BY timestamp DESC LIMIT ?",
                    (event_type, limit)
                )
            else:
                cursor = await db.execute(
                    "SELECT * FROM events ORDER BY timestamp DESC LIMIT ?", (limit,)
                )
            return [dict(r) for r in await cursor.fetchall()]

    @staticmethod
    async def get_events_by_ip(ip, limit=50):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM events WHERE ip=? ORDER BY timestamp DESC LIMIT ?", (ip, limit)
            )
            return [dict(r) for r in await cursor.fetchall()]

    @staticmethod
    async def get_top_attackers(limit=10):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                """SELECT ip, COUNT(*) as violations,
                          MAX(score) as peak_score, MAX(action) as worst_action
                   FROM ip_history GROUP BY ip ORDER BY violations DESC LIMIT ?""",
                (limit,)
            )
            return [dict(r) for r in await cursor.fetchall()]

    @staticmethod
    async def get_attack_history(limit=20):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM attack_sessions ORDER BY started_at DESC LIMIT ?", (limit,)
            )
            return [dict(r) for r in await cursor.fetchall()]

    @staticmethod
    async def save_ip_score(ip, score, action, violation=None):
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                "INSERT INTO ip_history (timestamp, ip, score, action, violation) VALUES (?,?,?,?,?)",
                (time.time(), ip, score, action, violation)
            )
            await db.commit()

    @staticmethod
    async def get_ip_history(ip, limit=50):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute(
                "SELECT * FROM ip_history WHERE ip=? ORDER BY timestamp DESC LIMIT ?", (ip, limit)
            )
            return [dict(r) for r in await cursor.fetchall()]

    @staticmethod
    async def save_metrics_snapshot(metrics):
        now = time.time()
        hour = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:00")
        async with aiosqlite.connect(DB_PATH) as db:
            await db.execute(
                """INSERT INTO metrics_snapshot
                   (timestamp, hour, requests_total, blocked_total, rate_limited, bruteforce, anomalies)
                   VALUES (?, ?, ?, ?, ?, ?, ?)
                   ON CONFLICT(hour) DO UPDATE SET
                   requests_total=excluded.requests_total,
                   blocked_total=excluded.blocked_total,
                   rate_limited=excluded.rate_limited,
                   bruteforce=excluded.bruteforce,
                   anomalies=excluded.anomalies""",
                (now, hour,
                 int(metrics.get("requests_total", 0)),
                 int(metrics.get("blocked_total", 0)),
                 int(metrics.get("rate_limited_total", 0)),
                 int(metrics.get("bruteforce_blocked_total", 0)),
                 int(metrics.get("anomalies_detected", 0)))
            )
            await db.commit()

    @staticmethod
    async def get_metrics_history(hours=24):
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            since = time.time() - (hours * 3600)
            cursor = await db.execute(
                "SELECT * FROM metrics_snapshot WHERE timestamp > ? ORDER BY timestamp ASC", (since,)
            )
            return [dict(r) for r in await cursor.fetchall()]

    @staticmethod
    async def get_summary():
        async with aiosqlite.connect(DB_PATH) as db:
            db.row_factory = aiosqlite.Row
            cursor = await db.execute("SELECT COUNT(*) as total FROM events")
            total = (await cursor.fetchone())["total"]
            cursor = await db.execute(
                "SELECT event_type, COUNT(*) as c FROM events GROUP BY event_type"
            )
            by_type = {r["event_type"]: r["c"] for r in await cursor.fetchall()}
            cursor = await db.execute(
                "SELECT COUNT(DISTINCT ip) as c FROM events WHERE event_type != 'allowed'"
            )
            unique_attackers = (await cursor.fetchone())["c"]
            cursor = await db.execute("SELECT COUNT(*) as c FROM attack_sessions")
            sessions = (await cursor.fetchone())["c"]
            cursor = await db.execute(
                "SELECT MIN(datetime) as first, MAX(datetime) as last FROM events"
            )
            row = await cursor.fetchone()
            return {
                "total_events": total,
                "by_type": by_type,
                "unique_attackers": unique_attackers,
                "attack_sessions": sessions,
                "first_event": row["first"],
                "last_event": row["last"],
                "blocked": by_type.get("blocked", 0),
                "rate_limited": by_type.get("rate_limited", 0),
                "brute_force": by_type.get("brute_force", 0),
            }
