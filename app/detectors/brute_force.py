"""
Brute Force Guard — specialized protection for authentication endpoints.

Features:
- Tracks failed login attempts per IP and per username
- Progressive lockout: each subsequent lockout doubles in duration
- Distinguishes credential stuffing (many usernames) from targeted attacks (one username)
- Integrates with IP reputation for cross-system scoring
"""

import time
import json
from app.core import get_redis
from config.settings import settings


class BruteForceGuard:
    PREFIX = "shield:bf"

    @classmethod
    async def check_login_allowed(cls, ip: str, username: str = "") -> dict:
        """
        Check if a login attempt is allowed.

        Returns: {
            "allowed": bool,
            "reason": str,
            "attempts_left": int,
            "lockout_remaining": int | None,
            "attack_type": str | None,  # 'targeted' | 'credential_stuffing'
        }
        """
        r = await get_redis()
        now = time.time()

        # Check IP lockout
        ip_lockout = await r.get(f"{cls.PREFIX}:lockout:{ip}")
        if ip_lockout:
            lockout_until = float(ip_lockout)
            if now < lockout_until:
                return {
                    "allowed": False,
                    "reason": "ip_locked",
                    "attempts_left": 0,
                    "lockout_remaining": int(lockout_until - now),
                    "attack_type": None,
                }

        # Check username lockout (if provided)
        if username:
            user_lockout = await r.get(f"{cls.PREFIX}:lockout:user:{username}")
            if user_lockout:
                lockout_until = float(user_lockout)
                if now < lockout_until:
                    return {
                        "allowed": False,
                        "reason": "user_locked",
                        "attempts_left": 0,
                        "lockout_remaining": int(lockout_until - now),
                        "attack_type": None,
                    }

        # Count recent failures
        failures = await cls._get_failure_count(r, ip, now)
        attempts_left = max(0, settings.bruteforce_max_attempts - failures)

        # Detect credential stuffing: many different usernames from same IP
        attack_type = await cls._detect_attack_type(r, ip)

        return {
            "allowed": attempts_left > 0,
            "reason": "ok" if attempts_left > 0 else "max_attempts",
            "attempts_left": attempts_left,
            "lockout_remaining": None,
            "attack_type": attack_type,
        }

    @classmethod
    async def record_failure(cls, ip: str, username: str = "") -> dict:
        """Record a failed login attempt. Returns lockout info if triggered."""
        r = await get_redis()
        now = time.time()
        window = settings.rate_limit_window_seconds

        # Record failure with timestamp
        failure_key = f"{cls.PREFIX}:failures:{ip}"
        pipe = r.pipeline()
        pipe.zadd(failure_key, {f"{now}:{username}": now})
        pipe.zremrangebyscore(failure_key, 0, now - window)
        pipe.zcard(failure_key)
        pipe.expire(failure_key, window + 1)
        results = await pipe.execute()
        failure_count = results[2]

        # Track unique usernames tried (for credential stuffing detection)
        if username:
            usernames_key = f"{cls.PREFIX}:usernames:{ip}"
            await r.sadd(usernames_key, username)
            await r.expire(usernames_key, window)

        # Check if lockout should be triggered
        lockout_info = {"locked": False}

        if failure_count >= settings.bruteforce_max_attempts:
            lockout_duration = await cls._calculate_lockout(r, ip)
            lockout_until = now + lockout_duration

            await r.set(
                f"{cls.PREFIX}:lockout:{ip}",
                str(lockout_until),
                ex=int(lockout_duration) + 1,
            )

            # Also lock the specific username if targeted
            if username:
                await r.set(
                    f"{cls.PREFIX}:lockout:user:{username}",
                    str(lockout_until),
                    ex=int(lockout_duration) + 1,
                )

            # Increment lockout counter for progressive lockout
            await r.incr(f"{cls.PREFIX}:lockout_count:{ip}")
            await r.expire(f"{cls.PREFIX}:lockout_count:{ip}", 86400)

            lockout_info = {
                "locked": True,
                "duration": int(lockout_duration),
                "failure_count": failure_count,
            }

        return lockout_info

    @classmethod
    async def record_success(cls, ip: str, username: str = ""):
        """Record a successful login — resets failure counter."""
        r = await get_redis()
        await r.delete(f"{cls.PREFIX}:failures:{ip}")
        if username:
            await r.delete(f"{cls.PREFIX}:lockout:user:{username}")

    @classmethod
    async def _get_failure_count(cls, r, ip: str, now: float) -> int:
        window = settings.rate_limit_window_seconds
        failure_key = f"{cls.PREFIX}:failures:{ip}"
        await r.zremrangebyscore(failure_key, 0, now - window)
        return await r.zcard(failure_key)

    @classmethod
    async def _calculate_lockout(cls, r, ip: str) -> float:
        """Progressive lockout: doubles with each consecutive lockout."""
        if not settings.bruteforce_progressive:
            return float(settings.bruteforce_lockout_seconds)

        count = await r.get(f"{cls.PREFIX}:lockout_count:{ip}")
        count = int(count) if count else 0

        # Base lockout * 2^count, max 1 hour
        duration = settings.bruteforce_lockout_seconds * (2 ** count)
        return min(duration, 3600.0)

    @classmethod
    async def _detect_attack_type(cls, r, ip: str) -> str | None:
        """Detect if this is credential stuffing vs targeted brute force."""
        usernames_key = f"{cls.PREFIX}:usernames:{ip}"
        unique_usernames = await r.scard(usernames_key)

        if unique_usernames is None or unique_usernames == 0:
            return None
        elif unique_usernames >= 3:
            return "credential_stuffing"
        elif unique_usernames == 1:
            return "targeted"
        return None

    @classmethod
    async def get_stats(cls) -> dict:
        """Get brute force protection stats."""
        r = await get_redis()
        locked_ips = []
        async for key in r.scan_iter(f"{cls.PREFIX}:lockout:*"):
            if ":user:" not in key:
                ip = key.split(":")[-1]
                ttl = await r.ttl(key)
                locked_ips.append({"ip": ip, "remaining_seconds": ttl})

        return {
            "locked_ips": locked_ips,
            "locked_count": len(locked_ips),
        }
