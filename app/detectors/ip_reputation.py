"""
IP Reputation Engine — maintains a threat score per IP.

Key features:
- Score accumulates with each violation
- Score decays over time (exponential decay) — IPs aren't banned forever
- Different penalties for different violation types
- Progressive response: warn → challenge → block → ban
"""

import time
import json
from app.core import get_redis
from config.settings import settings


class IPReputation:
    PREFIX = "shield:rep"
    HISTORY_PREFIX = "shield:rep:history"

    @classmethod
    async def get_score(cls, ip: str) -> float:
        """Get current reputation score with time-based decay applied."""
        r = await get_redis()
        data = await r.hgetall(f"{cls.PREFIX}:{ip}")

        if not data:
            return 0.0

        raw_score = float(data.get("score", 0))
        last_update = float(data.get("last_update", time.time()))

        # Apply exponential decay: score * decay_rate^(minutes_elapsed)
        minutes_elapsed = (time.time() - last_update) / 60.0
        decayed_score = raw_score * (settings.reputation_decay_rate ** minutes_elapsed)

        # Clean up if score is negligible
        if decayed_score < 0.1:
            await r.delete(f"{cls.PREFIX}:{ip}")
            return 0.0

        return round(decayed_score, 2)

    @classmethod
    async def add_violation(
        cls,
        ip: str,
        violation_type: str,
        details: str = "",
    ) -> float:
        """
        Add a violation to an IP's record. Returns new score.

        violation_type: 'rate_limit', 'brute_force', 'suspicious_fingerprint',
                       'anomaly', 'ddos_pattern'
        """
        penalties = {
            "rate_limit": 10.0,
            "brute_force": settings.reputation_bruteforce_penalty,
            "suspicious_fingerprint": 5.0,
            "anomaly": 15.0,
            "ddos_pattern": settings.reputation_ddos_penalty,
        }
        penalty = penalties.get(violation_type, 10.0)

        r = await get_redis()
        now = time.time()

        # Get current decayed score first
        current = await cls.get_score(ip)
        new_score = current + penalty

        # Store updated score
        await r.hset(f"{cls.PREFIX}:{ip}", mapping={
            "score": str(new_score),
            "last_update": str(now),
            "last_violation": violation_type,
            "violation_count": str(int(float(
                (await r.hget(f"{cls.PREFIX}:{ip}", "violation_count")) or "0"
            )) + 1),
        })
        await r.expire(f"{cls.PREFIX}:{ip}", 86400)  # 24h TTL

        # Log to history
        history_entry = json.dumps({
            "ts": now,
            "type": violation_type,
            "penalty": penalty,
            "new_score": new_score,
            "details": details,
        })
        pipe = r.pipeline()
        pipe.lpush(f"{cls.HISTORY_PREFIX}:{ip}", history_entry)
        pipe.ltrim(f"{cls.HISTORY_PREFIX}:{ip}", 0, 99)  # keep last 100
        pipe.expire(f"{cls.HISTORY_PREFIX}:{ip}", 86400)
        await pipe.execute()

        return new_score

    @classmethod
    async def get_action(cls, ip: str) -> str:
        """Determine action based on current reputation score."""
        score = await cls.get_score(ip)

        if score >= settings.reputation_ban_threshold:
            return "ban"
        elif score >= settings.reputation_challenge_threshold:
            return "challenge"
        elif score > 20:
            return "warn"
        else:
            return "allow"

    @classmethod
    async def get_info(cls, ip: str) -> dict:
        """Get full reputation info for an IP."""
        r = await get_redis()
        data = await r.hgetall(f"{cls.PREFIX}:{ip}")
        score = await cls.get_score(ip)
        action = await cls.get_action(ip)

        history_raw = await r.lrange(f"{cls.HISTORY_PREFIX}:{ip}", 0, 19)
        history = []
        for entry in history_raw:
            try:
                history.append(json.loads(entry))
            except (json.JSONDecodeError, TypeError):
                pass

        return {
            "ip": ip,
            "score": score,
            "action": action,
            "violation_count": int(data.get("violation_count", 0)),
            "last_violation": data.get("last_violation", "none"),
            "history": history,
        }

    @classmethod
    async def reset(cls, ip: str):
        """Manually reset an IP's reputation (admin action)."""
        r = await get_redis()
        await r.delete(f"{cls.PREFIX}:{ip}")
        await r.delete(f"{cls.HISTORY_PREFIX}:{ip}")

    @classmethod
    async def get_all_flagged(cls) -> list[dict]:
        """Get all IPs with non-zero reputation scores."""
        r = await get_redis()
        keys = []
        async for key in r.scan_iter(f"{cls.PREFIX}:*"):
            if ":history:" not in key:
                keys.append(key)

        flagged = []
        for key in keys[:100]:  # limit to 100
            ip = key.split(":")[-1]
            info = await cls.get_info(ip)
            if info["score"] > 0:
                flagged.append(info)

        return sorted(flagged, key=lambda x: x["score"], reverse=True)
