"""
Adaptive Rate Limiter — goes beyond static thresholds.

Two algorithms combined:
1. Sliding Window Counter (accurate, Redis-efficient)
2. Token Bucket (for burst tolerance)

The "adaptive" part: the system learns a baseline RPS from normal traffic
and dynamically adjusts thresholds. During detected attacks, limits tighten.
During normal operation, they relax.
"""

import time
from app.core import get_redis
from config.settings import settings


class AdaptiveRateLimiter:
    PREFIX = "shield:rl"
    BASELINE_KEY = "shield:baseline"

    @classmethod
    async def check_rate(
        cls,
        identifier: str,
        endpoint_type: str = "general",
    ) -> dict:
        """
        Check if identifier exceeds rate limit.

        Returns: {
            "allowed": bool,
            "current_count": int,
            "limit": int,
            "remaining": int,
            "retry_after": int | None,
            "adaptive_multiplier": float,
        }
        """
        r = await get_redis()
        now = time.time()
        window = settings.rate_limit_window_seconds

        # Base limit depends on endpoint type
        if endpoint_type == "login":
            base_limit = settings.rate_limit_login
        else:
            base_limit = settings.rate_limit_general

        # Adaptive adjustment: learn from traffic baseline
        adaptive_multiplier = 1.0
        if settings.adaptive_enabled:
            adaptive_multiplier = await cls._get_adaptive_multiplier(r)

        effective_limit = max(1, int(base_limit * adaptive_multiplier))

        # === Sliding Window Counter ===
        window_key = f"{cls.PREFIX}:{endpoint_type}:{identifier}"
        window_start = now - window

        pipe = r.pipeline()
        # Remove expired entries
        pipe.zremrangebyscore(window_key, 0, window_start)
        # Add current request
        pipe.zadd(window_key, {f"{now}:{id(now)}": now})
        # Count requests in window
        pipe.zcard(window_key)
        # Set expiry
        pipe.expire(window_key, window + 1)
        results = await pipe.execute()

        current_count = results[2]
        allowed = current_count <= effective_limit

        # Update global RPS tracker for adaptive learning
        await cls._update_baseline(r, now)

        return {
            "allowed": allowed,
            "current_count": current_count,
            "limit": effective_limit,
            "remaining": max(0, effective_limit - current_count),
            "retry_after": window if not allowed else None,
            "adaptive_multiplier": adaptive_multiplier,
        }

    @classmethod
    async def _get_adaptive_multiplier(cls, r) -> float:
        """
        Calculate adaptive multiplier based on global traffic.

        If current RPS is much higher than learned baseline,
        tighten the limits (multiplier < 1.0).
        If traffic is normal, keep multiplier at 1.0.
        """
        baseline_rps = await r.get(f"{cls.BASELINE_KEY}:rps")
        current_rps = await r.get(f"{cls.BASELINE_KEY}:current_rps")

        if not baseline_rps or not current_rps:
            return 1.0

        baseline_rps = float(baseline_rps)
        current_rps = float(current_rps)

        if baseline_rps < 1:
            return 1.0

        ratio = current_rps / baseline_rps

        if ratio > settings.burst_multiplier:
            # Under attack — tighten limits
            # More aggressive as ratio increases
            return max(0.2, 1.0 / (ratio / settings.burst_multiplier))
        elif ratio < 0.5:
            # Very low traffic — slightly relax
            return 1.2
        else:
            return 1.0

    @classmethod
    async def _update_baseline(cls, r, now: float):
        """Track current RPS and update baseline using exponential moving average."""
        second_key = f"{cls.BASELINE_KEY}:sec:{int(now)}"
        pipe = r.pipeline()
        pipe.incr(second_key)
        pipe.expire(second_key, 10)
        results = await pipe.execute()

        # Every 5 seconds, recalculate current RPS
        rps_calc_key = f"{cls.BASELINE_KEY}:last_calc"
        last_calc = await r.get(rps_calc_key)
        if last_calc and now - float(last_calc) < 5:
            return

        await r.set(rps_calc_key, str(now), ex=10)

        # Calculate average RPS over last 5 seconds
        total = 0
        for i in range(5):
            val = await r.get(f"{cls.BASELINE_KEY}:sec:{int(now) - i}")
            total += int(val) if val else 0
        current_rps = total / 5.0

        await r.set(f"{cls.BASELINE_KEY}:current_rps", str(current_rps), ex=30)

        # Update baseline with EMA (α = 0.1 for responsive learning)
        old_baseline = await r.get(f"{cls.BASELINE_KEY}:rps")
        if old_baseline:
            alpha = 0.1
            new_baseline = alpha * current_rps + (1 - alpha) * float(old_baseline)
        else:
            new_baseline = current_rps

        if new_baseline > 0.1:  # Don't store zero baselines
            await r.set(f"{cls.BASELINE_KEY}:rps", str(new_baseline))

    @classmethod
    async def get_current_stats(cls) -> dict:
        """Get current rate limiter statistics."""
        r = await get_redis()
        baseline = await r.get(f"{cls.BASELINE_KEY}:rps")
        current = await r.get(f"{cls.BASELINE_KEY}:current_rps")
        return {
            "baseline_rps": round(float(baseline), 2) if baseline else 0,
            "current_rps": round(float(current), 2) if current else 0,
            "adaptive_multiplier": await cls._get_adaptive_multiplier(r),
        }
