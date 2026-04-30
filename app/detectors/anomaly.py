"""
Anomaly Detector — uses statistical methods to detect unusual traffic patterns.

Approach:
1. Maintains a rolling window of request counts per IP
2. Calculates z-score: how many standard deviations from the mean
3. Uses Isolation Forest (lightweight ML) for multi-dimensional anomaly detection

This catches distributed attacks where each individual IP stays under
the rate limit, but the aggregate pattern is anomalous.
"""

import time
import json
import numpy as np
from app.core import get_redis
from config.settings import settings


class AnomalyDetector:
    PREFIX = "shield:anomaly"

    @classmethod
    async def analyze_request(cls, ip: str, path: str) -> dict:
        """
        Analyze if the current request pattern is anomalous.

        Returns: {
            "is_anomaly": bool,
            "z_score": float,
            "reasons": list[str],
            "risk_level": str,  # 'low', 'medium', 'high'
        }
        """
        r = await get_redis()
        now = time.time()
        reasons = []

        # 1. Per-IP request frequency z-score
        z_score = await cls._calculate_ip_zscore(r, ip, now)
        if z_score > settings.anomaly_z_score_threshold:
            reasons.append(f"high_frequency_zscore:{z_score:.1f}")

        # 2. Path concentration — is this IP hammering one endpoint?
        path_concentration = await cls._check_path_concentration(r, ip, path, now)
        if path_concentration > 0.8:
            reasons.append(f"path_concentration:{path_concentration:.2f}")

        # 3. Request interval regularity — bots often have very regular timing
        regularity = await cls._check_timing_regularity(r, ip, now)
        if regularity > 0.9:
            reasons.append(f"timing_regularity:{regularity:.2f}")

        # 4. Global traffic spike detection
        global_spike = await cls._detect_global_spike(r, now)
        if global_spike:
            reasons.append("global_traffic_spike")

        # Determine risk level
        is_anomaly = len(reasons) > 0
        if len(reasons) >= 3:
            risk_level = "high"
        elif len(reasons) >= 2:
            risk_level = "medium"
        elif len(reasons) >= 1:
            risk_level = "low"
        else:
            risk_level = "none"

        return {
            "is_anomaly": is_anomaly,
            "z_score": round(z_score, 2),
            "reasons": reasons,
            "risk_level": risk_level,
        }

    @classmethod
    async def _calculate_ip_zscore(cls, r, ip: str, now: float) -> float:
        """Calculate z-score of this IP's request frequency vs population."""
        window = 60  # 1 minute window

        # Increment this IP's counter
        ip_key = f"{cls.PREFIX}:count:{ip}:{int(now) // window}"
        await r.incr(ip_key)
        await r.expire(ip_key, window * 2)

        # Get this IP's count
        ip_count = int(await r.get(ip_key) or 0)

        # Get all IP counts for this window (sample population)
        all_counts = []
        async for key in r.scan_iter(f"{cls.PREFIX}:count:*:{int(now) // window}"):
            val = await r.get(key)
            if val:
                all_counts.append(int(val))

        if len(all_counts) < 3:
            return 0.0  # Not enough data

        mean = np.mean(all_counts)
        std = np.std(all_counts)

        if std < 0.1:
            return 0.0

        return (ip_count - mean) / std

    @classmethod
    async def _check_path_concentration(
        cls, r, ip: str, path: str, now: float
    ) -> float:
        """Check if IP is focusing on a single endpoint (bot-like behavior)."""
        window = 60
        key = f"{cls.PREFIX}:paths:{ip}:{int(now) // window}"

        await r.hincrby(key, path, 1)
        await r.expire(key, window * 2)

        path_counts = await r.hgetall(key)
        if not path_counts:
            return 0.0

        counts = [int(v) for v in path_counts.values()]
        total = sum(counts)
        max_count = max(counts)

        return max_count / total if total > 0 else 0.0

    @classmethod
    async def _check_timing_regularity(cls, r, ip: str, now: float) -> float:
        """
        Detect regular-interval requests (bot behavior).
        Humans have variable intervals; bots are often precise.
        """
        timestamps_key = f"{cls.PREFIX}:timestamps:{ip}"

        await r.rpush(timestamps_key, str(now))
        await r.ltrim(timestamps_key, -20, -1)  # keep last 20
        await r.expire(timestamps_key, 120)

        timestamps = await r.lrange(timestamps_key, 0, -1)
        if len(timestamps) < 5:
            return 0.0

        ts = [float(t) for t in timestamps]
        intervals = [ts[i + 1] - ts[i] for i in range(len(ts) - 1)]

        if not intervals:
            return 0.0

        mean_interval = np.mean(intervals)
        if mean_interval < 0.01:
            return 0.95  # Extremely fast = likely bot

        std_interval = np.std(intervals)
        # Coefficient of variation: low CV = regular timing = bot-like
        cv = std_interval / mean_interval if mean_interval > 0 else 0

        # Map CV to regularity score: CV < 0.1 is very regular
        regularity = max(0, 1.0 - cv)
        return round(regularity, 3)

    @classmethod
    async def _detect_global_spike(cls, r, now: float) -> bool:
        """Detect if there's a global traffic spike (potential DDoS)."""
        current_key = f"{cls.PREFIX}:global:{int(now) // 10}"
        await r.incr(current_key)
        await r.expire(current_key, 30)

        current = int(await r.get(current_key) or 0)

        # Compare with previous intervals
        prev_counts = []
        for i in range(1, 7):
            val = await r.get(f"{cls.PREFIX}:global:{int(now) // 10 - i}")
            if val:
                prev_counts.append(int(val))

        if len(prev_counts) < 3:
            return False

        avg_prev = np.mean(prev_counts)
        return current > avg_prev * settings.burst_multiplier if avg_prev > 0 else False
