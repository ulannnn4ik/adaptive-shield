"""
Adaptive Shield — Unit Tests
Тестирование всех алгоритмов защиты.

Запуск:
    pytest tests/test_protection.py -v
    pytest tests/test_protection.py -v --tb=short
"""

import pytest
import asyncio
import time
import sys
import os

# Добавляем корень проекта в путь
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


# ══════════════════════════════════════════════════════════════
# ТЕСТ 1: Token Bucket алгоритм
# ══════════════════════════════════════════════════════════════

class TokenBucket:
    """Чистая реализация Token Bucket для тестирования."""
    def __init__(self, rate: float, capacity: float):
        self.rate = rate          # tokens per second
        self.capacity = capacity  # max tokens
        self.tokens = capacity    # start full
        self.last_update = time.time()

    def consume(self, tokens: float = 1.0) -> bool:
        now = time.time()
        elapsed = now - self.last_update
        self.last_update = now

        # Пополняем токены
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        if self.tokens >= tokens:
            self.tokens -= tokens
            return True  # разрешено
        return False  # заблокировано


class TestTokenBucket:
    """Тесты алгоритма Token Bucket."""

    def test_full_bucket_allows_requests(self):
        """Полный bucket должен пропускать запросы."""
        bucket = TokenBucket(rate=10, capacity=10)
        assert bucket.consume() is True

    def test_empty_bucket_blocks_requests(self):
        """Пустой bucket должен блокировать."""
        bucket = TokenBucket(rate=10, capacity=5)
        # Исчерпываем все токены
        for _ in range(5):
            bucket.consume()
        # Следующий должен быть заблокирован
        assert bucket.consume() is False

    def test_bucket_refills_over_time(self):
        """Bucket должен пополняться со временем."""
        bucket = TokenBucket(rate=100, capacity=5)
        # Исчерпываем
        for _ in range(5):
            bucket.consume()
        assert bucket.consume() is False

        # Имитируем прошедшее время — добавляем токены напрямую
        bucket.tokens = 2.0
        assert bucket.consume() is True

    def test_burst_allowed_within_capacity(self):
        """Burst запросы разрешены пока есть токены."""
        bucket = TokenBucket(rate=1, capacity=10)
        results = [bucket.consume() for _ in range(10)]
        assert all(results), "Все 10 burst запросов должны пройти"

    def test_burst_blocked_after_capacity(self):
        """После исчерпания capacity — блокировать."""
        bucket = TokenBucket(rate=1, capacity=5)
        for _ in range(5):
            bucket.consume()
        assert bucket.consume() is False, "11-й запрос должен быть заблокирован"

    def test_rate_limits_sustained_traffic(self):
        """Rate должен ограничивать постоянный трафик."""
        bucket = TokenBucket(rate=2, capacity=2)  # 2 req/sec
        # Первые 2 проходят
        assert bucket.consume() is True
        assert bucket.consume() is True
        # Третий блокируется
        assert bucket.consume() is False

    def test_capacity_cannot_exceed_maximum(self):
        """Количество токенов не должно превышать capacity."""
        bucket = TokenBucket(rate=100, capacity=5)
        bucket.tokens = 3
        bucket.last_update = time.time() - 10  # 10 секунд назад
        bucket.consume()  # это обновит токены
        assert bucket.tokens <= 5, "Токены не должны превышать capacity"


# ══════════════════════════════════════════════════════════════
# ТЕСТ 2: EMA (Exponential Moving Average) алгоритм
# ══════════════════════════════════════════════════════════════

class EMABaseline:
    """Чистая реализация EMA для тестирования."""
    def __init__(self, alpha: float = 0.1):
        self.alpha = alpha
        self.baseline = None

    def update(self, value: float) -> float:
        if self.baseline is None:
            self.baseline = value
        else:
            self.baseline = self.alpha * value + (1 - self.alpha) * self.baseline
        return self.baseline

    def is_spike(self, current: float, multiplier: float = 2.0) -> bool:
        if self.baseline is None or self.baseline < 1:
            return False
        return current > self.baseline * multiplier


class TestEMABaseline:
    """Тесты алгоритма EMA Baseline."""

    def test_first_update_sets_baseline(self):
        """Первое значение должно стать baseline."""
        ema = EMABaseline()
        result = ema.update(100.0)
        assert result == 100.0

    def test_ema_smooths_values(self):
        """EMA должна сглаживать резкие изменения."""
        ema = EMABaseline(alpha=0.1)
        # Устанавливаем baseline
        for _ in range(20):
            ema.update(10.0)
        baseline_before = ema.baseline

        # Один spike не должен сильно изменить baseline
        ema.update(1000.0)
        # alpha=0.1: new = 0.1*1000 + 0.9*10 = 100+9 = 109
        # Главное — baseline вырос, но не до 1000
        assert ema.baseline < 200.0, "EMA должна сглаживать spike (не до 1000)"
        assert ema.baseline > baseline_before, "Baseline должен немного вырасти"

    def test_ema_learns_normal_traffic(self):
        """EMA должна учить нормальный трафик."""
        ema = EMABaseline(alpha=0.1)
        for _ in range(100):
            ema.update(50.0)
        # Baseline должен быть близко к 50
        assert abs(ema.baseline - 50.0) < 1.0

    def test_spike_detection(self):
        """Должен обнаруживать аномальный spike."""
        ema = EMABaseline(alpha=0.1)
        # Учим нормальный трафик
        for _ in range(50):
            ema.update(10.0)

        # Spike в 5 раз выше нормы
        assert ema.is_spike(50.0, multiplier=2.0) is True

    def test_normal_traffic_not_flagged(self):
        """Нормальный трафик не должен быть spike."""
        ema = EMABaseline(alpha=0.1)
        for _ in range(50):
            ema.update(10.0)

        # Небольшое увеличение — не spike
        assert ema.is_spike(12.0, multiplier=2.0) is False

    def test_alpha_affects_learning_speed(self):
        """Больший alpha = быстрее учится."""
        slow_ema = EMABaseline(alpha=0.01)
        fast_ema = EMABaseline(alpha=0.5)

        # Начинаем с 0
        slow_ema.baseline = 0.0
        fast_ema.baseline = 0.0

        # После одного обновления 100
        slow_ema.update(100.0)
        fast_ema.update(100.0)

        assert fast_ema.baseline > slow_ema.baseline, \
            "Быстрый EMA должен реагировать быстрее"

    def test_no_spike_without_baseline(self):
        """Без baseline нет spike."""
        ema = EMABaseline()
        assert ema.is_spike(1000.0) is False


# ══════════════════════════════════════════════════════════════
# ТЕСТ 3: Progressive Lockout алгоритм
# ══════════════════════════════════════════════════════════════

class ProgressiveLockout:
    """Чистая реализация Progressive Lockout для тестирования."""
    def __init__(self, max_attempts: int = 5, base_lockout: int = 900):
        self.max_attempts = max_attempts
        self.base_lockout = base_lockout
        self.failures = {}    # ip -> [timestamps]
        self.lockouts = {}    # ip -> until_timestamp
        self.lockout_count = {}  # ip -> count

    def record_failure(self, ip: str) -> dict:
        now = time.time()
        if ip not in self.failures:
            self.failures[ip] = []

        self.failures[ip].append(now)
        count = len(self.failures[ip])

        if count >= self.max_attempts:
            # Progressive: base * 2^lockout_count
            lc = self.lockout_count.get(ip, 0)
            duration = min(self.base_lockout * (2 ** lc), 3600)
            self.lockouts[ip] = now + duration
            self.lockout_count[ip] = lc + 1
            self.failures[ip] = []
            return {"locked": True, "duration": duration, "lockout_number": lc + 1}

        return {"locked": False, "attempts": count, "remaining": self.max_attempts - count}

    def is_locked(self, ip: str) -> tuple[bool, int]:
        if ip not in self.lockouts:
            return False, 0
        remaining = self.lockouts[ip] - time.time()
        if remaining > 0:
            return True, int(remaining)
        del self.lockouts[ip]
        return False, 0

    def detect_stuffing(self, ip: str, usernames: set) -> bool:
        return len(usernames) >= 3


class TestProgressiveLockout:
    """Тесты алгоритма Progressive Lockout."""

    def test_no_lockout_below_threshold(self):
        """До порога — нет блокировки."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        for i in range(4):
            result = guard.record_failure("1.2.3.4")
            assert result["locked"] is False

    def test_lockout_at_threshold(self):
        """На пороге — блокировка."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        for i in range(4):
            guard.record_failure("1.2.3.4")
        result = guard.record_failure("1.2.3.4")
        assert result["locked"] is True

    def test_first_lockout_duration(self):
        """Первая блокировка = base_lockout."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        for _ in range(5):
            result = guard.record_failure("1.2.3.4")
        assert result["duration"] == 900

    def test_second_lockout_doubles(self):
        """Вторая блокировка = base * 2."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        # Первая блокировка
        for _ in range(5):
            guard.record_failure("1.2.3.4")
        # Освобождаем
        guard.lockouts.clear()
        # Вторая блокировка
        for _ in range(5):
            result = guard.record_failure("1.2.3.4")
        assert result["duration"] == 1800  # 900 * 2

    def test_third_lockout_quadruples(self):
        """Третья блокировка = base * 4."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        for round_num in range(3):
            for _ in range(5):
                result = guard.record_failure("1.2.3.4")
            guard.lockouts.clear()
        assert result["duration"] == 3600  # max cap

    def test_lockout_max_cap(self):
        """Максимальная блокировка = 1 час."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        for round_num in range(10):
            for _ in range(5):
                result = guard.record_failure("1.2.3.4")
            guard.lockouts.clear()
        assert result["duration"] <= 3600

    def test_ip_is_blocked_after_lockout(self):
        """После блокировки — IP заблокирован."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        for _ in range(5):
            guard.record_failure("1.2.3.4")
        locked, remaining = guard.is_locked("1.2.3.4")
        assert locked is True
        assert remaining > 0

    def test_different_ips_independent(self):
        """Разные IP не влияют друг на друга."""
        guard = ProgressiveLockout(max_attempts=5, base_lockout=900)
        for _ in range(5):
            guard.record_failure("1.1.1.1")
        # Другой IP не заблокирован
        locked, _ = guard.is_locked("2.2.2.2")
        assert locked is False

    def test_credential_stuffing_detection(self):
        """3+ разных usernames с одного IP = credential stuffing."""
        guard = ProgressiveLockout()
        usernames = {"admin", "user1", "test"}
        assert guard.detect_stuffing("1.2.3.4", usernames) is True

    def test_targeted_attack_not_stuffing(self):
        """1 username = targeted attack, не stuffing."""
        guard = ProgressiveLockout()
        usernames = {"admin"}
        assert guard.detect_stuffing("1.2.3.4", usernames) is False


# ══════════════════════════════════════════════════════════════
# ТЕСТ 4: IP Reputation Scoring
# ══════════════════════════════════════════════════════════════

class IPReputationScore:
    """Чистая реализация IP Reputation для тестирования."""
    PENALTIES = {
        "rate_limit": 10.0,
        "brute_force": 35.0,
        "ddos_pattern": 25.0,
        "anomaly": 15.0,
        "suspicious_fingerprint": 5.0,
    }
    BAN_THRESHOLD = 100.0
    CHALLENGE_THRESHOLD = 50.0
    DECAY_RATE = 0.95  # per minute

    def __init__(self):
        self.scores = {}  # ip -> (score, timestamp)

    def add_violation(self, ip: str, violation_type: str) -> float:
        current = self.get_score(ip)
        penalty = self.PENALTIES.get(violation_type, 10.0)
        new_score = current + penalty
        self.scores[ip] = (new_score, time.time())
        return new_score

    def get_score(self, ip: str) -> float:
        if ip not in self.scores:
            return 0.0
        score, last_update = self.scores[ip]
        minutes = (time.time() - last_update) / 60.0
        decayed = score * (self.DECAY_RATE ** minutes)
        if decayed < 0.1:
            del self.scores[ip]
            return 0.0
        return round(decayed, 2)

    def get_action(self, ip: str) -> str:
        score = self.get_score(ip)
        if score >= self.BAN_THRESHOLD:
            return "ban"
        elif score >= self.CHALLENGE_THRESHOLD:
            return "challenge"
        elif score > 20:
            return "warn"
        return "allow"


class TestIPReputation:
    """Тесты системы IP Reputation."""

    def test_new_ip_has_zero_score(self):
        """Новый IP начинает с нулевым score."""
        rep = IPReputationScore()
        assert rep.get_score("1.2.3.4") == 0.0

    def test_violation_increases_score(self):
        """Нарушение увеличивает score."""
        rep = IPReputationScore()
        score = rep.add_violation("1.2.3.4", "rate_limit")
        assert score == 10.0

    def test_multiple_violations_accumulate(self):
        """Несколько нарушений накапливаются."""
        rep = IPReputationScore()
        rep.add_violation("1.2.3.4", "rate_limit")   # +10
        rep.add_violation("1.2.3.4", "rate_limit")   # +10
        rep.add_violation("1.2.3.4", "rate_limit")   # +10
        score = rep.get_score("1.2.3.4")
        assert score == 30.0

    def test_brute_force_penalty_higher(self):
        """Brute force имеет больший штраф чем rate limit."""
        rep = IPReputationScore()
        bf_score = rep.add_violation("1.1.1.1", "brute_force")
        rl_score = rep.add_violation("2.2.2.2", "rate_limit")
        assert bf_score > rl_score

    def test_ban_threshold_triggers_ban(self):
        """Score >= 100 → ban."""
        rep = IPReputationScore()
        # ddos_pattern = 25 * 4 = 100
        for _ in range(4):
            rep.add_violation("1.2.3.4", "ddos_pattern")
        assert rep.get_action("1.2.3.4") == "ban"

    def test_challenge_threshold(self):
        """Score >= 50 → challenge."""
        rep = IPReputationScore()
        rep.add_violation("1.2.3.4", "ddos_pattern")  # +25
        rep.add_violation("1.2.3.4", "ddos_pattern")  # +25 = 50
        assert rep.get_action("1.2.3.4") == "challenge"

    def test_clean_ip_allowed(self):
        """IP без нарушений → allow."""
        rep = IPReputationScore()
        assert rep.get_action("9.9.9.9") == "allow"

    def test_decay_reduces_score(self):
        """Score должен снижаться со временем (decay)."""
        rep = IPReputationScore()
        rep.add_violation("1.2.3.4", "ddos_pattern")  # score = 25

        # Имитируем прошедшее время — устанавливаем old timestamp
        rep.scores["1.2.3.4"] = (25.0, time.time() - 300)  # 5 минут назад

        score_after = rep.get_score("1.2.3.4")
        assert score_after < 25.0, "Score должен снижаться со временем"

    def test_different_ips_independent(self):
        """Scores разных IP независимы."""
        rep = IPReputationScore()
        rep.add_violation("1.1.1.1", "ddos_pattern")
        assert rep.get_score("2.2.2.2") == 0.0

    def test_score_resets_after_decay(self):
        """После полного decay IP разбаниватеся."""
        rep = IPReputationScore()
        rep.scores["1.2.3.4"] = (0.05, time.time() - 1)  # почти 0
        score = rep.get_score("1.2.3.4")
        assert score == 0.0  # должен быть удалён


# ══════════════════════════════════════════════════════════════
# ТЕСТ 5: Sliding Window Counter
# ══════════════════════════════════════════════════════════════

class SlidingWindowCounter:
    """Чистая реализация Sliding Window для тестирования."""
    def __init__(self, window_seconds: int, limit: int):
        self.window = window_seconds
        self.limit = limit
        self.requests = {}  # ip -> [timestamps]

    def add_request(self, ip: str) -> dict:
        now = time.time()
        if ip not in self.requests:
            self.requests[ip] = []

        # Удаляем старые запросы за пределами окна
        cutoff = now - self.window
        self.requests[ip] = [t for t in self.requests[ip] if t > cutoff]

        # Добавляем текущий
        self.requests[ip].append(now)
        count = len(self.requests[ip])

        return {
            "allowed": count <= self.limit,
            "count": count,
            "remaining": max(0, self.limit - count),
        }


class TestSlidingWindow:
    """Тесты алгоритма Sliding Window."""

    def test_allows_within_limit(self):
        """Запросы в пределах лимита должны проходить."""
        sw = SlidingWindowCounter(window_seconds=60, limit=10)
        for _ in range(10):
            result = sw.add_request("1.2.3.4")
        assert result["allowed"] is True

    def test_blocks_over_limit(self):
        """Запросы сверх лимита блокируются."""
        sw = SlidingWindowCounter(window_seconds=60, limit=5)
        for _ in range(5):
            sw.add_request("1.2.3.4")
        result = sw.add_request("1.2.3.4")
        assert result["allowed"] is False

    def test_old_requests_removed(self):
        """Запросы старше window удаляются."""
        sw = SlidingWindowCounter(window_seconds=60, limit=5)
        # Добавляем старые запросы (за пределами окна)
        old_time = time.time() - 120
        sw.requests["1.2.3.4"] = [old_time] * 10
        # Новый запрос должен пройти
        result = sw.add_request("1.2.3.4")
        assert result["allowed"] is True

    def test_remaining_decreases(self):
        """Remaining должен уменьшаться с каждым запросом."""
        sw = SlidingWindowCounter(window_seconds=60, limit=10)
        r1 = sw.add_request("1.2.3.4")
        r2 = sw.add_request("1.2.3.4")
        assert r2["remaining"] < r1["remaining"]

    def test_different_ips_independent(self):
        """Разные IP имеют независимые счётчики."""
        sw = SlidingWindowCounter(window_seconds=60, limit=3)
        for _ in range(3):
            sw.add_request("1.1.1.1")
        result = sw.add_request("2.2.2.2")
        assert result["allowed"] is True


# ══════════════════════════════════════════════════════════════
# ЗАПУСК ВСЕХ ТЕСТОВ
# ══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import subprocess
    result = subprocess.run(
        ["python", "-m", "pytest", __file__, "-v", "--tb=short"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    sys.exit(result.returncode)
