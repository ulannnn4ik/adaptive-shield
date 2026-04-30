from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # Redis
    redis_url: str = "redis://localhost:6379/0"

    # Rate limiting defaults (requests per window)
    rate_limit_general: int = 30         # general endpoints per minute
    rate_limit_login: int = 5            # login attempts per minute
    rate_limit_window_seconds: int = 60

    # Adaptive thresholds
    adaptive_enabled: bool = True
    baseline_learning_period: int = 60   # seconds to learn baseline (faster for demo)
    burst_multiplier: float = 2.0        # alert if RPS > baseline * multiplier (more sensitive)

    # IP reputation
    reputation_ban_threshold: float = 100.0
    reputation_challenge_threshold: float = 50.0
    reputation_decay_rate: float = 0.95  # per minute decay
    reputation_ddos_penalty: float = 25.0
    reputation_bruteforce_penalty: float = 35.0

    # Brute force
    bruteforce_max_attempts: int = 5
    bruteforce_lockout_seconds: int = 900  # 15 min
    bruteforce_progressive: bool = True    # progressive lockout

    # Fingerprinting
    fingerprint_enabled: bool = True

    # Telegram alerts
    telegram_bot_token: Optional[str] = None
    telegram_chat_id: Optional[str] = None

    # Anomaly detection
    anomaly_z_score_threshold: float = 2.5

    # Whitelist
    whitelisted_ips: list[str] = []

    # JWT Secret Key
    jwt_secret_key: str = "as-9f4k2m8x1p7q3r6t5v0w-diploma-2026-shield"

    # Reverse Proxy — защищаемый ресурс
    proxy_target: Optional[str] = None

    class Config:
        env_file = ".env"


settings = Settings()
