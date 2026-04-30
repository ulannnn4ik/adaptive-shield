from pydantic import BaseModel
from typing import Optional


class LoginRequest(BaseModel):
    username: str
    password: str


class LoginResponse(BaseModel):
    success: bool
    message: str
    token: Optional[str] = None
    user: Optional[dict] = None


class ShieldStatus(BaseModel):
    requests_total: int = 0
    blocked_total: int = 0
    rate_limited_total: int = 0
    bruteforce_blocked_total: int = 0
    anomalies_detected: int = 0
    challenges_issued: int = 0
    baseline_rps: float = 0
    current_rps: float = 0
    adaptive_multiplier: float = 1.0


class IPInfo(BaseModel):
    ip: str
    score: float
    action: str
    violation_count: int
    last_violation: str
    history: list = []
