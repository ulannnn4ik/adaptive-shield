"""
Client Fingerprinter — creates a composite identity from request metadata.

Unlike simple IP-based tracking, this combines multiple signals:
- IP address
- User-Agent string hash
- Accept-Language + Accept-Encoding
- TLS fingerprint approximation (via header ordering)
- Request timing patterns

This makes it harder for attackers to evade detection by rotating IPs.
"""

import hashlib
from fastapi import Request


def extract_fingerprint(request: Request) -> dict:
    """Extract fingerprint components from an HTTP request."""
    headers = dict(request.headers)

    # Header order fingerprint — bots often have different header ordering
    header_order = "|".join(headers.keys())
    header_hash = hashlib.md5(header_order.encode()).hexdigest()[:8]

    ua = headers.get("user-agent", "unknown")
    ua_hash = hashlib.md5(ua.encode()).hexdigest()[:8]

    accept_lang = headers.get("accept-language", "none")
    accept_enc = headers.get("accept-encoding", "none")

    # Composite fingerprint ID
    raw = f"{ua}|{accept_lang}|{accept_enc}|{header_order}"
    fingerprint_id = hashlib.sha256(raw.encode()).hexdigest()[:16]

    return {
        "fingerprint_id": fingerprint_id,
        "ip": request.client.host if request.client else "unknown",
        "ua_hash": ua_hash,
        "header_hash": header_hash,
        "accept_language": accept_lang[:50],
        "accept_encoding": accept_enc[:50],
        "user_agent": ua[:200],
    }


def is_suspicious_fingerprint(fp: dict) -> tuple[bool, list[str]]:
    """Basic heuristic checks on a client fingerprint."""
    reasons = []
    ua = fp.get("user_agent", "").lower()

    # No User-Agent or known bot patterns
    if not ua or ua == "unknown":
        reasons.append("missing_user_agent")
    bot_indicators = ["python-requests", "curl", "wget", "httpx", "go-http", "java/", "bot"]
    for indicator in bot_indicators:
        if indicator in ua:
            reasons.append(f"bot_ua:{indicator}")
            break

    # Missing standard headers
    if fp.get("accept_language") == "none":
        reasons.append("no_accept_language")
    if fp.get("accept_encoding") == "none":
        reasons.append("no_accept_encoding")

    return len(reasons) > 0, reasons
