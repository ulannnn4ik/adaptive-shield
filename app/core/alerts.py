"""
Alert system — sends notifications about attacks to Telegram.

If TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID are not set,
alerts are logged but not sent (graceful degradation).
"""

import asyncio
import aiohttp
import structlog
from config.settings import settings

log = structlog.get_logger()

_session: aiohttp.ClientSession | None = None


async def _get_session() -> aiohttp.ClientSession:
    global _session
    if _session is None or _session.closed:
        _session = aiohttp.ClientSession()
    return _session


async def send_alert(
    title: str,
    message: str,
    severity: str = "warning",  # 'info', 'warning', 'critical'
):
    """Send alert to Telegram and log it."""
    emoji = {"info": "ℹ️", "warning": "⚠️", "critical": "🚨"}.get(severity, "📌")
    full_message = f"{emoji} *{title}*\n\n{message}"

    log.warning("shield_alert", title=title, severity=severity, message=message)

    if not settings.telegram_bot_token or not settings.telegram_chat_id:
        return  # Telegram not configured, just log

    try:
        session = await _get_session()
        url = f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage"
        payload = {
            "chat_id": settings.telegram_chat_id,
            "text": full_message,
            "parse_mode": "Markdown",
        }
        async with session.post(url, json=payload, timeout=5) as resp:
            if resp.status != 200:
                log.error("telegram_send_failed", status=resp.status)
    except Exception as e:
        log.error("telegram_error", error=str(e))


async def alert_ddos_detected(ip: str, rps: float, baseline: float):
    await send_alert(
        "DDoS Attack Detected",
        f"IP: `{ip}`\nCurrent RPS: {rps:.1f}\nBaseline: {baseline:.1f}\n"
        f"Ratio: {rps / baseline:.1f}x",
        severity="critical",
    )


async def alert_bruteforce_detected(ip: str, attempts: int, target: str):
    await send_alert(
        "Brute Force Attack Detected",
        f"IP: `{ip}`\nAttempts: {attempts}\nTarget: {target}",
        severity="critical",
    )


async def alert_ip_banned(ip: str, score: float):
    await send_alert(
        "IP Banned",
        f"IP: `{ip}`\nReputation score: {score:.1f}",
        severity="warning",
    )


async def close_session():
    global _session
    if _session and not _session.closed:
        await _session.close()
        _session = None
