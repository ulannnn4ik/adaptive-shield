"""
Normal Traffic Simulator — generates realistic baseline traffic.

Run this BEFORE attacks to let the system learn normal patterns.
Also useful during attacks to show that legitimate users still get through.

Usage:
    python attacks/normal_traffic.py --rps 5 --duration 120
"""

import asyncio
import time
import random
import argparse

import httpx


ENDPOINTS = [
    "/api/",
    "/api/data",
    "/api/profile",
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148",
]


async def generate_traffic(base_url: str, rps: float, duration: int):
    print(f"[*] Generating normal traffic: ~{rps} RPS for {duration}s")
    print(f"    Target: {base_url}")

    success = 0
    blocked = 0
    errors = 0
    start = time.time()

    async with httpx.AsyncClient(timeout=10) as client:
        while time.time() - start < duration:
            endpoint = random.choice(ENDPOINTS)
            url = f"{base_url}{endpoint}"

            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
                "Accept-Encoding": "gzip, deflate, br",
                "Accept": "application/json",
            }

            try:
                r = await client.get(url, headers=headers)
                if r.status_code == 200:
                    success += 1
                elif r.status_code in (429, 403):
                    blocked += 1
                    print(f"  ⚠️ Legitimate user blocked! Status={r.status_code} — False Positive!")
            except Exception:
                errors += 1

            # Human-like variable delay
            delay = random.expovariate(rps) if rps > 0 else 1.0
            await asyncio.sleep(max(0.05, delay))

    elapsed = time.time() - start
    total = success + blocked + errors
    print(f"\n{'='*50}")
    print(f"  Normal Traffic Report")
    print(f"{'='*50}")
    print(f"  Duration:   {elapsed:.1f}s")
    print(f"  Total:      {total}")
    print(f"  Success:    {success}")
    print(f"  Blocked:    {blocked} (FALSE POSITIVES)")
    print(f"  Errors:     {errors}")
    print(f"  FP Rate:    {blocked / total * 100:.2f}%" if total else "  FP Rate:    N/A")
    print(f"{'='*50}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Normal Traffic Generator")
    parser.add_argument("--target", default="http://localhost:8000", help="Base URL")
    parser.add_argument("--rps", type=float, default=5, help="Avg requests per second")
    parser.add_argument("--duration", type=int, default=120, help="Duration in seconds")
    args = parser.parse_args()

    asyncio.run(generate_traffic(args.target, args.rps, args.duration))
