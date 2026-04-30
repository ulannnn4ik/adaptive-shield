"""
Full Demo Scenario — FIXED version.
Uses different User-Agents so attack traffic and normal traffic
have different fingerprints (won't ban each other).
"""

import asyncio
import time
import httpx
import random

BASE = "http://localhost:8000"

# Normal user headers (browser-like)
NORMAL_HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9,ru;q=0.8",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept": "application/json, text/html",
}

# Attack headers (bot-like — different fingerprint)
ATTACK_HEADERS = {
    "User-Agent": "python-requests/2.31.0",
}

# Brute force headers (another different fingerprint)
BF_HEADERS = {
    "User-Agent": "curl/8.0",
}


async def phase(name: str):
    print(f"\n{'='*60}")
    print(f"  PHASE: {name}")
    print(f"{'='*60}")
    await asyncio.sleep(2)


async def main():
    print("🛡️  ADAPTIVE SHIELD — FULL DEMO SCENARIO")
    print("📊 Open http://localhost:8000/dashboard to watch!\n")
    await asyncio.sleep(3)

    async with httpx.AsyncClient(timeout=10) as client:

        # Phase 1: Normal traffic — learn baseline
        await phase("1/5 — NORMAL TRAFFIC (30s baseline learning)")
        success, blocked = 0, 0
        start = time.time()
        while time.time() - start < 30:
            endpoints = ["/api/", "/api/data", "/api/profile"]
            try:
                r = await client.get(
                    f"{BASE}{random.choice(endpoints)}",
                    headers=NORMAL_HEADERS,
                )
                if r.status_code == 200:
                    success += 1
                elif r.status_code in (429, 403):
                    blocked += 1
            except Exception:
                pass
            await asyncio.sleep(random.uniform(0.3, 1.0))
        print(f"  ✅ Normal: {success} OK, {blocked} blocked (should be 0)")

        # Phase 2: DDoS Flood (bot headers — different fingerprint!)
        await phase("2/5 — DDoS FLOOD ATTACK (20s, ~50 RPS)")
        success, blocked = 0, 0
        start = time.time()
        while time.time() - start < 20:
            tasks = []
            for _ in range(10):
                async def flood_req():
                    try:
                        r = await client.get(
                            f"{BASE}/api/data",
                            headers=ATTACK_HEADERS,
                        )
                        return r.status_code
                    except Exception:
                        return 0
                tasks.append(asyncio.create_task(flood_req()))
            results = await asyncio.gather(*tasks)
            for code in results:
                if code == 200:
                    success += 1
                elif code in (429, 403):
                    blocked += 1
            await asyncio.sleep(0.2)
        total = success + blocked
        if total > 0:
            print(f"  🚨 Flood: {total} sent, {blocked} blocked ({blocked/total*100:.0f}% block rate)")
        else:
            print(f"  🚨 Flood: no responses received")

        # Phase 3: Recovery + normal traffic (browser headers — clean fingerprint)
        await phase("3/5 — RECOVERY + NORMAL TRAFFIC (15s)")
        success, blocked = 0, 0
        start = time.time()
        while time.time() - start < 15:
            endpoints = ["/api/", "/api/data", "/api/profile"]
            try:
                r = await client.get(
                    f"{BASE}{random.choice(endpoints)}",
                    headers=NORMAL_HEADERS,
                )
                if r.status_code == 200:
                    success += 1
                elif r.status_code in (429, 403):
                    blocked += 1
            except Exception:
                pass
            await asyncio.sleep(random.uniform(0.5, 1.5))
        print(f"  ✅ Recovery: {success} OK, {blocked} false positives")

        # Phase 4: Brute Force (curl headers — yet another fingerprint)
        await phase("4/5 — BRUTE FORCE ATTACK on /login")
        passwords = ["wrong1", "wrong2", "wrong3", "wrong4", "wrong5",
                      "wrong6", "wrong7", "admin123"]
        for pw in passwords:
            try:
                r = await client.post(
                    f"{BASE}/api/login",
                    json={"username": "admin", "password": pw},
                    headers=BF_HEADERS,
                )
                code = r.status_code
                data = r.json()
                if code == 200 and data.get("success"):
                    status = "✅ SUCCESS"
                elif code == 429:
                    lockout = data.get("lockout_remaining", "?")
                    status = f"🔒 LOCKED OUT for {lockout}s"
                elif code == 403:
                    status = "🚫 BANNED"
                else:
                    status = f"❌ Failed ({code})"
                print(f"  admin:{pw} → {status}")
            except Exception as e:
                print(f"  admin:{pw} → ⚠️ Error: {e}")
            await asyncio.sleep(0.5)

        # Phase 5: Final normal traffic (browser headers — should pass)
        await phase("5/5 — FINAL NORMAL TRAFFIC (15s, measuring FP rate)")
        success, blocked = 0, 0
        start = time.time()
        while time.time() - start < 15:
            endpoints = ["/api/", "/api/data", "/api/profile"]
            try:
                r = await client.get(
                    f"{BASE}{random.choice(endpoints)}",
                    headers=NORMAL_HEADERS,
                )
                if r.status_code == 200:
                    success += 1
                elif r.status_code in (429, 403):
                    blocked += 1
            except Exception:
                pass
            await asyncio.sleep(random.uniform(0.3, 1.0))
        total = success + blocked
        fp_rate = blocked / total * 100 if total else 0
        print(f"  📊 Final: {total} requests, {blocked} false positives ({fp_rate:.1f}% FP rate)")

    print(f"\n{'='*60}")
    print(f"  DEMO COMPLETE!")
    print(f"  Check the dashboard for full visualization.")
    print(f"{'='*60}\n")


if __name__ == "__main__":
    asyncio.run(main())
