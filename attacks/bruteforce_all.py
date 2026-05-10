"""
Запускает все 3 режима Brute Force атак подряд.
Скопируй этот файл на Kali рядом с bruteforce_simulator.py
"""

import asyncio
import sys
sys.path.insert(0, '.')

from bruteforce_simulator import simple_bruteforce, credential_stuffing, slow_and_low

TARGET = "http://localhost:8000/api/login"

async def main():
    print("\n" + "="*60)
    print("  BRUTE FORCE — ВСЕ 3 РЕЖИМА")
    print("="*60)

    print("\n[1/3] Simple Brute Force...")
    await simple_bruteforce(TARGET, "admin")

    print("\n⏳ Пауза 5 секунд...\n")
    await asyncio.sleep(5)

    print("\n[2/3] Credential Stuffing...")
    await credential_stuffing(TARGET)

    print("\n⏳ Пауза 5 секунд...\n")
    await asyncio.sleep(5)

    print("\n[3/3] Slow & Low...")
    await slow_and_low(TARGET, "admin")

    print("\n" + "="*60)
    print("  ВСЕ ТЕСТЫ ЗАВЕРШЕНЫ")
    print("  Проверь Dashboard: http://localhost:8000/dashboard")
    print("="*60 + "\n")

if __name__ == "__main__":
    asyncio.run(main())
