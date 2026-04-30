# Adaptive Shield — Система защиты веб-ресурсов

**Дипломный проект**  
Тема: *Разработка системы защиты веб-ресурсов от DDoS и Brute Force атак: методы и практическая реализация*

---

## Содержание

1. [Описание проекта](#описание-проекта)
2. [Архитектура системы](#архитектура-системы)
3. [Алгоритмы защиты](#алгоритмы-защиты)
4. [Установка и запуск](#установка-и-запуск)
5. [Структура проекта](#структура-проекта)
6. [Демонстрация атак](#демонстрация-атак)
7. [Результаты тестирования](#результаты-тестирования)
8. [Сравнение с аналогами](#сравнение-с-аналогами)
9. [API документация](#api-документация)
10. [Тестирование](#тестирование)

---

## Описание проекта

Adaptive Shield — это программная система защиты веб-ресурсов, реализованная в виде middleware для FastAPI. Система обнаруживает и блокирует три вида атак в реальном времени:

- **DDoS атаки** (HTTP Flood) — массовые запросы с целью перегрузки сервера
- **Brute Force атаки** — перебор паролей на эндпоинтах аутентификации
- **Slowloris атаки** — медленные соединения, исчерпывающие пул подключений

### Ключевые возможности

- Адаптивные лимиты на основе EMA (Exponential Moving Average)
- Прогрессивная блокировка IP с автоматическим разбаном (decay)
- Система репутации IP с накопительным scoring
- Обнаружение credential stuffing
- Защита от Slowloris с таймаутом соединений
- Dashboard мониторинга в реальном времени
- Персистентное хранение событий в SQLite
- Экспорт отчётов (PDF, CSV, JSON, TXT)
- Telegram уведомления об атаках

---

## Архитектура системы

```
Входящий запрос
       │
       ▼
┌─────────────────────────────────────┐
│         Shield Middleware           │
│                                     │
│  1. Извлечение реального IP         │
│     (защита от X-Forwarded-For)     │
│                                     │
│  2. Проверка Whitelist              │
│                                     │
│  3. Slowloris защита                │
│     (таймаут + лимит соединений)    │
│                                     │
│  4. IP Reputation check             │
│     score >= 100 → 403 BAN          │
│                                     │
│  5. Rate Limiting                   │
│     Token Bucket + Sliding Window   │
│                                     │
│  6. Anomaly Detection               │
│     Z-score анализ трафика          │
│                                     │
│  7. Brute Force Guard               │
│     (только для /api/login)         │
│                                     │
└─────────────────────────────────────┘
       │
       ▼
  Приложение / 403 / 429
       │
       ▼
┌─────────────┐    ┌──────────────┐
│    Redis    │    │    SQLite    │
│  (быстро)   │    │ (постоянно)  │
│ rate limit  │    │   события    │
│ ip scores   │    │   пользов.   │
│ brute force │    │   история    │
└─────────────┘    └──────────────┘
```

### Стек технологий

| Компонент | Технология |
|-----------|-----------|
| Backend | Python 3.12, FastAPI |
| Middleware | Starlette BaseHTTPMiddleware |
| Кэш | Redis 7 |
| База данных | SQLite (aiosqlite) |
| Аутентификация | JWT (python-jose), bcrypt (passlib) |
| Мониторинг | Chart.js, WebSocket |
| Тестирование | pytest |
| Атаки (демо) | Python aiohttp, socket |

---

## Алгоритмы защиты

### 1. Token Bucket (Ограничение запросов)

Алгоритм Token Bucket контролирует частоту запросов. Каждый IP получает "ведро" токенов которое пополняется с постоянной скоростью.

**Формула пополнения:**
```
tokens = min(capacity, tokens + elapsed × rate)
```

**Параметры:**
- `rate` = 30 запросов/минуту (general), 5 запросов/минуту (login)
- `capacity` = burst_multiplier × rate
- `elapsed` = время с последнего запроса (секунды)

**Логика:** если `tokens >= 1` → разрешить и `tokens -= 1`, иначе → 429.

---

### 2. Sliding Window Counter

Дополняет Token Bucket точным подсчётом запросов в скользящем окне.

**Реализация через Redis Sorted Set:**
```
ZREMRANGEBYSCORE key 0 (now - window)   # удаляем старые
ZADD key now:id now                      # добавляем текущий
ZCARD key                                # считаем в окне
```

Преимущество перед Fixed Window: нет эффекта "двойного лимита" на границе окон.

---

### 3. EMA Baseline (Адаптивный множитель)

Система обучается нормальному трафику и автоматически ужесточает лимиты при атаке.

**Формула EMA:**
```
baseline_new = α × current_rps + (1 - α) × baseline_old
```

где `α = 0.1` — коэффициент сглаживания.

**Адаптивный множитель:**
```
если current_rps > baseline × burst_multiplier:
    effective_limit = max(0.2, 1.0 / (ratio / burst_multiplier)) × base_limit
иначе:
    effective_limit = base_limit
```

При атаке (ratio = 10×): `effective_limit = 0.2 × base_limit` — лимит ужесточается в 5 раз.

---

### 4. Z-score Anomaly Detection

Статистический метод обнаружения аномального трафика.

**Формула Z-score:**
```
z = (x - μ) / σ
```

где:
- `x` = количество запросов от IP за текущий период
- `μ` = среднее по всем IP
- `σ` = стандартное отклонение

**Порог:** `z > 2.5σ` = аномалия (потенциальный DDoS).

Дополнительно проверяется:
- **Path concentration** > 0.8 — IP атакует один endpoint
- **Timing regularity** > 0.9 — слишком регулярные интервалы (бот)
- **Global traffic spike** — резкий рост общего трафика

---

### 5. IP Reputation Scoring

Накопительная система оценки угрозы каждого IP.

**Штрафные очки:**
| Тип нарушения | Штраф |
|--------------|-------|
| Rate limit | +10 |
| Anomaly | +15 |
| DDoS pattern | +25 |
| Brute Force | +35 |
| Suspicious fingerprint | +5 |

**Пороги действий:**
```
score >= 100 → BAN (403)
score >= 50  → CHALLENGE
score > 20   → WARN
score < 20   → ALLOW
```

**Exponential Decay (автоматический разбан):**
```
score_t = score_0 × decay_rate^(minutes_elapsed)
```

где `decay_rate = 0.95` — score снижается на 5% каждую минуту.

При `score < 0.1` → IP автоматически разбанивается.

---

### 6. Progressive Lockout (Brute Force защита)

Каждая последующая блокировка IP удваивает время бана.

```
lockout_n = min(base_lockout × 2^(n-1), 3600)
```

| Попытка | Длительность |
|---------|-------------|
| 1-я блокировка | 15 минут |
| 2-я блокировка | 30 минут |
| 3-я блокировка | 60 минут |
| 4+ блокировка | 60 минут (максимум) |

**Credential Stuffing Detection:**
Если с одного IP пробуются `>= 3` разных username → автоматическое обнаружение credential stuffing и немедленный бан.

---

### 7. Slowloris защита

Slowloris держит соединения открытыми, отправляя частичные HTTP заголовки.

**Два уровня защиты:**
1. **MAX_CONNECTIONS_PER_IP = 20** — если IP открыл > 20 соединений → 429
2. **REQUEST_TIMEOUT = 10s** — любой запрос дольше 10 сек → убивается (408)

Реализован через `asyncio.wait_for()`:
```python
response = await asyncio.wait_for(
    self._process_request(request, call_next, ip, path),
    timeout=10.0
)
```

---

## Установка и запуск

### Требования

- Python 3.12+
- Redis 7+
- Windows 10/11 или Linux

### Шаг 1 — Клонирование и установка

```bash
cd adaptive-shield
pip install -r requirements.txt
pip install aiosqlite==0.20.0
```

### Шаг 2 — Настройка окружения

Создайте файл `.env` в корне проекта:
```env
REDIS_URL=redis://localhost:6379/0
JWT_SECRET_KEY=ваш-секретный-ключ
TELEGRAM_BOT_TOKEN=  # опционально
TELEGRAM_CHAT_ID=    # опционально
```

### Шаг 3 — Запуск Redis

**Windows:**
```bash
redis-server
```

### Шаг 4 — Запуск сервера

```bash
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

### Шаг 5 — Открыть в браузере

| Страница | URL |
|----------|-----|
| Главная | http://localhost:8000/site/ |
| Вход | http://localhost:8000/site/login.html |
| Кабинет | http://localhost:8000/site/account.html |
| Dashboard | http://localhost:8000/dashboard |

### Тестовые аккаунты

| Логин | Пароль | Роль |
|-------|--------|------|
| admin | admin123 | Администратор |
| user | password | Пользователь |
| test | test123 | Пользователь |

---

## Структура проекта

```
adaptive-shield/
├── app/
│   ├── main.py                  # Точка входа, lifespan, фоновые задачи
│   ├── middleware/
│   │   └── shield.py            # Главный middleware защиты
│   ├── detectors/
│   │   ├── rate_limiter.py      # Token Bucket + Sliding Window + EMA
│   │   ├── ip_reputation.py     # IP Reputation Scoring с decay
│   │   ├── brute_force.py       # Progressive Lockout + Stuffing
│   │   ├── anomaly.py           # Z-score аномалий
│   │   └── fingerprint.py       # Fingerprinting клиентов
│   ├── core/
│   │   ├── auth.py              # JWT + bcrypt аутентификация
│   │   ├── database.py          # SQLite (события, пользователи)
│   │   ├── logger.py            # Логирование в Redis + SQLite
│   │   ├── report.py            # Генерация отчётов
│   │   └── alerts.py            # Telegram уведомления
│   ├── api/
│   │   └── routes.py            # API эндпоинты
│   └── dashboard/
│       └── templates/
│           ├── dashboard.html   # Dashboard мониторинга
│           └── site/
│               ├── index.html   # Главная страница
│               ├── login.html   # Страница входа
│               └── account.html # Личный кабинет
├── config/
│   └── settings.py              # Конфигурация системы
├── tests/
│   └── test_protection.py       # Unit тесты (39 тестов)
├── attacks/                     # Скрипты демонстрации атак (Kali Linux)
│   ├── ddos_demo.py             # HTTP Flood атака
│   ├── bruteforce_demo.py       # Brute Force атака
│   ├── slowloris_demo.py        # Slowloris атака
│   └── comparison_test.py       # Сравнительный тест
├── shield.db                    # SQLite база данных
├── .env                         # Переменные окружения
└── requirements.txt
```

---

## Демонстрация атак

Все скрипты запускаются с Kali Linux против Windows сервера.

### DDoS атака (HTTP Flood)

```bash
python3 ddos_demo.py
```

4 фазы: Normal → Ramp Up → Flood (500 RPS) → Recovery

**Результат:** 79.9% запросов заблокировано

### Brute Force атака

```bash
python3 bruteforce_demo.py
```

3 фазы: Dictionary Attack → Credential Stuffing → Slow Brute Force

**Результат:** 100% попыток заблокировано

### Slowloris атака

```bash
python3 slowloris_demo.py
```

25 медленных соединений — Shield убивает через REQUEST_TIMEOUT

### Сравнительный тест

```bash
python3 comparison_test.py
```

Автоматически сравнивает Adaptive Shield vs nginx vs fail2ban

---

## Результаты тестирования

### Unit тесты

```bash
pytest tests/test_protection.py -v
```

**Результат: 39/39 тестов пройдено**

| Алгоритм | Тестов | Статус |
|----------|--------|--------|
| Token Bucket | 7 | ✅ |
| EMA Baseline | 7 | ✅ |
| Progressive Lockout | 10 | ✅ |
| IP Reputation | 10 | ✅ |
| Sliding Window | 5 | ✅ |

### Результаты реальных атак

| Тип атаки | Запросов | Заблокировано | Block Rate |
|-----------|----------|---------------|------------|
| DDoS HTTP Flood | 6091 | 4866 | **79.9%** |
| Brute Force | 30 | 30 | **100%** |
| Credential Stuffing | 20 | 20 | **100%** |

---

## Сравнение с аналогами

| Функция | nginx | fail2ban | **Adaptive Shield** |
|---------|-------|----------|---------------------|
| DDoS блокировка | ~60% | 0% | **~80%** |
| Brute Force | ~40% | ~80% | **100%** |
| Credential Stuffing | ❌ | ❌ | **✅** |
| Slowloris защита | ✅ (config) | ❌ | **✅** |
| Адаптивные лимиты | ❌ | ❌ | **✅ (EMA)** |
| Скорость обнаружения | 0ms (static) | ~10000ms | **~50ms** |
| IP Reputation | ❌ | частично | **✅** |
| Real-time Dashboard | ❌ | ❌ | **✅** |
| Telegram алерты | ❌ | email | **✅** |
| Автоматический разбан | ❌ | частично | **✅ (decay)** |

---

## API документация

### Аутентификация

```
POST /api/login
Body: {"username": "admin", "password": "admin123"}
Response: {"token": "jwt...", "role": "admin"}

POST /api/logout
POST /api/register  (только admin)
GET  /api/me
```

### Dashboard API

```
GET /dashboard/api/status          # Текущие метрики
GET /dashboard/api/events          # Последние события (Redis)
GET /dashboard/api/reputation      # Список подозрительных IP
GET /dashboard/api/db/summary      # Сводка из SQLite
GET /dashboard/api/db/events       # История событий из SQLite
GET /dashboard/api/export/csv      # Экспорт событий CSV
GET /dashboard/api/export/json     # Экспорт отчёта JSON
GET /dashboard/api/export/txt      # Экспорт отчёта TXT
POST /dashboard/api/whitelist/{ip} # Добавить IP в whitelist
DELETE /dashboard/api/whitelist/{ip} # Удалить из whitelist
```

---

## Технические характеристики

| Параметр | Значение |
|----------|---------|
| Время обнаружения DDoS | ~50ms |
| Время блокировки IP | < 1ms (Redis) |
| Лимит запросов (general) | 30/мин |
| Лимит входов (login) | 5/мин |
| Порог бана (score) | 100 |
| Decay rate | 0.95/мин |
| Slowloris таймаут | 10 сек |
| Макс. соединений/IP | 20 |
| Z-score порог | 2.5σ |
| Прогрессивный бан | 15→30→60 мин |
