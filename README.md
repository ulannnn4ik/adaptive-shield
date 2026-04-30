# 🛡️ Adaptive Shield — DDoS & Brute Force Protection System

> Дипломный проект: "Разработка системы защиты веб-ресурсов от DDoS и Brute Force атак"

## Архитектура

```
Request → Fingerprinter → Rate Limiter → Anomaly Detector → Decision Engine → Response
                              ↕               ↕                    ↕
                           Redis           IP Reputation      Telegram Alerts
```

### Компоненты

| Компонент | Назначение | Алгоритм |
|-----------|-----------|----------|
| Client Fingerprinter | Идентификация клиента beyond IP | Hash(UA + Headers + Accept + Order) |
| Adaptive Rate Limiter | Динамические лимиты | Sliding Window + EMA baseline |
| Anomaly Detector | Статистический анализ | Z-score + timing regularity + path concentration |
| IP Reputation Engine | Кумулятивный threat score | Exponential decay scoring |
| Brute Force Guard | Защита аутентификации | Progressive lockout + credential stuffing detection |
| Dashboard | Визуализация в реальном времени | Chart.js + Redis Streams |
| Alert System | Уведомления | Telegram Bot API |

## Быстрый старт

### С Docker (рекомендуется)

```bash
# Клонировать проект
cd adaptive-shield

# Запустить
docker-compose up -d

# Открыть
# App:       http://localhost:8000/api/
# Dashboard: http://localhost:8000/dashboard
# Docs:      http://localhost:8000/docs
```

### Без Docker

```bash
# 1. Установить Redis и запустить его
# 2. Установить зависимости
pip install -r requirements.txt

# 3. Запустить
uvicorn app.main:app --reload --port 8000
```

## Демонстрация (для защиты диплома)

### Полная автоматическая демонстрация

```bash
# Терминал 1: Запустить приложение
docker-compose up

# Терминал 2: Открыть dashboard в браузере
# http://localhost:8000/dashboard

# Терминал 3: Запустить демо-сценарий
python attacks/demo_scenario.py
```

### Ручное тестирование

```bash
# 1. Сначала создать baseline нормальным трафиком (2 минуты)
python attacks/normal_traffic.py --rps 5 --duration 120

# 2. DDoS-атака (HTTP Flood)
python attacks/ddos_simulator.py --mode flood --rps 200 --duration 30

# 3. DDoS-атака (Burst)
python attacks/ddos_simulator.py --mode burst --duration 30

# 4. Brute Force (простой)
python attacks/bruteforce_simulator.py --mode simple

# 5. Brute Force (credential stuffing)
python attacks/bruteforce_simulator.py --mode stuffing

# 6. Нормальный трафик после атаки (проверка false positives)
python attacks/normal_traffic.py --rps 3 --duration 60
```

## Метрики эффективности

| Метрика | Описание | Как измерять |
|---------|----------|-------------|
| Block Rate | % заблокированных вредоносных запросов | `blocked / attack_total * 100` |
| False Positive Rate | % заблокированных легитимных запросов | `normal_blocked / normal_total * 100` |
| Response Time (P99) | Задержка обработки запроса | Логи middleware |
| Recovery Time | Время возврата к нормальному режиму | Dashboard timeseries |
| Detection Time | Время до первого блока атаки | Redis event stream |

## Настройка Telegram-уведомлений

1. Создать бота через @BotFather в Telegram
2. Получить chat_id через @userinfobot
3. Создать файл `.env`:

```env
TELEGRAM_BOT_TOKEN=1234567890:ABCdefGHIjklMNOpqrsTUVwxyz
TELEGRAM_CHAT_ID=123456789
```

## Структура проекта

```
adaptive-shield/
├── app/
│   ├── main.py              # FastAPI app entry point
│   ├── middleware/
│   │   └── shield.py        # Main Shield middleware (orchestrator)
│   ├── detectors/
│   │   ├── fingerprint.py   # Client fingerprinting
│   │   ├── rate_limiter.py  # Adaptive rate limiter
│   │   ├── ip_reputation.py # IP reputation engine
│   │   ├── anomaly.py       # Anomaly detection
│   │   └── brute_force.py   # Brute force guard
│   ├── core/
│   │   ├── __init__.py      # Redis connection
│   │   ├── logger.py        # Event logging + metrics
│   │   └── alerts.py        # Telegram alerts
│   ├── api/
│   │   └── routes.py        # App + Dashboard API routes
│   ├── models/
│   │   └── __init__.py      # Pydantic models
│   └── dashboard/
│       └── templates/
│           └── dashboard.html # Real-time monitoring UI
├── attacks/
│   ├── ddos_simulator.py     # DDoS attack scripts
│   ├── bruteforce_simulator.py # Brute force scripts
│   ├── normal_traffic.py     # Baseline traffic generator
│   └── demo_scenario.py      # Full demo for defense
├── config/
│   └── settings.py           # All configuration
├── tests/
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```

## Уникальные фишки проекта

1. **Адаптивные лимиты** — система сама учит baseline и подстраивает пороги
2. **Client Fingerprinting** — идентификация beyond IP (header order, UA hash)
3. **Progressive Lockout** — каждый новый lockout удваивает время блокировки
4. **Credential Stuffing Detection** — отличает целевой brute force от credential stuffing
5. **Exponential Decay Scoring** — IP-репутация постепенно восстанавливается
6. **Real-time Dashboard** — визуализация атак с обновлением каждые 2 секунды
7. **Telegram Alerts** — мгновенные уведомления об атаках
8. **Anomaly Z-score** — статистическое обнаружение аномалий
9. **Timing Regularity Analysis** — детекция ботов по регулярности запросов

## Стек технологий

- **Python 3.11** + **FastAPI** — async web framework
- **Redis** — in-memory хранилище для counters, scores, streams
- **Docker Compose** — оркестрация сервисов
- **Chart.js** — визуализация на dashboard
- **structlog** — structured logging
- **numpy** — статистические расчёты для anomaly detection
