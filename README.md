# Adaptive Shield

**Дипломдық жоба** · Ақпараттық технологиялар кафедрасы  
Тақырып: *Веб-ресурстарды DDoS және Brute Force шабуылдарынан қорғау жүйесін әзірлеу: әдістері және практикалық іске асыру*

---

## Жоба туралы

Adaptive Shield — FastAPI үшін middleware-қорғаныс жүйесі. Желілік шабуылдарды қосымшаға жеткенге дейін анықтап блокировкалайды. L7 (HTTP) деңгейінде жұмыс істейді және қосымша кодын өзгертуді қажет етпейді.

**Мүмкіндіктері:**
- HTTP Flood, Slowloris, Brute Force және Credential Stuffing шабуылдарын блокировкалайды
- EMA алгоритмі арқылы қалыпты трафикті өздігінен үйренеді
- Әр IP-дің репутациясын автоматты разбанмен бірге жүргізеді
- Шабуылдарды Dashboard-та нақты уақытта көрсетеді
- Қауіп анықталғанда Telegram-хабарлама жібереді

---

## Архитектура

```
Кіріс сұраным
       │
       ▼
┌──────────────────────────────────────┐
│          Shield Middleware           │
│                                      │
│  1. Нақты IP-ді анықтау             │
│  2. Bot Detection (User-Agent)       │
│  3. Scanner Path Detection           │
│  4. Slowloris қорғанысы             │
│  5. IP Reputation тексеру           │
│  6. Rate Limiting (EMA)             │
│  7. Anomaly Detection (Z-score)     │
│  8. Brute Force Guard               │
│                                      │
└──────────────────────────────────────┘
       │
       ▼
  200 OK / 403 Banned / 429 Limited
       │
  ┌────┴────┐
  │  Redis  │  ←  счётчиктер, бандар, EMA (мс)
  │ SQLite  │  ←  оқиғалар, тарих, пайдаланушылар
  └─────────┘
```

---

## Қорғаныс алгоритмдері

### EMA Rate Limiting

Жүйе трафиктің қалыпты деңгейін үйренеді және шабуыл кезінде лимиттерді автоматты түрде қатайтады.

```
baseline_new = α × current_rps + (1 - α) × baseline_old   (α = 0.1)

егер current_rps > baseline × burst_multiplier болса:
    limit = max(0.2, 1 / ratio) × base_limit
```

### Z-score Аномалия детекциясы

```
z = (x - μ) / σ

z > 2.5σ  →  аномалия (ықтимал DDoS)
```

Қосымша тексерулер: path concentration > 0.8, timing regularity > 0.9.

### IP Репутация скорингі

| Бұзушылық | Айыппұл |
|-----------|---------|
| Rate limit | +10 |
| Аномалия | +15 |
| DDoS паттерні | +25 |
| Brute Force | +35 |

```
score >= 100  →  БАН (403)
score >= 50   →  CHALLENGE
score < 20    →  ALLOW

затухание: score_t = score_0 × 0.95^(өткен_минуттар)
```

### Прогрессивті блокировка

```
lockout_n = min(base_lockout × 2^(n-1), 3600)
```

| Әрекет | Ұзақтығы |
|--------|---------|
| 1-ші блокировка | 15 минут |
| 2-ші блокировка | 30 минут |
| 3-ші және одан артық | 60 минут |

Credential Stuffing: бір IP-дан 3+ әртүрлі username → дереу бан.

### Slowloris қорғанысы

```python
response = await asyncio.wait_for(
    self._process_request(request, call_next, ip, path),
    timeout=10.0  # 10 секундтан кейін байланысты үземіз
)
```

MAX_CONNECTIONS_PER_IP = 20

---

## Тестілеу нәтижелері

Тесттер Kali Linux-тан Windows-серверге қарсы жүргізілді.

| Шабуыл түрі | Сұраным | Блокталды | Пайыз |
|-------------|---------|-----------|-------|
| HTTP Flood (DDoS) | 6091 | 4866 | **79.9%** |
| Brute Force | 30 | 30 | **100%** |
| Credential Stuffing | 20 | 20 | **100%** |
| Slowloris | 25 байл. | 25 байл. | **100%** |

Unit-тесттер: **39/39 өтті**

---

## Аналогтармен салыстыру

| Функция | nginx | fail2ban | Adaptive Shield |
|---------|-------|----------|-----------------|
| DDoS блокировка | ~60% | 0% | **~80%** |
| Brute Force | ~40% | ~80% | **100%** |
| Credential Stuffing | ✗ | ✗ | **✓** |
| Slowloris | ✓ (config) | ✗ | **✓** |
| Адаптивті лимиттер | ✗ | ✗ | **✓ (EMA)** |
| Анықтау уақыты | 0мс (статик) | ~10000мс | **~50мс** |
| Нақты уақыт Dashboard | ✗ | ✗ | **✓** |
| Автоматты разбан | ✗ | ішінара | **✓ (decay)** |

---

## Орнату және іске қосу

### Талаптар

- Python 3.12+
- Redis 7+
- Windows 10/11 немесе Linux

### Іске қосу

```bash
# 1. Тәуелділіктерді орнату
pip install -r requirements.txt

# 2. .env файлын жасау
REDIS_URL=redis://localhost:6379/0
JWT_SECRET_KEY=кілт

# 3. Redis-ті іске қосу

# 4. Серверді іске қосу
uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### Беттер

| Бет | URL |
|-----|-----|
| Басты бет | http://localhost:8000/site/ |
| Кіру | http://localhost:8000/site/login.html |
| Dashboard | http://localhost:8000/dashboard |
| Пайдаланушылар | http://localhost:8000/admin |

### Тестілік аккаунттар

| Логин | Пароль | Рөл |
|-------|--------|-----|
| admin | admin123 | Әкімші |
| user | password | Пайдаланушы |
| test | test123 | Пайдаланушы |

---

## Шабуылдарды демонстрациялау

```bash
# Қалыпты трафик (baseline үшін)
python attacks/normal_traffic.py --rps 5 --duration 120

# DDoS — HTTP Flood
python attacks/ddos_simulator.py --mode flood --rps 100 --duration 30

# DDoS — Burst
python attacks/ddos_simulator.py --mode burst --duration 30

# DDoS — Distributed (әртүрлі IP-дан)
python attacks/ddos_simulator.py --mode distributed --ips 20 --duration 30

# Brute Force
python attacks/bruteforce_simulator.py --mode simple

# Credential Stuffing
python attacks/bruteforce_simulator.py --mode stuffing
```

---

## Жоба құрылымы

```
adaptive-shield/
├── app/
│   ├── main.py                   # Кіру нүктесі
│   ├── middleware/
│   │   └── shield.py             # Негізгі middleware
│   ├── detectors/
│   │   ├── rate_limiter.py       # Token Bucket + EMA
│   │   ├── ip_reputation.py      # IP Reputation + decay
│   │   ├── brute_force.py        # Прогрессивті блокировка
│   │   ├── anomaly.py            # Z-score
│   │   └── fingerprint.py        # Client fingerprinting
│   ├── core/
│   │   ├── auth.py               # JWT + bcrypt
│   │   ├── database.py           # SQLite
│   │   ├── logger.py             # Логирование
│   │   ├── report.py             # Есептер (PDF, CSV, JSON)
│   │   └── alerts.py             # Telegram
│   ├── api/
│   │   └── routes.py             # API эндпоинттер
│   └── dashboard/
│       └── templates/
│           ├── dashboard.html    # Мониторинг
│           ├── admin.html        # Пайдаланушыларды басқару
│           └── site/             # Публикалық сайт
├── attacks/                      # Демонстрация скрипттері
├── config/
│   └── settings.py               # Конфигурация
├── tests/
│   └── test_protection.py        # 39 unit-тест
├── docker-compose.yml
└── requirements.txt
```

---

## Технологиялар стегі

| Компонент | Технология |
|-----------|-----------|
| Backend | Python 3.12, FastAPI |
| Middleware | Starlette BaseHTTPMiddleware |
| Кэш | Redis 7 |
| Дерекқор | SQLite (aiosqlite) |
| Аутентификация | JWT (python-jose), bcrypt |
| Мониторинг | Chart.js |
| Тесттер | pytest |
| Контейнеризация | Docker Compose |

---

## API

```
POST /api/login                      # Авторизация
POST /api/logout                     # Шығу
POST /api/register                   # Тіркеу (admin)

GET  /dashboard/api/status           # Нақты уақыт метрикалары
GET  /dashboard/api/events           # Соңғы оқиғалар
GET  /dashboard/api/reputation       # Күдікті IP тізімі
GET  /dashboard/api/users            # Пайдаланушылар (admin)
POST /dashboard/api/users/{u}/role   # Рөлді өзгерту (admin)
GET  /dashboard/api/export/json      # Есеп экспорты
GET  /dashboard/api/export/csv       # Оқиғалар экспорты
```

---

*Дипломдық жоба · 2026*
