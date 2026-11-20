<div align="center">

<img src="assets/logo.svg" alt="Hydra Logo" width="100%" style="max-width: 100%; height: auto;">

# Hydra — High-Performance Rust Proxy Checker, Validator & Pool Engine

[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-0ea5e9.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-10b981.svg?style=flat-square)](LICENSE)
[![Tokio Runtime](https://img.shields.io/badge/async-tokio%201.43-0ea5e9.svg?style=flat-square&logo=tokio)](https://tokio.rs/)
[![Speed](https://img.shields.io/badge/speed-8%2C300%2B%20checks%2Fsec-10b981.svg?style=flat-square)](docs/BENCHMARK_RESULTS.ru.md)
[![Protocols](https://img.shields.io/badge/protocols-SOCKS5%20%7C%20SOCKS4%20%7C%20HTTP-64748b.svg?style=flat-square)](docs/API.ru.md)
[![Storage: libSQL](https://img.shields.io/badge/storage-libSQL%20WAL-0ea5e9.svg?style=flat-square)](hydra_api/README.md)
[![OpenAPI 3.0](https://img.shields.io/badge/OpenAPI-3.0%20%2F%20Swagger-10b981.svg?style=flat-square&logo=swagger)](docs/API.ru.md)
[![Tested Scale: 10M](https://img.shields.io/badge/tested%20scale-10M%20proxies-0ea5e9.svg?style=flat-square)](docs/BENCHMARK_RESULTS.ru.md)

<p align="center">
  <b>High-throughput, asynchronous proxy validation engine and streaming pool manager written in pure Rust.</b><br>
  Промышленный асинхронный движок на Rust для валидации, скоринга, классификации анонимности и потоковой маршрутизации десятков миллионов прокси в реальном времени.
</p>

[English](README.md) • [Русский](README.ru.md) • [简体中文](README.zh.md)

<br>

[⚡ Быстрый старт](#quick-start) • [✨ Возможности](#features) • [📊 Бенчмарки](#benchmarks) • [⚖️ Сравнение](#comparison) • [📐 Архитектура](#architecture) • [⚙️ Конфигурация](#configuration) • [📖 REST API](docs/API.ru.md)

</div>

---

> [!NOTE]
> **Для кого создана Hydra?** Проект устраняет падения по памяти при чеке сотен тысяч IP, исключает ошибки блокировки баз данных (`database locked`), нивелирует утечки TCP-дескрипторов (`TIME_WAIT`) и автоматически нормализует «сырые» прокси от сотен разношерстных поставщиков.

### 🎯 Три ключевых преимущества:

1. **Zero-Config инжест любых форматов (14 000+ прокси/сек)**: Прием «сырых» списков прокси без предварительной ручной очистки — распознает `ip:port`, `ip:port:user:pass`, `user:pass@ip:port`, URL-схемы, IPv6 (`[::1]:port`) и структурированный JSON. Система на лету отсекает Bogon/Private IP и выполняет каскадный автодетект рабочих протоколов (`SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP`).
2. **Гранулярные политики жизненного цикла (SLA для каждого пула)**: Индивидуальный контроль проверок через гибкие профили политик — раздельные тайм-ауты (L4 Connect, L7 Handshake, I/O), периодичность планового речека живых узлов, дифференцированный экспоненциальный карантинный бэкофф (`dead_backoff_mult_zero` / `dead_backoff_mult_active`) и раздельные лимиты ошибок (`max_dead_strikes_zero` / `max_dead_strikes_active`). Планировщик автоматически поддерживает базу в актуальном состоянии 24/7.
3. **Отдача живых прокси за 0.06 мс и 0 ошибок блокировки БД**: Кластеризованные таблицы и 8 специализированных B-Tree индексов в режиме SQLite WAL обеспечивают ультрабыструю фильтрацию по странам, ASN, протоколам и уровню анонимности. Архитектура MPSC микробатчинга (транзакционный сброс каждые 100 мс) гарантирует 100% стабильность транзакций даже при непрерывной параллельной нагрузке в 10 000 000 прокси.

---

## <a id="quick-start"></a>🚀 Быстрый старт (Quick Start Guide)

> [!IMPORTANT]
> **Системные требования:**
> * Компилятор **Rust >= 1.85** (поддержка редакции `Rust 2024`).
> * Утилита **Git**.

### 1. Клонирование и настройка окружения
```bash
git clone https://github.com/stormsia/hydra.git
cd hydra
cp .env.example .env
```

В файле `.env` задайте ваш мастер-ключ доступа к API:
```env
API_KEY=my_secure_hydra_key_12345
```

### 2. Сборка монорепозитория

#### Стандартная сборка:
```bash
cargo build --workspace --release
```

#### Максимальная производительность (с инструкциями AVX2/BMI2 процессора хоста):
```bash
# Linux / macOS (Bash):
RUSTFLAGS="-C target-cpu=native" cargo build --workspace --release
```
```powershell
# Windows (PowerShell):
$env:RUSTFLAGS="-C target-cpu=native"; cargo build --workspace --release
```
```cmd
REM Windows (CMD):
set RUSTFLAGS=-C target-cpu=native && cargo build --workspace --release
```

### 3. Запуск

> [!TIP]
> По умолчанию в конфигурации параметр `EMBED_JUDGE` равен `false`. Для быстрого локального запуска в режиме **All-In-One** (с встроенным judge-сервером проверки анонимности) передайте переменную окружения `EMBED_JUDGE=true` либо укажите `EMBED_JUDGE=true` в файле `.env`.

#### 🐧 Linux / macOS:
```bash
# Увеличение лимита файловых сокетов (критично для 5 000+ параллельных воркеров)
ulimit -n 65535

# Запуск в All-In-One режиме (встроенный эхо-сервер Judge на порту 8080):
EMBED_JUDGE=true ./target/release/hydra_api

# Фоновый запуск в продакшене (nohup):
nohup ./target/release/hydra_api > hydra_api.log 2>&1 &
```

#### 🪟 Windows (PowerShell):
```powershell
# Запуск в All-In-One режиме:
$env:EMBED_JUDGE="true"; .\target\release\hydra_api.exe
```

#### Автономный запуск выделенного L7 Judge (продакшен):
При развертывании в распределенном контуре судья запускается как отдельный сервис:
```bash
# Запуск автономного высоконагруженного эхо-сервера
./target/release/hydra_judge
```

После старта доступны интерфейсы:
* 📖 **Интерактивный Swagger UI:** [http://127.0.0.1:3000/swagger-ui](http://127.0.0.1:3000/swagger-ui)
* 📋 **Спецификация OpenAPI 3.0 (JSON):** [http://127.0.0.1:3000/api-docs/openapi.json](http://127.0.0.1:3000/api-docs/openapi.json)
* ⚡ **Телеметрия движка в реальном времени:**
  ```bash
  curl -H "X-API-Key: my_secure_hydra_key_12345" http://127.0.0.1:3000/api/v1/stats/engine
  ```

---

## <a id="features"></a>⚡ Возможности и архитектурные решения (Features & Benefits)

| Задача / Проблема | Как решает Hydra | Результат |
|---|---|---|
| **Разрозненные форматы от сотен поставщиков** | **Zero-Config парсер с автодетектом**: парсит `ip:port`, `ip:port:user:pass`, URL-нотацию, IPv6 и JSON | Нулевая ручная предобработка списков; инжест на скорости **14 000+ прокси/с** |
| **Неизвестные протоколы прокси** | **Каскадный протокольный автодетект**: `SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP` | Не нужно заранее знать тип прокси: движок определяет рабочий протокол автоматически |
| **Разные требования к пулам под разные задачи** | **Гранулярные политики жизненного цикла**: кастомные L4/L7 тайм-ауты, интервалы речека, окно стабильности | Каждому пулу/источнику назначается индивидуальная политика (Check Policy) |
| **Блокировки БД при пиковых нагрузках** | Неблокирующий **MPSC Micro-Batching (100 мс)** в режиме **SQLite WAL** | До **8 340 проверок/с** на запись и **14 000+ прокси/с** на импорт при **0 ошибок `database locked`** |
| **Утечки сокетов и исчерпание портов (`TIME_WAIT`)** | Прямое управление сокетами через **`SO_LINGER=0` (TCP RST drop)** | Нулевое накопление дескрипторов при 5 000+ параллельных воркерах |
| **Лишний трафик на неживых IP** | **4-фазный Fail-Fast конвейер**: L4 Connect &rarr; Handshake &rarr; TLS/Judge &rarr; Anonymity | Экономия до 95% сетевого трафика и дескрипторов (отсечение на этапе SYN) |
| **Отказ тестовых судей (Judge)** | **Динамический Failover Judge Pool** (выбор по `lowest_latency` / консенсус) | Бесшовное переключение на здоровых судей; динамическое определение публичного IP чекера консенсусом большинства |
| **Сканирование эхо-серверов ботами** | **Anti-Abuse Token Guard** + суточная скользящая ротация **HMAC-SHA256** | Неавторизованные сканеры (Shodan, Censys) сбрасываются мгновенным TCP RST |
| **Устаревание гео-баз** | **Lock-Free GeoIP/ASN на `ArcSwap`** с автообновлением по HTTP ETag | Базы MaxMind обновляются на лету без блокировок Tokio runtime и без рестарта |
| **Реакция на блокировки целевыми сайтами** | Контур обратной связи **`POST /api/v1/proxies/report-fail`** | Мгновенный перевод сбойных прокси в карантин `cooldown` с экспоненциальным бэкоффом |

---

## <a id="comparison"></a>⚖️ Сравнение с аналогами (Benchmark Comparison)

| Характеристика / Движок | **Hydra** | **[ProxyBroker](https://github.com/bluet/proxybroker2)** | **[proxypool](https://github.com/henson/proxypool)** | **[proxy-checker](https://www.npmjs.com/package/proxy-checker)** |
|---|:---:|:---:|:---:|:---:|
| **Язык разработки** | **Rust 2024 (Tokio 1.43)** | Python (asyncio) | Go (goroutines) | Node.js (JavaScript) |
| **Пропускная способность проверок** | **2 100 – 8 340+ пров/сек** | ~100 – 250 пров/сек | ~400 – 800 пров/сек | ~200 – 500 пров/сек |
| **Проверенная емкость базы** | **10 000 000+ прокси** | < 50 000 (утечки памяти) | < 200 000 (деградация Redis) | < 100 000 (деградация GC) |
| **Потребление RAM под нагрузкой** | **~92 MB RAM** | 400 – 900+ MB | 250 – 500 MB | 300 – 700 MB |
| **Предотвращение сокетов TIME_WAIT** | **Да (`SO_LINGER=0` TCP RST)** | Нет (дефолтные сокеты ОС) | Частично | Нет |
| **Слой персистентности** | **Встроенный libSQL/WAL (MPSC)** | SQLite (блокируется) | Внешний Redis | MongoDB / In-memory |
| **Гранулярные SLA-политики пулов** | **Да (индивидуальный речек)** | Нет (глобальные флаги) | Нет | Нет |
| **Анти-скан защита судьи (HMAC/RST)** | **Да (скользящее окно 24ч)** | Нет | Нет | Нет |
| **Каскадный автодетект протоколов** | **SOCKS5/4 &rarr; CONNECT &rarr; HTTP** | Ограниченный | Ограниченный | Ручной выбор |

---

## <a id="benchmarks"></a>📊 Бенчмарки производительности (10M Proxy Stress-Test & Latency)

Результаты стресс-тестирования при **5 000 параллельных воркерах** на базе в **10 000 000 прокси** (размер базы данных `hydra.db` — 3.57 GB).

> [!NOTE]
> Задержки API измерены **под 100% параллельной нагрузкой сетевого чекера** (5 000 воркеров непрерывно валидируют и записывают результаты). Внутренний SQL overhead поиска по кластеризованному B-Tree индексу составляет **0.06 мс** (по ID — **0.01 мс**).

| Метрика | Значение | Условия и контекст |
|---|:---:|---|
| **Импорт прокси через REST API** | **14 096 прокси/с** | Десериализация JSON, bogon-отсев, дедупликация и пакетная запись |
| **Устойчивая скорость непрерывного чека** | **2 111.5 проверок/с** | **~7.6 млн проверок/час** (380 725 проверок за 3 минуты) |
| **Пиковая скорость чека** | **8 340.0 проверок/с** | В моменты массового завершения TCP-сессий |
| **Потребление RAM под нагрузкой 5 000 воркеров** | **92.4 MB (avg) / 136.4 MB (peak)** | Нулевые утечки памяти на пуле в 10M записей |
| **Нагрузка на CPU (5 000 воркеров)** | **25.8% (avg) / 47.6% (peak)** | Равномерное распределение по пулу потоков Tokio |
| **Ошибки блокировки БД (`database locked`)** | **0 ошибок** | За счет транзакционного MPSC буфера (100 мс) |
| **Задержка API: выборка быстрых (`limit=50`)** | **~25.6 мс** | **Под 100% нагрузкой чекера** на 10M базе (сквозной HTTP RTT) |
| **Задержка API: выборка по гео (`country=US`)** | **~67.2 мс** | **Под 100% нагрузкой чекера** с сортировкой по RTT |
| **Телеметрия рантайма (`GET /api/v1/stats/engine`)** | **< 1.0 мс** | In-memory атомарные счетчики без обращения к диску |

> 🔬 Подробные протоколы замеров и методология: [docs/BENCHMARK_RESULTS.ru.md](docs/BENCHMARK_RESULTS.ru.md).

---

## 📦 Пакеты воркспейса

Репозиторий спроектирован как модульный Cargo-монорепозиторий:

```
Hydra Monorepo
├── hydra_api       — REST API (Axum), планировщик речека, MPSC батчер, хранилище libSQL, Swagger UI
├── hydra_checker   — Неблокирующее сетевое ядро проверок, протокольный стек, пул судей и фильтрация
└── hydra_judge     — Сверхбыстрый zero-framework L7 эхо-сервер с защитой от сканеров и HMAC-токенами
```

| Пакет | Назначение | Документация |
|---|---|:---:|
| **`hydra_api`** | Оркестрация жизненного цикла, REST API, Swagger UI, выборка прокси, фоновый планировщик | [README модуля](hydra_api/README.md) • [Спецификация API](docs/API.ru.md) |
| **`hydra_checker`** | Ядро сетевой валидации, каскадный автодетект, замер задержек и определение анонимности | [README модуля](hydra_checker/README.md) |
| **`hydra_judge`** | Высоконагруженный эхо-сервер зеркалирования заголовков и внешнего IP с защитой RST | [README модуля](hydra_judge/README.md) |

---

## <a id="architecture"></a>📐 Архитектура монорепозитория

```mermaid
flowchart LR
    classDef client fill:#1e293b,stroke:#0ea5e9,stroke-width:2px,color:#f8fafc;
    classDef api fill:#0f172a,stroke:#38bdf8,stroke-width:2px,color:#f8fafc;
    classDef checker fill:#064e3b,stroke:#10b981,stroke-width:2px,color:#f8fafc;
    classDef judge fill:#134e4a,stroke:#14b8a6,stroke-width:2px,color:#f8fafc;
    classDef storage fill:#312e81,stroke:#6366f1,stroke-width:2px,color:#f8fafc;

    subgraph Clients["Клиенты"]
        Scrapers["Скрейперы / Боты"]:::client
        SwaggerUI["Swagger UI / CLI"]:::client
    end

    subgraph API["hydra_api"]
        Auth["X-API-Key Guard"]:::api
        Endpoints["REST API (/api/v1)"]:::api
        Scheduler["Scheduler Daemon (1с)"]:::api
        BatchWriter["MPSC Writer (100мс)"]:::api
        Maintenance["DB Maintenance (1ч)"]:::api
    end

    subgraph Checker["hydra_checker"]
        PreFlight["Pre-flight Filter"]:::checker
        L4Probe["Phase 1: L4 TCP Probe"]:::checker
        Cascade["Phase 2: Protocol Cascade"]:::checker
        L7Probe["Phase 3: L7 Validation"]:::checker
        Verdict["Phase 4: Anonymity Verdict"]:::checker
        JudgePool["Judge Failover Pool"]:::checker
    end

    subgraph Judges["Эхо-судьи"]
        HydraJudge["hydra_judge (HMAC Guard)"]:::judge
        ExternalJudges["Внешние Fallback Судьи"]:::judge
    end

    subgraph Storage["Хранилище"]
        DB[("libSQL / SQLite WAL<br/>WITHOUT ROWID (8 индексов)")]:::storage
    end

    Scrapers --> Auth
    SwaggerUI --> Auth
    Auth --> Endpoints
    Endpoints -->|"Выборка живых (0.06 мс)"| DB

    Scheduler -->|"Запрос due-узлов"| DB
    Scheduler -->|"Делегирование проверки"| PreFlight

    PreFlight --> L4Probe --> Cascade --> L7Probe --> Verdict
    L7Probe --> JudgePool
    JudgePool -->|"Probe с токеном"| HydraJudge
    JudgePool -.->|"Авто-failover"| ExternalJudges

    Verdict -->|"Результат проверки"| BatchWriter
    BatchWriter -->|"BEGIN IMMEDIATE batch"| DB
    Maintenance -->|"Очистка и incremental_vacuum"| DB
```

> [!NOTE]
> **Пул судей и композитный детект анонимности**: На Фазе 4 уровень анонимности (Elite, Anonymous, Transparent) определяется по факту утечки реального IP в заголовках ответа (`REMOTE_ADDR`, `X-Forwarded-For`, `Via`). Если `CHECKER_REAL_IPS` / `CHECKER_REAL_IP` не задан, чекер динамически формирует композитную сетевую идентичность (`HostIdentity`): опрашивает локальные сетевые интерфейсы хоста (выявляя публичные IPv4, IPv6 и вычисляя `/64` подсети) и объединяет их с результатами фонового опроса судей (пробивая NAT и контейнеры). Это предотвращает ложные результаты при ротации временных IPv6 SLAAC Privacy адресов и при наличии нескольких аплинков/IPv4. Явное задание `CHECKER_REAL_IPS` или `CHECKER_REAL_IP` переопределяет автодетект.

---

## 🔄 Детерминированный жизненный цикл прокси

Управление состоянием узлов исключает потерю рабочих адресов и предотвращает бесконечные проверки мертвых узлов:

```mermaid
stateDiagram-v2
    [*] --> cold_queue: Импорт в систему (state=0, strikes=0)
    cold_queue --> alive: Первичная проверка успешна (state=1)
    cold_queue --> cooldown: Ошибка подключения (state=2, strikes=1)

    alive --> alive: Плановый речек успешен (recheck_alive_sec)
    alive --> cooldown: Ошибка речека ИЛИ POST /report-fail от клиента

    cooldown --> alive: Карантинный речек успешен (strikes=0)
    cooldown --> cooldown: Повторная ошибка (strikes < strike_limit)
    cooldown --> dead_permanent: Лимит ошибок исчерпан (state=3)

    dead_permanent --> cold_queue: Повторный импорт (revive_dead=true)
    dead_permanent --> [*]: Физическое удаление фоновым демоном (>30 дней)
```

> [!NOTE]
> Подробная формула экспоненциального бэкоффа и параметры политик речека описаны в [Спецификации политик CheckPolicyDto](docs/API.ru.md#13-политика-сетевых-проверок-и-речека-checkpolicydto).

---

## 🔍 Быстрые примеры использования REST API

### 1. Пакетный импорт прокси (строки или объекты с кастомными политиками)
```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/import \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  -d '{
    "source": "datacenter_feed_1",
    "revive_dead": true,
    "proxies": [
      "socks5://alice:secret123@185.220.101.5:1080",
      "195.154.255.3:8080"
    ]
  }'
```

### 2. Выборка проверенных живых прокси по фильтрам (страна, протокол, анонимность)
```bash
curl -X GET "http://127.0.0.1:3000/api/v1/proxies?country=DE&anon=elite&protocol=socks5&limit=10" \
  -H "X-API-Key: my_secure_hydra_key_12345"
```

### 3. Отправка сигнала клиентского сбоя (экстренный перевод в карантин)
```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail \
  -H "Content-Type: application/json" \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  -d '{
    "ids": ["185.220.101.5:1080:alice:secret123"],
    "reason": "Target rate limited (HTTP 429)"
  }'
```

> 📖 Полный справочник всех 13 эндпоинтов, форматов запросов и ответов: [docs/API.ru.md](docs/API.ru.md).

---

## <a id="configuration"></a>⚙️ Конфигурация окружения (.env)

### Основные параметры

| Переменная | Тип | По умолчанию | Обязательно | Описание |
|---|:---:|:---:|:---:|---|
| `API_KEY` | `String` | *(отсутствует)* | **Да** | Секретный мастер-ключ заголовка `X-API-Key`. |
| `LISTEN_ADDR` | `SocketAddr` | `0.0.0.0:3000` | Нет | Адрес и порт API-сервера и веб-интерфейса Swagger UI. |
| `DB_PATH` | `String` | `./data/hydra.db` | Нет | Путь к файлу базы данных libSQL/SQLite (режим WAL). |
| `EMBED_JUDGE` | `bool` | `false` | Нет | Включение встроенного судьи Judge в процессе API (All-In-One режим). |
| `EMBED_JUDGE_PORT` | `u16` | `8080` | Нет | Порт встроенного сервера проверки анонимности. |
| `JUDGE_HTTP_URL` | `Url` | `http://127.0.0.1:8080` | Нет | HTTP URL судьи для проверки незашифрованных HTTP-прокси. |
| `JUDGE_HTTPS_URL` | `Url` | `http://127.0.0.1:8080` | Нет | HTTPS URL судьи для проверки туннелей CONNECT и SOCKS. |
| `JUDGE_SECRET_TOKEN` | `String` | `hydra_secret_token` | Нет | Статический проверочный токен верификации эхо-ответа. |
| `CHECKER_CONCURRENCY` | `usize` | `5000` | Нет | Лимит одновременно выполняемых параллельных сетевых проверок. |
| `CHECKER_REAL_IP` | `IpAddr` | *(авто: интерфейсы + судьи)* | Нет | Публичный IP хоста чекера для классификации Transparent прокси. Поддерживает `CHECKER_REAL_IPS` для нескольких IP и CIDR-подсетей (например `203.0.113.1,2001:db8::/64`); по умолчанию композитный автодетект (интерфейсы хоста + судьи). |
| `ENABLE_BUILTIN_JUDGE` | `bool` | *(auto)* | Нет | Включение встроенного судьи в пул проверок (true при EMBED_JUDGE или кастомном URL, иначе false). |
| `ENABLE_THIRD_PARTY_JUDGES` | `bool` | `true` | Нет | Включение пула внешних судей (Httpbingo, Httpbin) для failover. |
| `JUDGE_SELECTION_STRATEGY` | `String` | `lowest_latency` | Нет | Стратегия выбора судьи: `lowest_latency`, `priority`, `round_robin`. |
| `GEOIP_AUTO_UPDATE` | `bool` | `true` | Нет | Автоматическая загрузка и обновление баз MaxMind по HTTP ETag. |

<details>
<summary>👉 <b>Развернуть параметры расширенного тюнинга (тайм-ауты, GeoIP пути, ротация HMAC, планировщик)</b></summary>

| Переменная | Тип | По умолчанию | Описание |
|---|:---:|:---:|---|
| `GEOIP_COUNTRY_PATH` | `String` | `./geo/GeoLite2-Country.mmdb` | Путь к локальной базе стран MaxMind MMDB. |
| `GEOIP_ASN_PATH` | `String` | `./geo/GeoLite2-ASN.mmdb` | Путь к локальной базе автономных систем MaxMind MMDB. |
| `GEOIP_RELOAD_SECS` | `u64` | `3600` | Период автоматической перезагрузки файлов MMDB в память (сек). |
| `GEOIP_UPDATE_INTERVAL_SECS` | `u64` | `86400` | Интервал проверки свежих версий баз MaxMind по HTTP (сек). |
| `GEOIP_COUNTRY_URL` | `String` | *(jsdelivr mirror)* | HTTP URL для автозагрузки архива GeoLite2-Country.mmdb.gz. |
| `GEOIP_ASN_URL` | `String` | *(jsdelivr mirror)* | HTTP URL для автозагрузки архива GeoLite2-ASN.mmdb.gz. |
| `JUDGE_SECRET_KEY` | `String` | *(нет)* | HMAC-SHA256 ключ скользящей 24-часовой ротации токенов судьи. |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS`| `u64` | `30` | Интервал проверки доступности судей (в секундах). |
| `ADDITIONAL_JUDGES` | `String` | *(нет)* | Дополнительные пользовательские судьи (`HTTP_URL\|HTTPS_URL,...`). |
| `CHECKER_CONNECT_TIMEOUT_MS` | `u64` | `3000` | Таймаут на L4 TCP SYN подключение к сокету прокси (мс). |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | `u64` | `4000` | Таймаут на рукопожатие туннеля (SOCKS, HTTP CONNECT) (мс). |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | `u64` | `5000` | Таймаут на обмен данными с судьей через туннель (мс). |
| `CHECKER_MAX_READ_BYTES` | `usize` | `8192` | Максимальный объем читаемого ответа (защита от memory tarpit). |
| `CHECKER_LOCAL_BIND_IP` | `IpAddr` | *(нет)* | Привязка исходящих сокетов чекера к локальному IP интерфейса. |
| `SCHEDULER_BATCH_SIZE` | `usize` | `10000` | Число созревших прокси, выбираемых планировщиком в секунду. |
| `BATCH_FLUSH_INTERVAL_MS` | `u64` | `100` | Интервал транзакционного сброса буфера результатов MPSC в БД (мс). |
| `DEAD_PROXY_RETENTION_DAYS` | `u32` | `30` | Срок хранения мертвых узлов в днях до физического удаления. |
| `DB_MAINTENANCE_INTERVAL_SECS` | `u64` | `3600` | Период фонового обслуживания БД (`PRAGMA incremental_vacuum`). |
| `RUST_LOG` | `String` | `info` | Уровень детализации логов и трассировки (`tracing`). |

</details>

---

## 🛠️ Разработка и тестирование

```bash
# Запуск полного набора тестов монорепозитория
cargo test --workspace

# Тестирование отдельных модулей
cargo test -p hydra_checker
cargo test -p hydra_judge
cargo test -p hydra_api

# Проверка форматирования и статический анализ Clippy
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 🤝 Участие в разработке

Мы приветствуем Pull Request'ы, сообщения об ошибках и предложения по оптимизации сетевого стека!
Пожалуйста, ознакомьтесь с правилами в документе:
👉 **[Руководство контрибьютора (CONTRIBUTING.ru.md)](CONTRIBUTING.ru.md)**.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией **MIT License**. Подробности в файле [LICENSE](LICENSE).
