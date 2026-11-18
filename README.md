<p align="center">
  <img src="assets/logo.svg" alt="Hydra Logo" width="100%">
</p>

# Hydra — High-Performance Distributed Proxy Engine

[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-dea584.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Tokio Runtime](https://img.shields.io/badge/async-tokio%201.43-ff69b4.svg?style=flat-square&logo=tokio)](https://tokio.rs/)
[![OpenAPI 3.0](https://img.shields.io/badge/OpenAPI-3.0%20%2F%20Swagger-85EA2D.svg?style=flat-square&logo=swagger)](docs/API.md)
[![Storage: libSQL](https://img.shields.io/badge/storage-libSQL%20WAL-0052cc.svg?style=flat-square)](hydra_api/README.md)
[![Tested Scale: 10M](https://img.shields.io/badge/tested%20scale-10M%20proxies-success.svg?style=flat-square)](docs/BENCHMARK_RESULTS.md)

**Hydra** — промышленный асинхронный движок на Rust для валидации, скоринга, классификации анонимности и потоковой маршрутизации десятков миллионов прокси в режиме реального времени.

### 🎯 Три ключевых преимущества Hydra:
1. **Всеядный парсер форматов на входе**: Принимает любые списки прокси «как есть» без ручной подготовки — `ip:port`, `ip:port:user:pass`, `user:pass@ip:port`, `proto://user:pass@ip:port`, IPv6 `[::1]:port` и структурированный JSON со скоростью **14 000+ прокси в секунду**. Автоматически отсекает Bogon/Private IP, проводит каскадный автодетект протоколов (`SOCKS5` &rarr; `SOCKS4` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP`) и валидирует адреса.
2. **Автоматическое тестирование по гибким политикам (`CheckPolicyDto`)**: Полный контроль жизненного цикла каждого пула или отдельного прокси — индивидуальные тайм-ауты (Connect, Handshake, I/O), настраиваемые интервалы речека живых узлов, экспоненциальный карантинный бэкофф (`cooldown`) и пороги отсева мертвых узлов (`max_dead_strikes`). Планировщик сам распределяет проверки и поддерживает базу в актуальном состоянии 24/7.
3. **Высокоскоростная отдача и фильтрация без деградации БД**: Кластеризованные таблицы `WITHOUT ROWID` и 8 B-Tree индексов в режиме SQLite WAL выдают выборку живых узлов по стране, ASN, протоколу и анонимности за **0.06 мс** (по ID — за **0.01 мс**). Архитектура MPSC микробатчинга гарантирует **0 ошибок блокировки БД** и мгновенный ответ API даже при одновременной фоновой проверке пула из 10 000 000 прокси.

[Быстрый старт](#-быстрый-старт) • [Архитектура](#-архитектура-монорепозитория) • [Пакеты воркспейса](#-пакеты-воркспейса) • [Бенчмарки](#-производительность-на-базе-в-10-млн-записей) • [Конфигурация](#-конфигурация-окружения-env) • [Спецификация REST API](docs/API.md) • [Участие в разработке](CONTRIBUTING.md)

---

## ⚡ Почему Hydra? (Ключевые преимущества)

| Задача / Проблема | Как решает Hydra | Результат |
|---|---|---|
| **Разрозненные форматы прокси от разных поставщиков** | **Универсальный парсер с автодетектом**: строки `ip:port`, `ip:port:user:pass`, URL-нотация, IPv6 или JSON-объекты | Нулевая ручная предобработка списков; парсинг и инжестинг со скоростью **14 000+ прокси/с** |
| **Неизвестные протоколы прокси** | **Каскадный автодетект протоколов**: `SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP` | Не нужно заранее знать тип прокси: движок определяет рабочий протокол автоматически |
| **Разные требования к проверкам под разные задачи** | **Гибкие политики верификации (`CheckPolicyDto`)**: гранулярные тайм-ауты L4/L7, интервалы речека, окно стабильности | Каждому пулу/источнику можно задать свою политику (например, жесткий тайм-аут 1.5 с для быстрых прокси или мягкий для резидентских) |
| **Блокировки БД при высоких нагрузках** | Неблокирующий **MPSC Micro-Batching (100 мс)** в режиме **SQLite WAL** | До **8 340 проверок/с** на запись и **14 000+ прокси/с** на импорт при **0 ошибок `database locked`** |
| **Утечки сокетов и портов в `TIME_WAIT`** | Управление TCP сокетами через **`SO_LINGER=0` (TCP RST drop)** | Нулевое накопление дескрипторов при 5 000+ параллельных воркерах |
| **Лишний трафик на неживых IP** | **4-фазный Fail-Fast конвейер**: L4 Connect &rarr; Handshake &rarr; TLS/Judge &rarr; Anonymity | Экономия до 95% сетевого трафика и дескрипторов (отсечение на этапе SYN) |
| **Падение тестовых судей** | **Динамический Failover Judge Pool** (выбор по минимальной задержке `lowest_latency`) | При отказе основного судьи трафик за секунды переключается на здоровый резерв |
| **Сканирование эхо-серверов ботами** | **Anti-Abuse Token Guard** + суточная скользящая ротация **HMAC-SHA256** | Неавторизованные сканеры (Shodan, Censys) сбрасываются мгновенным TCP RST |
| **Устаревание гео-баз** | **Lock-Free GeoIP/ASN на `ArcSwap`** с автообновлением по HTTP ETag | Базы MaxMind обновляются на лету без блокировок Tokio runtime и без рестарта |
| **Реакция на блокировки целевыми сайтами** | Контур обратной связи **`POST /api/v1/proxies/report-fail`** | Мгновенный перевод сбойных прокси в карантин `cooldown` с экспоненциальным бэкоффом |

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
| **`hydra_api`** | Оркестрация жизненного цикла, REST API, Swagger UI, выборка прокси, фоновый планировщик | [README модуля](hydra_api/README.md) • [Спецификация API](docs/API.md) |
| **`hydra_checker`** | Ядро сетевой валидации, каскадный автодетект, замер задержек и определение анонимности | [README модуля](hydra_checker/README.md) |
| **`hydra_judge`** | Высоконагруженный эхо-сервер зеркалирования заголовков и внешнего IP с защитой RST | [README модуля](hydra_judge/README.md) |

---

## 📐 Архитектура монорепозитория

```mermaid
flowchart TD
    subgraph Clients["Клиенты и интеграции"]
        Scrapers["Парсеры / Боты / Скрейперы"]
        WebAdmin["Браузер / Swagger UI (:3000/swagger-ui)"]
    end

    subgraph Workspace["Hydra Core Engine"]
        subgraph HydraAPI["Пакет: hydra_api"]
            AuthMiddle["X-API-Key Middleware"]
            HttpRoutes["Axum REST Endpoints (/api/v1)"]
            Scheduler["Scheduler Daemon (1 сек)"]
            BatchWriter["MPSC Batch Writer (100 мс)"]
            Maintenance["DB Maintenance (1 час)"]
            GeoIP["MaxMind GeoIP Resolver (ArcSwap)"]
        end

        subgraph HydraChecker["Пакет: hydra_checker"]
            PreFlight["Pre-flight Bogon & Private IP Filter"]
            L4Probe["Phase 1: L4 TCP SYN Probe (SO_LINGER=0)"]
            Cascade["Phase 2: Protocol Cascade (SOCKS5/4/CONNECT)"]
            L7Probe["Phase 3: TLS & L7 Echo Validation"]
            Verdict["Phase 4: Anonymity Verdict (Elite/Anon/Trans)"]
            JudgePool["Judge Pool (Leader + Health Checks + Failover)"]
        end

        subgraph HydraJudge["Пакет: hydra_judge"]
            RawListener["Raw TcpListener (httparse, zero-framework)"]
            TokenGuard["Token Guard (HMAC-SHA256 sliding window)"]
            AntiScanner["Anti-Scanner RST Drop (drop_rst)"]
            EchoFormat["Formatters (AZenv text / HTTPBin JSON)"]
        end

        subgraph Storage["Слой персистентности: libSQL / SQLite (WAL)"]
            DB[("hydra.db (WAL Mode)<br/>Таблицы WITHOUT ROWID<br/>8 оптимизированных B-Tree индексов")]
        end
    end

    subgraph ExtJudges["Внешние Fallback Судьи"]
        FallbackJ["httpbingo.org / httpbun.com / httpbin.org"]
    end

    Scrapers -->|"REST API + X-API-Key"| AuthMiddle
    WebAdmin -->|"Swagger UI / Telemetry"| AuthMiddle
    AuthMiddle --> HttpRoutes
    HttpRoutes -->|"Выборка живых прокси"| DB

    Scheduler -->|"Запрос due-прокси (индекс idx_scheduler_prio)"| DB
    Scheduler -->|"Делегирование проверки"| HydraChecker

    PreFlight --> L4Probe
    L4Probe --> Cascade
    Cascade --> L7Probe
    L7Probe --> Verdict
    L7Probe --> JudgePool
    JudgePool -->|"L7 Probe с токеном"| HydraJudge
    JudgePool -.->|"Авто-failover при деградации"| FallbackJ

    RawListener --> TokenGuard
    TokenGuard -->|"Невалидный токен"| AntiScanner
    TokenGuard -->|"Токен подтвержден"| EchoFormat

    Verdict -->|"Результат проверки"| BatchWriter
    BatchWriter -->|"Пакетный BEGIN IMMEDIATE UPDATE"| DB
    Maintenance -->|"Очистка dead_permanent и VACUUM"| DB
```

---

## 🔄 Детерминированный жизненный цикл прокси

Управление состоянием узлов исключает потерю рабочих адресов и бесконечные проверки мертвых узлов:

```mermaid
stateDiagram-v2
    [*] --> cold_queue: Импорт в систему (state=0, strikes=0)
    cold_queue --> alive: Первичная проверка успешна (state=1)
    cold_queue --> cooldown: Ошибка подключения (state=2, strikes=1)

    alive --> alive: Плановый речек успешен (recheck_alive_sec)
    alive --> cooldown: Ошибка речека ИЛИ POST /report-fail от клиента

    cooldown --> alive: Карантинный речек успешен (strikes=0)
    cooldown --> cooldown: Повторная ошибка (strikes < max_dead_strikes)
    cooldown --> dead_permanent: Лимит ошибок исчерпан (state=3)

    dead_permanent --> cold_queue: Повторный импорт (revive_dead=true)
    dead_permanent --> [*]: Физическое удаление фоновым демоном (>30 дней)
```

> Подробная формула экспоненциального бэкоффа и настройки политики речека описаны в [Спецификации политик CheckPolicyDto](docs/API.md#13-политика-сетевых-проверок-и-речека-checkpolicydto).

---

## 📊 Производительность на базе в 10 млн записей

Сводные результаты стресс-тестирования при **5 000 параллельных воркерах** на базе в **10 000 000 прокси** (размер `hydra.db` — 3.57 GB).

> 🔬 Полный отчет и условия тестирования: [docs/BENCHMARK_RESULTS.md](docs/BENCHMARK_RESULTS.md).

| Метрика | Значение | Условия и контекст |
|---|:---:|---|
| **Импорт прокси через REST API** | **14 096 прокси/с** | Десериализация JSON, bogon-отсев, дедупликация и запись |
| **Устойчивая скорость непрерывного чека** | **2 111.5 проверок/с** | **~7.6 млн проверок/час** (380 725 проверок за 3 минуты) |
| **Пиковая скорость чека** | **8 340.0 проверок/с** | В моменты массового завершения TCP-сессий |
| **Потребление RAM под нагрузкой 5 000 воркеров** | **92.4 MB (avg) / 136.4 MB (peak)** | Нулевые утечки памяти на пуле в 10M записей |
| **Нагрузка на CPU (5 000 воркеров)** | **25.8% (avg) / 47.6% (peak)** | Равномерное распределение по пулу потоков Tokio |
| **Ошибки блокировки БД (`database locked`)** | **0 ошибок** | За счет транзакционного MPSC буфера (100 мс) |
| **Задержка API: выборка быстрых (`limit=50`)** | **~25.6 мс** | **Под 100% нагрузкой чекера** на 10M базе |
| **Задержка API: выборка по гео (`country=US`)** | **~67.2 мс** | **Под 100% нагрузкой чекера** с сортировкой по пингу |
| **Телеметрия рантайма (`GET /api/v1/stats/engine`)** | **< 1.0 мс** | In-memory атомарные счетчики без обращения к диску |

---

## 🚀 Быстрый старт

### 1. Клонирование и настройка окружения
```bash
git clone https://github.com/stormsia/hydra.git
cd hydra
cp .env.example .env
```

В файле `.env` укажите ваш секретный ключ авторизации:
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
RUSTFLAGS="-C target-cpu=native" cargo build --workspace --release
```

### 3. Запуск

#### 🐧 Linux / macOS:
```bash
# Увеличение системного лимита файловых дескрипторов (критично для 5 000+ воркеров)
ulimit -n 65535

# Запуск API-сервера (по умолчанию с EMBED_JUDGE=true в All-In-One режиме)
./target/release/hydra_api

# Фоновый запуск в продакшене (nohup)
nohup ./target/release/hydra_api > hydra_api.log 2>&1 &
```

#### 🪟 Windows (PowerShell / CMD):
```powershell
.\target\release\hydra_api.exe
```

> **Для быстрой локальной отладки без ручного билда:**
> ```bash
> cargo run -p hydra_api --release
> ```

После запуска доступны интерфейсы:
- 📖 **Интерактивный Swagger UI:** [http://127.0.0.1:3000/swagger-ui](http://127.0.0.1:3000/swagger-ui)
- 📋 **Спецификация OpenAPI 3.0 (JSON):** [http://127.0.0.1:3000/api-docs/openapi.json](http://127.0.0.1:3000/api-docs/openapi.json)
- ⚡ **Телеметрия движка в реальном времени:**
  ```bash
  curl -H "X-API-Key: my_secure_hydra_key_12345" http://127.0.0.1:3000/api/v1/stats/engine
  ```

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

> 📖 Полный справочник всех 13 эндпоинтов, форматов запросов и ответов: [docs/API.md](docs/API.md).

---

## ⚙️ Конфигурация окружения (.env)

| Переменная | Тип | По умолчанию | Обязательно | Описание |
|---|:---:|:---:|:---:|---|
| `API_KEY` | `String` | *(отсутствует)* | **Да** | Секретный мастер-ключ заголовка `X-API-Key`. |
| `LISTEN_ADDR` | `SocketAddr` | `0.0.0.0:3000` | Нет | Адрес и порт API-сервера и веб-интерфейса Swagger. |
| `DB_PATH` | `String` | `./data/hydra.db` | Нет | Путь к файлу базы данных libSQL/SQLite (режим WAL). |
| `EMBED_JUDGE` | `bool` | `false` | Нет | Включение встроенного судьи Judge в процессе API (All-In-One). |
| `EMBED_JUDGE_PORT` | `u16` | `8080` | Нет | Порт встроенного сервера проверки анонимности. |
| `JUDGE_HTTP_URL` | `Url` | `http://127.0.0.1:8080` | Нет | HTTP URL судьи для проверки незашифрованных HTTP-прокси. |
| `JUDGE_HTTPS_URL` | `Url` | `http://127.0.0.1:8080` | Нет | HTTPS URL судьи для проверки туннелей CONNECT и SOCKS. |
| `JUDGE_SECRET_TOKEN` | `String` | `hydra_secret_token` | Нет | Статический проверочный токен верификации эхо-ответа. |
| `CHECKER_CONCURRENCY` | `usize` | `5000` | Нет | Лимит одновременно выполняемых параллельных проверок. |
| `CHECKER_REAL_IP` | `IpAddr` | *(нет)* | Нет | Публичный IP хоста чекера (для точного детекта Transparent прокси). |
| `ENABLE_THIRD_PARTY_JUDGES` | `bool` | `true` | Нет | Включение пула внешних судей (Httpbingo, Httpbin) для failover. |
| `JUDGE_SELECTION_STRATEGY` | `String` | `lowest_latency` | Нет | Стратегия выбора судьи: `lowest_latency`, `priority`, `round_robin`. |
| `GEOIP_AUTO_UPDATE` | `bool` | `true` | Нет | Автоматическая загрузка и обновление баз MaxMind по HTTP ETag. |

<details>
<summary>👉 <b>Развернуть параметры расширенного тюнинга (таймауты, ротация HMAC, планировщик)</b></summary>

| Переменная | Тип | По умолчанию | Описание |
|---|:---:|:---:|---|
| `JUDGE_SECRET_KEY` | `String` | *(нет)* | HMAC-SHA256 ключ скользящей 24-часовой ротации токенов. |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS`| `u64` | `30` | Интервал проверки доступности судей (в секундах). |
| `ADDITIONAL_JUDGES` | `String` | *(нет)* | Дополнительные пользовательские судьи (`HTTP_URL\|HTTPS_URL,...`). |
| `CHECKER_CONNECT_TIMEOUT_MS` | `u64` | `3000` | Таймаут на L4 TCP SYN подключение к прокси (мс). |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | `u64` | `4000` | Таймаут на рукопожатие туннеля (SOCKS, HTTP CONNECT) (мс). |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | `u64` | `5000` | Таймаут на обмен данными с судьей через туннель (мс). |
| `CHECKER_MAX_READ_BYTES` | `usize` | `8192` | Максимальный объем читаемого ответа (защита от memory tarpit). |
| `CHECKER_LOCAL_BIND_IP` | `IpAddr` | *(нет)* | Привязка исходящих сокетов чекера к локальному IP интерфейса. |
| `SCHEDULER_BATCH_SIZE` | `usize` | `10000` | Число созревших прокси, выбираемых планировщиком в секунду. |
| `BATCH_FLUSH_INTERVAL_MS` | `u64` | `100` | Интервал транзакционного сброса буфера результатов MPSC в БД (мс). |
| `DEAD_PROXY_RETENTION_DAYS` | `u32` | `30` | Срок хранения мертвых узлов в днях до физического удаления. |
| `DB_MAINTENANCE_INTERVAL_SECS` | `u64` | `3600` | Период фоновой дефрагментации и оптимизации БД (`PRAGMA optimize`). |
| `RUST_LOG` | `String` | `info` | Уровень детализации логов и трассировки (`tracing`). |

</details>

---

## 🛠️ Разработка и тестирование

```bash
# Запуск всех тестов монорепозитория
cargo test --workspace

# Тестирование отдельных модулей
cargo test -p hydra_checker
cargo test -p hydra_judge
cargo test -p hydra_api

# Проверка форматирования и линтер Clippy
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
```

---

## 🤝 Участие в разработке

Мы приветствуем Pull Request'ы, сообщения об ошибках и предложения по оптимизации сетевого стека!
Пожалуйста, ознакомьтесь с правилами в документе:
👉 **[Руководство контрибьютора (CONTRIBUTING.md)](CONTRIBUTING.md)**.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией **MIT License**. Подробности в файле [LICENSE](LICENSE).
