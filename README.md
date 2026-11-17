<p align="center">
  <img src="assets/logo.svg" alt="Hydra Logo" width="650">
</p>

# Hydra — High-Performance Distributed Proxy Engine

[![Rust 2024](https://img.shields.io/badge/rust-2024%20edition-dea584.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg?style=flat-square)](LICENSE)
[![Tokio Runtime](https://img.shields.io/badge/async-tokio%201.43-ff69b4.svg?style=flat-square&logo=tokio)](https://tokio.rs/)
[![OpenAPI 3.0](https://img.shields.io/badge/OpenAPI-3.0%20%2F%20Swagger-85EA2D.svg?style=flat-square&logo=swagger)](hydra_api/API.md)
[![Storage: libSQL](https://img.shields.io/badge/storage-libSQL%20WAL-0052cc.svg?style=flat-square)](hydra_api/README.md)
[![Checked Scale](https://img.shields.io/badge/tested%20scale-10M%20proxies-success.svg?style=flat-square)](BENCHMARK_RESULTS.md)

**Hydra** — это асинхронный распределенный движок промышленного уровня на языке Rust для непрерывной валидации, классификации анонимности, гео-скоринга и диспетчеризации миллионов прокси-серверов в секунду. Проект решает проблему стремительного устаревания и нестабильности прокси-пулов, автоматизируя обнаружение протоколов, карантин сбойных узлов и фильтрацию без деградации базы данных.

[Быстрый старт](#-быстрый-старт-zero-friction) • [Архитектура](#-системная-архитектура-и-пакеты-монорепозитория) • [Пакеты](#-структура-пакетов-workspace) • [Конфигурация](#-конфигурация-окружения-env) • [Бенчмарки](#-производительность-и-бенчмарки-10m-records) • [API Спецификация](hydra_api/API.md) • [Лицензия](#-лицензия)

---

## 🏛️ Архитектурные возможности (Feature &rarr; Benefit)

| Техническая особенность | Инженерное преимущество |
|---|---|
| **Асинхронный MPSC Micro-Batching (100 мс)** | Сохранение до 8 300+ результатов проверок в секунду и 14 000+ импортов без единой ошибки `database is locked` при базе в 10M записей. |
| **Fail-Fast 4-фазный сетевой конвейер** | Сброс нерабочих прокси на этапе L4 TCP SYN Connect экономит до 95% сетевого трафика и дескрипторов сокетов. |
| **Управление сокетами через `SO_LINGER=0`** | Мгновенный сброс TCP RST устраняет накопление портов в состоянии `TIME_WAIT` (0 утечек файловых дескрипторов при 5 000+ воркерах). |
| **Каскадный протокольный автодетект** | Автоматическая идентификация `SOCKS5` &rarr; `SOCKS4/4a` &rarr; `HTTP CONNECT` &rarr; `Plain HTTP` без предварительного указания типа прокси. |
| **Отказоустойчивый пул судей (Failover Judge Pool)** | Автоматическое переключение на 5 резервных внешних судей (Httpbingo, Httpbin и др.) по алгоритму `lowest_latency` при сбое основного сервера. |
| **Синхронизированные HMAC-SHA256 токены** | Скользящая 24-часовая UTC ротация токенов с окном мягкого перехода защищает эхо-сервер от интернет-сканеров (Shodan, Censys). |
| **Анти-сканер защита `drop_rst`** | Неавторизованные сетевые сканеры мгновенно сбрасываются через TCP RST без расхода CPU и памяти на генерацию HTTP 403 ответа. |
| **Lock-Free GeoIP/ASN на `ArcSwap`** | Фоновое автообновление баз MaxMind GeoLite2 по условным запросам HTTP ETag без остановки сервиса и без блокировки потоков. |

---

## 📦 Структура пакетов (Workspace)

Репозиторий организован как Cargo-монорепозиторий, разделенный на независимые функциональные слои:

| Пакет | Директория | Роль и назначение | Документация |
|---|---|---|:---:|
| **`hydra_api`** | [`hydra_api`](hydra_api/README.md) | REST API сервер на Axum, планировщик задач, MPSC буфер записи, хранилище SQLite/libSQL WAL, Swagger UI. | [README](hydra_api/README.md) • [API.md](hydra_api/API.md) |
| **`hydra_checker`** | [`hydra_checker`](hydra_checker/README.md) | Автономное неблокирующее ядро сетевых проверок (L4 TCP, Handshake, TLS, L7 Judge, Bogon-фильтрация). | [README](hydra_checker/README.md) |
| **`hydra_judge`** | [`hydra_judge`](hydra_judge/README.md) | Высоконагруженный zero-framework L7 эхо-сервер для зеркалирования заголовков и классификации анонимности. | [README](hydra_judge/README.md) |

---

## 📐 Системная архитектура и пакеты монорепозитория

```mermaid
flowchart TD
    subgraph Clients["Клиенты и Внешние Потребители"]
        Scrapers["Скрейперы / Боты / Прокси-Шлюзы"]
        WebAdmin["Инженер / Браузер / Swagger UI"]
    end

    subgraph Workspace["Hydra Monorepo Architecture"]
        subgraph HydraAPI["Пакет: hydra_api (Port 3000)"]
            AuthMiddle["X-API-Key Middleware"]
            HttpRoutes["Axum REST Endpoints (/api/v1)"]
            Scheduler["Scheduler Daemon (1 сек)"]
            BatchWriter["MPSC Batch Writer (100 мс)"]
            Maintenance["DB Maintenance (1 час)"]
            GeoIP["MaxMind GeoIP Reader (ArcSwap)"]
        end

        subgraph HydraChecker["Пакет: hydra_checker (Core Engine)"]
            PreFlight["Pre-flight Bogon / Private IP Filter"]
            L4Probe["Phase 1: L4 TCP SYN Probe (SO_LINGER=0)"]
            Cascade["Phase 2: Protocol Cascade (SOCKS5/4/CONNECT)"]
            L7Probe["Phase 3: TLS & L7 Echo Validation"]
            Verdict["Phase 4: Anonymity Verdict (Elite/Anon/Trans)"]
            JudgePool["Judge Pool (Leader + Health Checks + Failover)"]
        end

        subgraph HydraJudge["Пакет: hydra_judge (Port 8080/8443)"]
            RawListener["Raw TcpListener (Zero-Framework, httparse)"]
            TokenGuard["Token Guard (HMAC-SHA256 sliding window)"]
            AntiScanner["Anti-Scanner RST Drop (drop_rst / SO_LINGER=0)"]
            EchoFormat["Formatters (AZenv text / HTTPBin JSON)"]
        end

        subgraph Storage["Слой хранения: libSQL / SQLite (WAL)"]
            DB[("hydra.db (WAL Mode)<br/>Таблицы WITHOUT ROWID<br/>8 частичных B-Tree индексов")]
        end
    end

    subgraph ExtJudges["Внешние Fallback Судьи"]
        FallbackJ["httpbingo.org / httpbun.com / httpbin.org"]
    end

    Scrapers -->|"REST API + X-API-Key"| AuthMiddle
    WebAdmin -->|"Swagger UI / Telemetry"| AuthMiddle
    AuthMiddle --> HttpRoutes
    HttpRoutes -->|"Выборка живых прокси"| DB

    Scheduler -->|"Запрос due-прокси (idx_scheduler_prio)"| DB
    Scheduler -->|"Делегирование проверки"| HydraChecker

    PreFlight --> L4Probe
    L4Probe --> Cascade
    Cascade --> L7Probe
    L7Probe --> Verdict
    L7Probe --> JudgePool
    JudgePool -->|"L7 Probe с токеном"| HydraJudge
    JudgePool -.->|"Авто-failover при сбое"| FallbackJ

    RawListener --> TokenGuard
    TokenGuard -->|"Токен невалиден"| AntiScanner
    TokenGuard -->|"Токен подтвержден"| EchoFormat

    Verdict -->|"Результат проверки"| BatchWriter
    BatchWriter -->|"BEGIN IMMEDIATE пакетный UPDATE"| DB
    Maintenance -->|"Очистка dead_permanent & VACUUM"| DB
```

---

## 🔄 Модель жизненного цикла прокси (State Machine)

Каждый прокси-сервер в системе проходит детерминированный жизненный цикл:

```mermaid
stateDiagram-v2
    [*] --> cold_queue: Импорт в систему (state=0, strikes=0)
    cold_queue --> alive: Первичная проверка успешна (state=1)
    cold_queue --> cooldown: Ошибка подключения (state=2, strikes=1)

    alive --> alive: Речек успешен (интервал recheck_alive_sec)
    alive --> cooldown: Ошибка речека ИЛИ POST /report-fail от клиента

    cooldown --> alive: Карантинный речек успешен (strikes=0)
    cooldown --> cooldown: Повторная ошибка (strikes < max_dead_strikes)
    cooldown --> dead_permanent: Лимит ошибок исчерпан (state=3)

    dead_permanent --> cold_queue: Повторный импорт (revive_dead=true)
    dead_permanent --> [*]: Физическое удаление фоновым демоном (>30 дней)
```

---

## 📋 Системные требования (Prerequisites)

- **Компилятор Rust:** версия `>= 1.85.0` (с поддержкой редакции `Rust 2024`).
- **Операционная система:** Linux (рекомендуется для продакшена), Windows 10/11, macOS.
- **Инструменты сборки:** `cargo`, `git`.
- **База данных:** SQLite / libSQL (собирается встроенным компилятором C/Rust, внешняя СУБД не требуется).

---

## 🚀 Быстрый старт (Zero Friction)

### 1. Клонирование и настройка окружения
```bash
git clone https://github.com/your-org/hydra.git
cd hydra
cp .env.example .env
```

### 2. Сборка всего монорепозитория
```bash
# Стандартная оптимизированная сборка (LTO fat, opt-level 3, codegen-units 1, strip)
cargo build --workspace --release

# Максимальная производительность (с оптимизацией под микроархитектуру CPU хоста — AVX2/BMI2)
RUSTFLAGS="-C target-cpu=native" cargo build --workspace --release
```

### 3. Запуск скомпилированного сервиса

После сборки исполняемые бинарные файлы находятся в директории `target/release/`. Запускайте их из корня проекта, где расположен файл `.env`:

#### 🐧 Linux / macOS:
```bash
# Увеличение лимита открытых сокетов/файлов (критично для 5000+ воркеров)
ulimit -n 65535

# Запуск основного сервиса Hydra API (All-In-One или с внешним Judge)
./target/release/hydra_api

# Запуск автономного эхо-сервера Judge (на отдельном сервере)
./target/release/hydra_judge

```

#### 🪟 Windows (PowerShell / CMD):
```powershell
# Запуск основного сервиса Hydra API
.\target\release\hydra_api.exe

# Запуск автономного эхо-сервера Judge
.\target\release\hydra_judge.exe
```

> [!TIP]
> Для быстрой локальной отладки без предварительного ручного запуска бинарника также доступна команда:
> `cargo run -p hydra_api --release`

После старта доступны следующие интерфейсы:
- **Интерактивный Swagger UI:** [http://127.0.0.1:3000/swagger-ui](http://127.0.0.1:3000/swagger-ui)
- **Схема OpenAPI 3.0 (JSON):** [http://127.0.0.1:3000/api-docs/openapi.json](http://127.0.0.1:3000/api-docs/openapi.json)
- **Мгновенная in-memory телеметрия:** `curl -H "X-API-Key: hydra_super_secret_api_key_change_me_in_production" http://127.0.0.1:3000/api/v1/stats/engine`

---

## 🛠️ Рабочий процесс монорепозитория (Monorepo Workflow)

Для работы с отдельными компонентами монорепозитория используйте стандартные флаги фильтрации Cargo:

### Запуск тестов воркспейса
```bash
cargo test --workspace
```

### Запуск тестов отдельного пакета
```bash
cargo test -p hydra_checker
cargo test -p hydra_judge
cargo test -p hydra_api
```

### Проверка линтером и форматирование кода
```bash
cargo clippy --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
```

### Запуск автономного Judge сервера
```bash
cargo run -p hydra_judge --release
```

---

## ⚙️ Конфигурация окружения (.env)

Основные параметры конфигурации задаются в файле `.env` в корне рабочей директории:

| Переменная | Тип | По умолчанию | Обязательно | Описание |
|---|:---:|:---:|:---:|---|
| `API_KEY` | `String` | *(отсутствует)* | **Да** | Мастер-ключ для авторизации в REST API через заголовок `X-API-Key`. |
| `LISTEN_ADDR` | `SocketAddr` | `0.0.0.0:3000` | Нет | Сетевой адрес и TCP-порт API-сервера и Swagger UI. |
| `DB_PATH` | `Path` | `./data/hydra.db` | Нет | Путь к локальному файлу базы данных libSQL/SQLite (режим WAL). |
| `EMBED_JUDGE` | `bool` | `false` | Нет | Включение встроенного инстанса `hydra_judge` внутри процесса API (All-In-One). |
| `EMBED_JUDGE_PORT` | `u16` | `8080` | Нет | Порт встроенного judge-сервера. |
| `JUDGE_HTTP_URL` | `Url` | `http://127.0.0.1:8080` | Нет | HTTP URL судьи для валидации незашифрованных HTTP-прокси. |
| `JUDGE_HTTPS_URL` | `Url` | `http://127.0.0.1:8080` | Нет | HTTPS URL судьи для валидации туннелей CONNECT и SOCKS4/5. |
| `JUDGE_SECRET_TOKEN` | `String` | `hydra_secret_token` | Нет | Секретный статический токен для валидации ответа эхо-сервера. |
| `CHECKER_CONCURRENCY` | `usize` | `5000` | Нет | Лимит одновременно выполняемых параллельных проверок сетевым ядром. |
| `CHECKER_REAL_IP` | `IpAddr` | *(нет)* | Нет | Реальный внешний IP чекера (для точной классификации Transparent прокси и anti-self-scan). |
| `ENABLE_THIRD_PARTY_JUDGES` | `bool` | `true` | Нет | Использование пула внешних судей (httpbingo, httpbun, httpbin) при сбоях. |
| `JUDGE_SELECTION_STRATEGY` | `String` | `lowest_latency` | Нет | Стратегия выбора судьи: `lowest_latency`, `priority`, `round_robin`. |
| `GEOIP_AUTO_UPDATE` | `bool` | `true` | Нет | Фоновая загрузка и обновление баз MaxMind Country/ASN по ETag. |

<details>
<summary>👉 <b>Развернуть расширенные параметры тюнинга (таймауты, ротация HMAC, батчинг)</b></summary>

| Переменная | Тип | По умолчанию | Описание |
|---|:---:|:---:|---|
| `JUDGE_SECRET_KEY` | `String` | *(нет)* | Ключ HMAC-SHA256 для включения динамической 24-часовой ротации токенов. |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS`| `u64` | `30` | Период зондирования доступности судей в секундах. |
| `ADDITIONAL_JUDGES` | `String` | *(нет)* | Дополнительные пользовательские судьи через запятую (`HTTP_URL\|HTTPS_URL,...`). |
| `CHECKER_CONNECT_TIMEOUT_MS` | `u64` | `3000` | Таймаут на L4 TCP SYN рукопожатие с прокси (в миллисекундах). |
| `CHECKER_HANDSHAKE_TIMEOUT_MS` | `u64` | `4000` | Таймаут на протокольное согласование (SOCKS, HTTP CONNECT). |
| `CHECKER_READ_WRITE_TIMEOUT_MS` | `u64` | `5000` | Таймаут на чтение ответа судьи через туннель. |
| `CHECKER_MAX_READ_BYTES` | `usize` | `8192` | Максимальный объем читаемого ответа (защита от tarpit). |
| `CHECKER_LOCAL_BIND_IP` | `IpAddr` | *(нет)* | Локальный сетевой IP интерфейса для привязки исходящих сокетов чекера. |
| `SCHEDULER_BATCH_SIZE` | `usize` | `10000` | Размер пачки прокси, выбираемых планировщиком в секунду. |
| `BATCH_FLUSH_INTERVAL_MS` | `u64` | `100` | Интервал сброса буфера результатов MPSC в БД (миллисекунды). |
| `DEAD_PROXY_RETENTION_DAYS` | `u32` | `30` | Срок хранения мертвых прокси в днях до их физического удаления. |
| `DB_MAINTENANCE_INTERVAL_SECS` | `u64` | `3600` | Период фоновой очистки и оптимизации БД (PRAGMA optimize). |
| `RUST_LOG` | `String` | `info` | Уровень детализации журналов трассировки (`tracing`). |

</details>

---

## 📊 Производительность и бенчмарки (10M Records)

Сводные результаты стресс-тестирования на базе объемом **10 000 000 прокси** (размер базы `hydra.db` на диске — **3.57 GB**, 935 210 страниц SQLite, 7 B-Tree индексов). Детальный отчет см. в [BENCHMARK_RESULTS.md](BENCHMARK_RESULTS.md).

| Метрика | Значение | Условия и контекст тестирования |
|---|:---:|---|
| **Скорость массовой вставки (Bulk Insert)** | **109 692 записей/сек** | Пакетная вставка в SQLite в режиме WAL (батчи по 100k) |
| **Скорость Ingestion через REST API** | **14 096 прокси/сек** | Десериализация JSON, bogon-фильтрация, дедупликация и запись |
| **Устойчивая скорость непрерывного чека** | **2 111.5 проверок/сек** | ~126 700 проверок/мин (~7.6 млн проверок/час) |
| **Пиковая скорость чека** | **8 340 проверок/сек** | В моменты пикового завершения сетевых TCP батчей |
| **Завершено проверок за 3-минутный тест** | **380 725 проверок** | 5 000 воркеров под непрерывной нагрузкой |
| **Потребление RAM под нагрузкой 5 000 воркеров** | **92.4 MB** (среднее) / **136.4 MB** (пик) | Отсутствие утечек памяти и утечек дескрипторов сокетов |
| **Нагрузка на процессор (5 000 воркеров)** | **25.8%** (среднее) / **47.6%** (пик) | Ровное распределение по пулу Tokio runtime |
| **Ошибки блокировки SQLite (`DB Locked`)** | **0 ошибок** | Полное устранение конкуренции благодаря MPSC буферу (100 мс) |

### Задержки SQL и API на 10M записях:
- **PK Lookup (`id = 'ip:port'`):** `0.01 мс` *(10 мкс)*
- **Выборка Топ-50 быстрых живых (`idx_alive_fastest`):** `0.03 мс` *(30 мкс)*
- **Маршрутизация страна + протокол + анонимность:** `0.06 мс` *(60 мкс)*
- **Выборка по стране с сортировкой по RTT:** `1.49 мс`
- **Выборка пачки планировщика на 10 000 прокси:** `10.67 мс`
- **In-memory счетчики движка (`GET /api/v1/stats/engine`):** `< 1.0 мс`

---

## 🔍 Краткий обзор API и примеры использования

### 1. Пакетный импорт прокси
```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/import \
  -H "Content-Type: application/json" \
  -H "X-API-Key: hydra_super_secret_api_key_change_me_in_production" \
  -d '{
    "source": "datacenter_feed_1",
    "revive_dead": true,
    "proxies": [
      "socks5://alice:secret123@185.220.101.5:1080",
      "195.154.255.3:8080"
    ]
  }'
```

### 2. Выборка активных живых прокси
```bash
curl -X GET "http://127.0.0.1:3000/api/v1/proxies?country=DE&limit=10" \
  -H "X-API-Key: hydra_super_secret_api_key_change_me_in_production"
```

### 3. Экстренный репорт клиентского сбоя (Карантин)
```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail \
  -H "Content-Type: application/json" \
  -H "X-API-Key: hydra_super_secret_api_key_change_me_in_production" \
  -d '{
    "ids": ["185.220.101.5:1080:alice:secret123"],
    "reason": "Target rate limited (HTTP 429)"
  }'
```

Подробная спецификация всех 13 эндпоинтов со схемами данных представлена в [hydra_api/API.md](hydra_api/API.md).

---

## ❓ Диагностика и частые вопросы (Troubleshooting & FAQ)

### Q: Ошибка `os error 24: Too many open files` при запуске 5000+ воркеров
На Unix-подобных системах системный лимит файловых дескрипторов по умолчанию часто равен 1024. Увеличьте лимит перед запуском:
```bash
ulimit -n 65535
```

### Q: Как проверить работу стека локально без развертывания внешних серверов?
Установите параметр `EMBED_JUDGE=true` в файле `.env`. При старте `hydra_api` автоматически поднимет встроенный фоновый инстанс `hydra_judge` на порту 8080, обеспечивая замкнутый тестовый контур для валидации прокси.

### Q: Блокируется ли база данных SQLite при одновременных запросах к API и проверках?
Нет. Вся запись результатов проверок изолирована в асинхронном MPSC-буфере `batch_writer`, который объединяет сотни обновлений в единые неблокирующие транзакции `BEGIN IMMEDIATE` каждые 100 мс. Чтение выполняется параллельно без задержек за счет режима WAL (Write-Ahead Logging).

---

## 🤝 Участие в разработке (Contributing)

Мы приветствуем вклад сообщества в развитие Hydra! Пожалуйста, ознакомьтесь с нашим руководством по участию в разработке:
👉 **[Руководство контрибьютора (CONTRIBUTING.md)](CONTRIBUTING.md)**

1. Форкните репозиторий и создайте тематическую ветку (`git checkout -b feat/my-new-feature`).
2. Убедитесь, что все тесты проходят: `cargo test --workspace`.
3. Проверьте соответствие кода стандартам оформления: `cargo fmt --all -- --check` и `cargo clippy --workspace`.
4. Откройте Pull Request с описанием внесенных изменений.

---

## 📄 Лицензия

Проект распространяется под открытой лицензией **MIT License**. Полный текст лицензии доступен в файле [LICENSE](LICENSE).
