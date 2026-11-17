# Hydra API — High-Performance REST API & Proxy Pool Orchestrator

[![Rust Version](https://img.shields.io/badge/rust-1.85%2B-orange.svg?style=flat-square&logo=rust)](https://www.rust-lang.org/)
[![Axum Version](https://img.shields.io/badge/axum-0.8-blue.svg?style=flat-square&logo=rust)](https://github.com/tokio-rs/axum)
[![Storage: libSQL WAL](https://img.shields.io/badge/storage-libSQL%20WAL-00D2B8.svg?style=flat-square&logo=sqlite)](https://libsql.org/)
[![OpenAPI / Swagger](https://img.shields.io/badge/docs-OpenAPI%203.0%20%7C%20Swagger-85EA2D.svg?style=flat-square&logo=swagger)](http://127.0.0.1:3000/swagger-ui)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg?style=flat-square)](../LICENSE)
[![Status: Production Ready](https://img.shields.io/badge/status-production--ready-brightgreen.svg?style=flat-square)](https://github.com/hydra-engine)

[Возможности](#-возможности) • [Архитектура](#-архитектура-системы) • [Жизненный цикл](#-жизненный-цикл-прокси-state-machine) • [Системные требования](#-системные-требования) • [Быстрый старт](#-быстрый-старт) • [Конфигурация](#-конфигурация) • [Справочник API](#-справочник-api) • [Бенчмарки](#-производительность-и-бенчмарки) • [Диагностика и FAQ](#-диагностика-и-faq) • [Участие в разработке](#-участие-в-разработке) • [Лицензия](#-лицензия)

---

## 💡 О компоненте

**Hydra API** — это асинхронный центральный оркестратор и REST API сервер пула прокси-серверов на базе Axum 0.8 и libSQL (SQLite WAL), устраняющий задержки оркестрации и блокировки базы данных при параллельном обслуживании десятков миллионов прокси со скоростью инжестинга свыше 14 000 адресов в секунду.

Компонент координирует работу высокопроизводительного конвейера валидации [`hydra_checker`](../hydra_checker/README.md), взаимодействует с эхо-серверами проверки анонимности [`hydra_judge`](../hydra_judge/README.md), непрерывно планирует периодические речеки и предоставляет клиентам низколатентный доступ к проверенным прокси через REST API и интерактивный Swagger UI.

---

## ✨ Возможности

* ⚡ **MPSC Micro-Batching (транзакционный буфер 100 мс):** Потоковая группировка результатов валидации устраняет конкуренцию потоков и ошибки `database is locked`, обеспечивая устойчивую скорость обновления до 8 340 проверок/сек без потери транзакционной целостности.
* 🚀 **Таблицы `WITHOUT ROWID` и 8 B-Tree индексов:** Кластеризованное хранилище на базе libSQL гарантирует точечный поиск по первичному ключу `ip:port` за **0.01 мс** и сложную многофакторную фильтрацию (страна + протокол + анонимность + стабильность) за **0.06 мс** на 10 миллионах записей.
* 🗺️ **Lock-free MaxMind GeoIP / ASN на базе `ArcSwap`:** Фоновое обогащение IP-адресов метаданными страны и автономной системы без блокировок Tokio worker-потоков и без накладных расходов на мьютексы.
* 🔄 **Автоматическое обновление GeoIP баз по ETag:** Непрерывный мониторинг CDN-зеркал (jsDelivr) с поддержкой HTTP `304 Not Modified` и горячей перезагрузкой баз данных на лету без перезапуска сервиса.
* 🛡️ **Контур обратной связи (`POST /report-fail`):** Оперативная изоляция нестабильных или заблокированных целевыми сайтами прокси — клиентские приложения моментально отправляют сигнал сбоя, перемещая прокси в карантин `cooldown`.
* 🎛️ **Режим All-In-One (`EMBED_JUDGE=true`):** Встроенный эхо-сервер проверки анонимности Judge запускается в едином процессе с API, позволяя мгновенно развернуть полноценный стенд разработки без внешних зависимостей.
* 📖 **Интерактивная документация OpenAPI 3.0 / Swagger UI:** Автоматически сгенерированная спецификация схемы и веб-интерфейс Swagger по адресу `/swagger-ui` для быстрой интеграции на любом стеке (Python, Go, Node.js, Rust).

---

## 🏛️ Архитектура системы

Топология взаимодействия модулей Hydra API, фоновых задач Tokio и слоев хранения данных:

```mermaid
graph TD
    subgraph Clients["Клиентский контур"]
        UserApp["Скраперы / Боты / Клиенты"]
        Swagger["Swagger UI / OpenAPI (:3000/swagger-ui)"]
        AdminCLI["DevOps / Скрипты импорта"]
    end

    subgraph API_Edge["Граничный слой hydra_api (Axum 0.8)"]
        Router["Axum HTTP Router (:3000)"]
        AuthMiddleware["Auth Middleware (X-API-Key)"]
        ReportHandler["Fail-Report Ingestion"]
        ProxyHandler["Proxy Query & Import Handler"]
    end

    subgraph Orchestration["Контур оркестрации и планирования"]
        Scheduler["Scheduler Loop<br/>(10 000 созревших прокси / сек)"]
        BatchWriter["MPSC Batch Writer<br/>(100 мс микробатчинг)"]
        Maintenance["DB Maintenance Loop<br/>(Очистка dead_permanent, PRAGMA optimize)"]
        GeoIP["GeoIP Service (MaxMind ArcSwap + ETag Auto-updater)"]
    end

    subgraph Verification["Контур верификации и судейства"]
        Checker["hydra_checker Pipeline<br/>(L4 TCP / TLS / L7 Protocol Detect)"]
        JudgePool["Judge Pool (failover, lowest_latency)"]
        EmbedJudge["Встроенный Judge (:8080)<br/>(при EMBED_JUDGE=true)"]
    end

    subgraph Storage["Слой персистентности (libSQL WAL)"]
        DB[("hydra.db (WITHOUT ROWID)<br/>proxies, sources, proxy_sources")]
        Indexes["8 B-Tree Индексов<br/>(idx_scheduler_prio, idx_alive_fastest, idx_alive_stability и др.)"]
    end

    UserApp -->|REST API + X-API-Key| Router
    Swagger -->|HTTP GET| Router
    AdminCLI -->|POST /import| Router

    Router --> AuthMiddleware
    AuthMiddleware --> ProxyHandler
    AuthMiddleware --> ReportHandler

    ProxyHandler -->|Точечное чтение / Инжестинг| DB
    ReportHandler -->|Сигнал сбоя| BatchWriter

    Scheduler -->|fetch_due_proxies| Indexes
    Scheduler -->|Пакет задач| Checker

    Checker --> JudgePool
    JudgePool -.->|Проверка эхо-заголовков| EmbedJudge

    Checker -->|Результаты проверок| BatchWriter
    BatchWriter -->|Атомарная транзакция| DB

    GeoIP -->|Обогащение метаданными| ProxyHandler
    Maintenance -->|Вакуум и оптимизация| DB
```

---

## 🔄 Жизненный цикл прокси (State Machine)

Каждый прокси-сервер в пуле строго следует 4-фазному конечному автомату состояний:

```mermaid
stateDiagram-v2
    [*] --> cold_queue: Импорт через POST /proxies/import (state=0, next_check_at=0)
    
    cold_queue --> alive: L4 + L7 Check Успешен (state=1, strikes=0)
    cold_queue --> dead_permanent: Недоступен / Bogon IP / Таймаут (state=3)
    
    alive --> cooldown: Ошибка речека ИЛИ POST /report-fail (state=2, strikes++)
    alive --> alive: Успешный плановый речек (state=1, recheck_alive_sec)
    
    cooldown --> alive: Успешная перепроверка (state=1, strikes=0)
    cooldown --> cooldown: Очередной сбой (strikes < max_dead_strikes)
    cooldown --> dead_permanent: Превышен лимит сбоев (strikes >= max_dead_strikes)
    
    dead_permanent --> cold_queue: Принудительный реимпорт с revive_dead=true
    dead_permanent --> [*]: Очистка фоновым обслуживанием (DEAD_PROXY_RETENTION_DAYS)
```

| Состояние | Код | Семантика | Поведение планировщика |
| :--- | :---: | :--- | :--- |
| `cold_queue` | `0` | Новая прокси, ожидает первичной классификации протокола и валидации. | Приоритетная очередь с `next_check_at = 0`. |
| `alive` | `1` | Подтвержденная рабочая прокси с известным RTT, протоколом и страной. | Регулярный речек через интервал `recheck_alive_sec`. Доступна в API. |
| `cooldown` | `2` | Временный сбой соединения или репорт от скрапера. Находится в карантине. | Экспоненциальный речек через интервал `recheck_dead_sec`. |
| `dead_permanent` | `3` | Окончательно неработоспособна, превышен порог `max_dead_strikes`. | Исключена из очереди проверок. Удаляется через 30 дней. |

---

## 💻 Системные требования

Перед сборкой и запуском `hydra_api` убедитесь в наличии следующего окружения:

* **Операционная система:** Linux (Ubuntu 22.04+, Debian 12+, RHEL 9+), macOS 13+, Windows 10/11 или Windows Server 2022.
* **Rust Toolchain:** Версия `>= 1.85.0` (редакция Rust 2024).
* **СУБД / Хранилище:** Встроенный движок libSQL / SQLite (никаких внешних серверов MySQL или PostgreSQL не требуется; движок компилируется статически).
* **Оперативная память (RAM):**
  * Холостой ход / минимальный пул: **~25 MB**.
  * Под нагрузкой 5 000 параллельных воркеров (10M записей): **~95–140 MB**.
* **Дисковое пространство:** ~3.8 GB для хранения базы данных на 10 000 000 записей со всеми 7 вторичными B-Tree индексами.

---

## 🚀 Быстрый старт

Запустите полностью автономный оркестратор Hydra API за 3 шага.

### Шаг 1. Подготовьте файл переменных окружения

```bash
cp .env.example .env
```

### Шаг 2. Задайте секретный ключ авторизации API

Отредактируйте созданный файл `.env` и укажите секретный ключ `API_KEY`:

```bash
sed -i 's/API_KEY=.*/API_KEY=my_secure_hydra_key_12345/' .env
```

> [!TIP]
> Параметр `EMBED_JUDGE=true` в файле `.env.example` уже активирован по умолчанию. Сервер автоматически запустит встроенный тестовый эхо-сервер Judge на порту 8080 параллельно с REST API.

### Шаг 3. Соберите и запустите сервис

```bash
cargo run --release -p hydra_api
```

После старта сервер начнет принимать соединения:
* **REST API:** `http://127.0.0.1:3000`
* **Swagger UI:** `http://127.0.0.1:3000/swagger-ui`
* **OpenAPI 3.0 Спецификация:** `http://127.0.0.1:3000/api-docs/openapi.json`

Проверьте готовность сервиса простым запросом телеметрии:

```bash
curl -H "X-API-Key: my_secure_hydra_key_12345" http://127.0.0.1:3000/api/v1/stats/engine
```

---

## ⚙️ Конфигурация

Все параметры считываются из переменных окружения процесса или локального файла `.env`.

| Переменная | Тип | По умолчанию | Обязательно | Описание |
| :--- | :---: | :---: | :---: | :--- |
| `LISTEN_ADDR` | `string` | `0.0.0.0:3000` | Нет | Сетевой интерфейс и TCP-порт REST API сервера и Swagger UI. |
| `API_KEY` | `string` | — | **Да** | Секретный токен для проверки заголовка `X-API-Key`. Без него сервер завершит запуск с ошибкой. |
| `DB_PATH` | `string` | `./data/hydra.db` | Нет | Путь к локальному файлу базы данных libSQL на диске. |
| `EMBED_JUDGE` | `bool` | `false` | Нет | Включение встроенного экземпляра JudgeServer в фоновом потоке API для режима All-in-One. |
| `EMBED_JUDGE_PORT` | `int` | `8080` | Нет | TCP-порт для прослушивания запросов встроенного судьи Judge. |
| `CHECKER_CONCURRENCY` | `int` | `5000` | Нет | Максимальный лимит параллельных проверок чекера [`hydra_checker`](../hydra_checker/README.md). |
| `JUDGE_HTTP_URL` | `string` | `http://127.0.0.1:8080` | Нет | HTTP URL эхо-сервера Judge для проверки Plain HTTP прокси. |
| `JUDGE_HTTPS_URL` | `string` | `http://127.0.0.1:8080` | Нет | HTTPS URL эхо-сервера Judge для проверки TLS/CONNECT туннелей. |
| `JUDGE_SECRET_TOKEN` | `string` | `hydra_secret_token` | Нет | Статический токен верификации ответов судьи. |
| `RUST_LOG` | `string` | `info,hydra_api=debug` | Нет | Уровень детализации структурированных логов `tracing`. |

<details>
<summary><b>Показать расширенные параметры тюнинга GeoIP, планировщика и обслуживания БД (Advanced Tuning)</b></summary>

| Переменная | Тип | По умолчанию | Обязательно | Описание |
| :--- | :---: | :---: | :---: | :--- |
| `JUDGE_SELECTION_STRATEGY` | `enum` | `lowest_latency` | Нет | Стратегия выбора судьи из пула (`lowest_latency`, `priority`, `round_robin`). |
| `JUDGE_SECRET_KEY` | `string` | — | Нет | Мастер-ключ HMAC-SHA256 для динамической посуточной ротации токенов судьи. |
| `ENABLE_THIRD_PARTY_JUDGES` | `bool` | `true` | Нет | Разрешить использование внешних публичных судей при отказе основного пула. |
| `JUDGE_HEALTH_CHECK_INTERVAL_SECS` | `int` | `30` | Нет | Интервал автоматической проверки доступности судей (в секундах). |
| `ADDITIONAL_JUDGES` | `string` | — | Нет | Список дополнительных судей в формате `HTTP_URL\|HTTPS_URL,...`. |
| `CHECKER_REAL_IP` | `string` | — | Нет | Статический внешний IP чекера для точного определения уровня анонимности (`elite`/`transparent`). |
| `GEOIP_AUTO_UPDATE` | `bool` | `true` | Нет | Автоматическая загрузка и обновление баз GeoLite2 из CDN-зеркала (jsDelivr). |
| `GEOIP_COUNTRY_PATH` | `string` | `./geo/GeoLite2-Country.mmdb` | Нет | Путь к файлу базы стран MaxMind GeoLite2 Country. |
| `GEOIP_ASN_PATH` | `string` | `./geo/GeoLite2-ASN.mmdb` | Нет | Путь к файлу базы автономных систем MaxMind GeoLite2 ASN. |
| `GEOIP_RELOAD_SECS` | `int` | `3600` | Нет | Период перечитки файлов баз с диска без перезапуска (в секундах). |
| `GEOIP_UPDATE_INTERVAL_SECS` | `int` | `86400` | Нет | Интервал проверки свежих версий баз в CDN-зеркале по ETag (в секундах). |
| `GEOIP_COUNTRY_URL` | `string` | `https://cdn.jsdelivr.net/...` | Нет | Прямой URL для загрузки архива базы стран `GeoLite2-Country.mmdb.gz`. |
| `GEOIP_ASN_URL` | `string` | `https://cdn.jsdelivr.net/...` | Нет | Прямой URL для загрузки архива базы автономных систем `GeoLite2-ASN.mmdb.gz`. |
| `SCHEDULER_BATCH_SIZE` | `int` | `10000` | Нет | Размер пакета созревших прокси, извлекаемых планировщиком каждую секунду. |
| `BATCH_FLUSH_INTERVAL_MS` | `int` | `100` | Нет | Максимальный интервал сброса буфера результатов проверок в БД (микробатчинг). |
| `DEAD_PROXY_RETENTION_DAYS` | `int` | `30` | Нет | Срок хранения окончательно мертвых прокси (`dead_permanent`) до удаления. |
| `DB_MAINTENANCE_INTERVAL_SECS`| `int` | `3600` | Нет | Интервал запуска обслуживания БД (очистка, неблокирующий WAL checkpoint, `PRAGMA optimize`). |

</details>

---

## 📡 Справочник API

Полное формальное описание всех эндпоинтов, DTO-моделей и параметров доступно в отдельном документе:
👉 **[Полная документация REST API (API.md)](API.md)**

Также интерактивный интерфейс доступен в браузере:
* **Swagger UI:** [`http://127.0.0.1:3000/swagger-ui`](http://127.0.0.1:3000/swagger-ui)
* **OpenAPI 3.0 Схема:** [`http://127.0.0.1:3000/api-docs/openapi.json`](http://127.0.0.1:3000/api-docs/openapi.json)

Все запросы требуют обязательного заголовка `X-API-Key: <значение>`.

### 1. Пакетный импорт сырых прокси

Принимает прокси списком строк (поддерживаются форматы `ip:port`, `protocol://ip:port`, `ip:port:user:pass`) или массивом JSON-объектов с индивидуальными таймаутами.

```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/import \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "source": "datacenter_provider_alpha",
    "revive_dead": true,
    "policy": {
      "connect_timeout_ms": 3000,
      "recheck_alive_sec": 60,
      "recheck_dead_sec": 300,
      "max_dead_strikes": 3,
      "stability_window_min": 5,
      "dead_backoff_mult": 1.5
    },
    "proxies": [
      "socks5://user:pass@185.220.101.5:1080",
      "195.154.255.3:8080",
      "194.67.210.88:9050:proxy_user:proxy_pass"
    ]
  }'
```

Пример успешного ответа (`200 OK`):

```json
{
  "source_id": 1,
  "total_received": 3,
  "inserted_new": 3,
  "updated_existing": 0,
  "revived": 0,
  "invalid_format": 0
}
```

---

### 2. Выборка проверенных прокси с фильтрацией

Выборка готовых к работе прокси из активного пула (`state=alive`) с сортировкой по пингу, фильтрацией по стране, протоколу и анонимности.

```bash
curl -G http://127.0.0.1:3000/api/v1/proxies \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  --data-urlencode "country=DE" \
  --data-urlencode "protocol=socks5" \
  --data-urlencode "anon=elite" \
  --data-urlencode "min_stability=90" \
  --data-urlencode "limit=2"
```

Пример успешного ответа (`200 OK`):

```json
[
  {
    "id": "185.220.101.5:1080",
    "ip": "185.220.101.5",
    "port": 1080,
    "url": "socks5://185.220.101.5:1080",
    "protocol": "socks5",
    "has_auth": false,
    "auth_user": null,
    "auth_pass": null,
    "state": "alive",
    "supports_https": true,
    "out_ip": "185.220.101.5",
    "country": "DE",
    "asn": 24940,
    "asn_org": "Hetzner Online GmbH",
    "anon": "elite",
    "rtt_tcp_ms": 25,
    "rtt_handshake_ms": 17,
    "rtt_total_ms": 42,
    "uptime_pct": 99.8,
    "stability_pct": 100.0,
    "stability_window_min": 5,
    "checks_total": 1420,
    "checks_success": 1417,
    "dead_strikes": 0,
    "last_error": null,
    "remark": null,
    "first_seen_at": 1731300000,
    "last_checked_at": 1731362400,
    "next_check_at": 1731362460
  }
]
```

---

### 3. Экстренный клиентский отчет о сбое (Fail Report)

Клиентские боты или скраперы мгновенно отправляют уведомление, если живая прокси заблокирована целевым ресурсом (например, Cloudflare 403 / Captcha). Прокси сразу перемещается в `cooldown`.

```bash
curl -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail \
  -H "X-API-Key: my_secure_hydra_key_12345" \
  -H "Content-Type: application/json" \
  -d '{
    "id": "185.220.101.5:1080",
    "reason": "Target host returned 403 Forbidden Cloudflare challenge"
  }'
```

Пример успешного ответа (`200 OK`):

```json
{
  "status": "reported",
  "id": "185.220.101.5:1080",
  "new_state": 2
}
```

---

### 4. Мгновенная in-memory телеметрия движка

Возвращает агрегированные счетчики очередей и производительности чекера из оперативной памяти без дискового ввода-вывода (время ответа `< 1 мс`).

```bash
curl -H "X-API-Key: my_secure_hydra_key_12345" \
  http://127.0.0.1:3000/api/v1/stats/engine
```

Пример успешного ответа (`200 OK`):

```json
{
  "active_workers": 1284,
  "queue_depth": 3105,
  "checks_per_second": 2450.8,
  "pool_alive_count": 48210,
  "pool_cooldown_count": 312,
  "pool_cold_count": 1400,
  "pool_dead_count": 5200,
  "db_batch_queue_len": 45
}
```

---

## 📊 Производительность и бенчмарки

Архитектура Hydra API спроектирована для работы с базами данных объемом **до 10 000 000 записей** на обычном commodity-оборудовании. Ниже приведены консолидированные замеры нагрузочного тестирования.

> Подробная методология, конфигурация стенда и замеры дискового пространства приведены в документе:
> 👉 **[Полный отчет о бенчмарках (BENCHMARK_RESULTS.md)](../BENCHMARK_RESULTS.md)**

### Ключевые показатели производительности

| Параметр | Значение | Условия и описание |
| :--- | :---: | :--- |
| **Скорость массовой вставки (Bulk SQL Insert)** | **109 692 записей/сек** | Пакетная вставка в 10M таблицу батчами по 100k в режиме WAL. |
| **Скорость API импорта (API Ingestion)** | **14 096 прокси/сек** | HTTP JSON десериализация, валидация, отсев bogon IP и запись. |
| **Пиковая скорость чека (10M пул)** | **8 340 проверок/сек** | Момент пикового завершения пачек TCP handshake и L7 Judge. |
| **Средняя скорость непрерывного чека** | **2 111.5 проверок/сек** | 380 725 проверок за 3 минуты при 5 000 параллельных воркерах. |
| **Ошибки блокировки БД (DB Locked / Busy)** | **0 ошибок** | За счет неблокирующего транзакционного буфера MPSC (100 мс). |
| **Потребление RAM (холостой ход API)** | **22.9 – 27.0 MB** | При пуле в 307 прокси и загруженных маршрутах Axum. |
| **Потребление RAM (под нагрузкой 5 000 воркеров)** | **92.4 MB (avg), 136.4 MB (peak)** | Без утечек памяти на пуле из 10 000 000 записей. |
| **Загрузка CPU (5 000 воркеров)** | **25.8% (avg), 47.6% (peak)** | Равномерная утилизация пула потоков Tokio runtime. |

### Задержки выполнения запросов (Latency)

| Операция / Эндпоинт | Задержка (Latency) | Механизм выполнения |
| :--- | :---: | :--- |
| **PK Lookup (`id = 'ip:port'`)** | **0.01 мс** *(10 мкс)* | Поиск по первичному ключу таблицы `WITHOUT ROWID`. |
| **Топ-50 быстрых живых (`LIMIT 50`)** | **0.03 мс** *(30 мкс)* | Сканирование специализированного B-Tree индекса `idx_alive_fastest`. |
| **Маршрутизация (страна + протокол + анонимность)** | **0.06 мс** *(60 мкс)* | Поиск по составному B-Tree индексу `idx_alive_routing`. |
| **Выборка по стране с сортировкой по пингу** | **1.49 мс** | Индексный поиск по `idx_alive_country_rtt`. |
| **Выборка пачки планировщика на 10 000 прокси** | **10.67 мс** | Пакетный сбор задач через `idx_scheduler_prio`. |
| `GET /api/v1/stats/engine` | **< 1.0 мс** | Мгновенное чтение in-memory атомарных счетчиков Tokio. |
| `GET /api/v1/proxies?limit=50` | **25.6 мс** | Полный сквозной HTTP-запрос Axum + сериализация JSON. |

---

## 🔧 Диагностика и FAQ

### В: При вызове любого эндпоинта возвращается ошибка `401 Unauthorized`.
**О:** В запросе отсутствует заголовок `X-API-Key` или его значение не совпадает с переменной `API_KEY` в файле `.env`. Добавьте заголовок:
```bash
curl -H "X-API-Key: <ваш_ключ>" http://127.0.0.1:3000/api/v1/proxies
```

### В: Ошибка при запуске: `Address already in use (os error 98 / 10048)`.
**О:** Порт `3000` (API) или `8080` (Judge) уже занят другим процессом. Измените параметры `LISTEN_ADDR` (например, `0.0.0.0:3001`) или `EMBED_JUDGE_PORT` (например, `8081`) в конфигурационном файле `hydra_api/.env`.

### В: В ответах API поля `country` и `asn` возвращают `null`.
**О:** Локальные файлы баз MaxMind GeoLite2 отсутствуют по путям `GEOIP_COUNTRY_PATH` и `GEOIP_ASN_PATH`. Включите `GEOIP_AUTO_UPDATE=true` в `.env` для их автоматической загрузки из CDN или поместите файлы `.mmdb` в каталог `./geo/`.

### В: Почему после импорта прокси не появляются в `GET /api/v1/proxies`?
**О:** Эндпоинт `GET /api/v1/proxies` по умолчанию возвращает только проверенные рабочие прокси (`state=alive`). Свежеимпортированные прокси поступают в очередь `cold_queue` (`state=0`) и ожидают первой валидации планировщиком. Чтобы увидеть их, выполните запрос с фильтром:
```bash
curl -H "X-API-Key: <ваш_ключ>" "http://127.0.0.1:3000/api/v1/proxies?state=cold_queue"
```

---

## 🤝 Участие в разработке

Мы приветствуем вклад в развитие Hydra API! Перед отправкой Pull Request ознакомьтесь с общими стандартами в документе [`CONTRIBUTING.md`](../CONTRIBUTING.md).

### Сборка и тестирование

```bash
cargo fmt --all -- --check
cargo clippy -p hydra_api --all-targets -- -D warnings
cargo test -p hydra_api
```

---

## 📜 Лицензия

Проект распространяется под открытой лицензией MIT. Подробности см. в файле [`LICENSE`](../LICENSE).
