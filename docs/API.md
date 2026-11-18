# Hydra REST API

Base URL: `http://127.0.0.1:3000`  
Аутентификация: HTTP-заголовок `X-API-Key: <token>` (переменная окружения `API_KEY`). Эндпоинты `/swagger-ui` и `/api-docs/openapi.json` общедоступны.

---

## 1. Справочные таблицы

### 1.1. Состояния жизненного цикла (`ProxyState`)

| Значение `state` | Код | Описание |
|---|---|---|
| `cold_queue` | `0` | Новая прокси, ожидает первой проверки в очереди первичного тестирования. |
| `alive` | `1` | Рабочая прокси в активном пуле, подтвержденная judge-сервером. Готова к выдаче клиентам. |
| `cooldown` | `2` | Карантин после сбоя проверки или клиентского fail-report. Ожидает речека с экспоненциальным бэкоффом. |
| `dead_permanent` | `3` | Превышен лимит последовательных сбоев (`max_dead_strikes`). Исключена из очередей речека. |

### 1.2. Протоколы и уровни анонимности

| Параметр | Возможные значения | Описание |
|---|---|---|
| `protocol` | `socks5`, `socks4`, `http` | Сетевой протокол. Для `http` проверяется поддержка CONNECT-туннелирования (`supports_https`). |
| `anon` | `elite` | Высокая анонимность: факт проксирования и исходный IP скрыты (заголовки `Via`, `X-Forwarded-For` отсутствуют). |
| | `anonymous` | Средняя анонимность: факт проксирования виден серверу, но реальный IP клиента скрыт. |
| | `transparent` | Прозрачный: реальный IP клиента передается целевому серверу в заголовках. |

### 1.3. Политика сетевых проверок и речека (`CheckPolicyDto`)

Настройки сетевых тайм-аутов, порогов деградации и расписания фонового планировщика. Задаются при импорте пула (`POST /api/v1/proxies/import`) или обновляются индивидуально для каждой прокси через `PATCH /api/v1/proxies/{id}`.

| Поле (JSON) | Тип | Дефолт | Диапазон | Точное назначение и влияние на планировщик/чекер |
|---|---|---|---|---|
| `connect_timeout_ms` | `u32` | `3000` (мс) | `100` – `60000` | Предельный тайм-аут на установление первичного TCP-соединения с сокетом прокси. При превышении чекер фиксирует сбой этапа `connect`. |
| `handshake_timeout_ms` | `u32` | `4000` (мс) | `100` – `60000` | Предельный тайм-аут на выполнение протокольного рукопожатия (SOCKS-аутентификация / SSL/TLS-handshake / HTTP CONNECT). Превышение расценивается как сбой этапа `handshake`. |
| `rw_timeout_ms` | `u32` | `5000` (мс) | `100` – `60000` | Предельный тайм-аут на отправку контрольного HTTP-запроса и чтение ответа от judge-сервера (I/O). При превышении чекер фиксирует сбой этапа валидации (`rw timeout`). |
| `recheck_alive_sec` | `u32` | `60` (с) | `10` – `86400` | Интервал плановой фоновой перепроверки валидных прокси в статусе `alive`. При успешной проверке планировщик выставляет `next_check_at = now + recheck_alive_sec`. |
| `recheck_dead_sec` | `u32` | `1800` (с) | `30` – `604800` | Базовый интервал речека сбойных прокси в карантине (`cooldown`). Служит основой для расчета задержки первого и последующих штрафных речеков. При значении `0` прокси сразу помечается как `dead_permanent`. |
| `max_dead_strikes` | `u32` | `3` | `1` – `50` | Порог допустимых последовательных сбоев (`dead_strikes`). При достижении порога прокси безвозвратно переводится в `dead_permanent` (код `3`) и исключается из очередей планировщика. |
| `stability_window_min` | `u32` | `5` (мин) | `1` – `1440` | Временное скользящее окно (в минутах) для расчета метрики качества `stability_pct`. Результаты проверок старше `(now - stability_window_min * 60)` автоматически отсекаются. Алиасы: `stability_window`, `window_min`, `window_minutes`. |
| `dead_backoff_mult` | `f32` | `1.5` | `1.0` – `10.0` | Множитель экспоненциального бэкоффа для расчета задержки повторных проверок в статусе `cooldown`. При значении `1.0` интервал между речеками остается постоянным. Алиасы: `backoff_multiplier`, `recheck_dead_multiplier`, `dead_multiplier`, `recheck_dead_mult`, `multiplier`. |

**Формула расчета карантинного речека в `cooldown`:**

При неудачной проверке инкрементируется счетчик последовательных сбоев `strikes` (`new_strikes = current_strikes + 1`). Если `strikes < max_dead_strikes`, прокси переводится в статус `cooldown` (или остается в нем), а задержка следующей проверки вычисляется по формуле:

`интервал = recheck_dead_sec * (dead_backoff_mult ^ (strikes - 1))`

> *Примечание:* Вычисленный `интервал` аппаратно ограничивается диапазоном от 1 секунды до 30 дней: `clamp(1, 2592000)` секунд. Время следующей проверки назначается как `next_check_at = now + интервал`. При `strikes >= max_dead_strikes` прокси переходит в терминальное состояние `dead_permanent` (код `3`).

> **Формат идентификатора прокси (`id`):** `ip:port` (для публичных) или `ip:port:user:pass` (для приватных). В путях URL (`/api/v1/proxies/{id}`) спецсимволы (`:`, `@`, `#`, `/`) **обязаны** быть percent-encoded (например, `1.2.3.4%3A8080%3Au%40ser%3Ap%23ass`).

---

## 2. Маршруты API

### Группа 1: Proxies

#### `POST /api/v1/proxies/import`
Пакетный импорт сырых прокси в очередь `cold_queue` с валидацией, дедупликацией и привязкой к источнику.

- **Request Body (JSON):**
  ```json
  {
    "source": "premium_pool_v1",
    "source_url": "https://provider.example.com/feed.txt",
    "remark": "Corporate subnet proxies",
    "revive_dead": true,
    "ignore_protocol": false,
    "policy": {
      "connect_timeout_ms": 3000,
      "handshake_timeout_ms": 4000,
      "rw_timeout_ms": 5000,
      "recheck_alive_sec": 60,
      "recheck_dead_sec": 1800,
      "max_dead_strikes": 3,
      "stability_window_min": 5,
      "dead_backoff_mult": 1.5
    },
    "proxies": [
      "socks5://user:pass@185.220.101.5:1080",
      "195.154.255.3:8080",
      {
        "ip": "185.220.101.6",
        "port": 1080,
        "protocol": "socks5",
        "auth_user": "myuser",
        "auth_pass": "mypassword",
        "ignore_protocol": false
      }
    ]
  }
  ```
  - `revive_dead` *(bool, def: false)*: Сбросить счетчики и перевести найденные `dead_permanent` прокси в `cold_queue`.
  - `ignore_protocol` *(bool, def: false)*: Игнорировать переданный протокол и запустить каскадный автодетект (SOCKS5 → SOCKS4 → HTTP).
  - `policy` *(object, opt)*: Переопределение сетевых тайм-аутов и расписания речека для пула (см. [п. 1.3](#13-политика-сетевых-проверок-и-речека-checkpolicydto)). При отсутствии применяются системные значения по умолчанию.
  - `proxies` *(array)*: Элементы в формате строк (`proto://user:pass@ip:port`, `ip:port:user:pass`, `ip:port`, `[ipv6]:port`) или объектов.

- **Response `200 OK` (JSON):**
  ```json
  {
    "source_id": 1,
    "total_received": 3,
    "inserted_new": 2,
    "updated_existing": 1,
    "revived": 0,
    "invalid_format": 0
  }
  ```
- **Ошибки:** `400 Bad Request` (пустой `source`), `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X POST http://127.0.0.1:3000/api/v1/proxies/import -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"source":"p1","proxies":["socks5://u:p@1.2.3.4:1080","5.6.7.8:8080"]}'
  ```

---

#### `GET /api/v1/proxies`
Фильтрация и постраничная выгрузка прокси по сетевым характеристикам, географии и качеству.

- **Query-параметры:**
  | Параметр | Тип | Дефолт | Назначение |
  |---|---|---|---|
  | `state` | string | `alive` | Фильтр статуса: `alive`, `cold_queue`, `cooldown`, `dead_permanent`. |
  | `country` | string | — | ISO-код страны или список через запятую (`DE` или `DE,NL,FR`). |
  | `exclude_country` | string | — | Исключение стран через запятую (`RU,CN`). |
  | `protocol` | string | — | Протокол: `socks5`, `http`, `socks4`. |
  | `anon` | string | — | Анонимность: `elite`, `anonymous`, `transparent`. |
  | `supports_https` | bool | — | Поддержка HTTPS CONNECT (`true`/`false`). |
  | `has_auth` | bool | — | Наличие авторизации (`true` — приватные, `false` — публичные). |
  | `max_rtt` | u32 | — | Максимальный суммарный RTT (мс). |
  | `min_uptime` | f32 | — | Минимальный пожизненный аптайм (0.0 — 100.0 %). |
  | `min_stability` | f32 | — | Минимальная стабильность в окне N минут (0.0 — 100.0 %). |
  | `stability_window_min` | u32 | — | Размер окна расчета стабильности (минуты). |
  | `source` | string | — | Имя источника импорта. |
  | `limit` | u32 | `50` | Лимит записей. Значение `0` снимает ограничение (выгрузка всего пула). |
  | `offset` | u32 | `0` | Смещение пагинации. |

- **Response `200 OK` (JSON):**
  ```json
  [
    {
      "id": "185.220.101.5:1080:user:secret123",
      "ip": "185.220.101.5",
      "port": 1080,
      "url": "socks5://user:secret123@185.220.101.5:1080",
      "protocol": "socks5",
      "has_auth": true,
      "auth_user": "user",
      "auth_pass": "secret123",
      "state": "alive",
      "supports_https": true,
      "out_ip": "185.220.101.5",
      "country": "DE",
      "asn": 24940,
      "asn_org": "Hetzner Online GmbH",
      "anon": "elite",
      "rtt_tcp_ms": 42,
      "rtt_handshake_ms": 68,
      "rtt_total_ms": 110,
      "uptime_pct": 98.5,
      "stability_pct": 100.0,
      "stability_window_min": 5,
      "checks_total": 450,
      "checks_success": 445,
      "dead_strikes": 0,
      "last_error": null,
      "remark": "High performance German node",
      "first_seen_at": 1731200000,
      "last_checked_at": 1731256800,
      "next_check_at": 1731256860
    }
  ]
  ```
- **Ошибки:** `400 Bad Request`, `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/proxies?state=alive&protocol=socks5&country=DE&limit=10" -H "X-API-Key: $KEY"
  ```

---

#### `POST /api/v1/proxies/report-fail`
Клиентское уведомление о сбое прокси: перевод в `cooldown`, инкремент `dead_strikes` и назначение внеочередного речека.

- **Request Body (JSON):**
  ```json
  {
    "ids": [
      "185.220.101.5:1080:myuser:mypassword",
      "195.154.255.3:8080"
    ],
    "reason": "Connection reset by peer during target handshake"
  }
  ```
  *(Поддерживается как одиночный `id: "..."`, так и массив `ids: ["..."]`)*.

- **Response `200 OK` (JSON):**
  ```json
  {
    "status": "reported",
    "affected_count": 2,
    "reported_ids": [
      "185.220.101.5:1080:myuser:mypassword",
      "195.154.255.3:8080"
    ],
    "proxy_id": "185.220.101.5:1080:myuser:mypassword"
  }
  ```
- **Ошибки:** `400 Bad Request` (нет `id`/`ids` или пустой `reason`), `401 Unauthorized`, `404 Not Found` (ни одна прокси не найдена в статусе `alive`), `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X POST http://127.0.0.1:3000/api/v1/proxies/report-fail -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"ids":["195.154.255.3:8080"],"reason":"target ban"}'
  ```

---

#### `GET /api/v1/proxies/{id}`
Получение полной карточки прокси с политикой тайм-аутов (см. [п. 1.3](#13-политика-сетевых-проверок-и-речека-checkpolicydto)), RTT-метриками и деталями источников.

- **Path-параметры:** `id` *(string, URL-encoded)* — идентификатор прокси (`ip:port` или `ip:port:user:pass`).
- **Response `200 OK` (JSON):**
  ```json
  {
    "id": "185.220.101.5:1080:user:secret123",
    "ip": "185.220.101.5",
    "port": 1080,
    "url": "socks5://user:secret123@185.220.101.5:1080",
    "has_auth": true,
    "auth_user": "user",
    "auth_pass": "secret123",
    "state": "alive",
    "protocol": "socks5",
    "supports_https": true,
    "out_ip": "185.220.101.5",
    "country": "DE",
    "asn": 24940,
    "asn_org": "Hetzner Online GmbH",
    "anon": "elite",
    "metrics": {
      "rtt_tcp_ms": 42,
      "rtt_handshake_ms": 68,
      "rtt_total_ms": 110
    },
    "policy": {
      "connect_timeout_ms": 3000,
      "handshake_timeout_ms": 4000,
      "rw_timeout_ms": 5000,
      "recheck_alive_sec": 60,
      "recheck_dead_sec": 1800,
      "max_dead_strikes": 3,
      "stability_window_min": 5,
      "dead_backoff_mult": 1.5
    },
    "stats": {
      "checks_total": 450,
      "checks_success": 445,
      "uptime_pct": 98.88,
      "stability_pct": 100.0,
      "dead_strikes": 0,
      "last_error": null,
      "first_seen_at": 1731200000,
      "last_checked_at": 1731256800,
      "next_check_at": 1731256860
    },
    "meta": {
      "remark": "High performance German node",
      "sources": ["premium_pool_v1", "backup_tor_feed"],
      "source_details": [
        { "name": "premium_pool_v1", "added_at": 1731200000 },
        { "name": "backup_tor_feed", "added_at": 1731210000 }
      ]
    }
  }
  ```
- **Ошибки:** `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY"
  ```

---

#### `PATCH /api/v1/proxies/{id}`
Частичное обновление параметров, учетных данных, политики тайм-аутов или принудительный запуск речека.

- **Path-параметры:** `id` *(string, URL-encoded)*.
- **Request Body (JSON):**
  ```json
  {
    "remark": "Reserved for scraper worker #4",
    "auth_user": "myuser",
    "auth_pass": "mypassword",
    "ignore_protocol": false,
    "force_recheck": true,
    "policy": {
      "connect_timeout_ms": 2000,
      "handshake_timeout_ms": 3000,
      "rw_timeout_ms": 4000,
      "recheck_alive_sec": 30,
      "recheck_dead_sec": 600,
      "max_dead_strikes": 2,
      "stability_window_min": 5,
      "dead_backoff_mult": 2.0
    }
  }
  ```
  - `policy` *(object, opt)*: Частичное или полное обновление параметров тайм-аутов и речека (см. [п. 1.3](#13-политика-сетевых-проверок-и-речека-checkpolicydto)).
  - `force_recheck` *(bool, opt)*: Принудительно запланировать проверку на текущую секунду.
  - `ignore_protocol` *(bool, opt)*: Сбросить протокол на автоопределение (SOCKS5 → SOCKS4 → HTTP).

- **Response:** `200 OK` (пустое тело).
- **Ошибки:** `400 Bad Request`, `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X PATCH "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY" -H "Content-Type: application/json" -d '{"force_recheck":true,"remark":"updated"}'
  ```

---

#### `DELETE /api/v1/proxies/{id}`
Безвозвратное удаление прокси и её привязок к источникам из базы данных.

- **Path-параметры:** `id` *(string, URL-encoded)*.
- **Response:** `204 No Content`.
- **Ошибки:** `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -i -X DELETE "http://127.0.0.1:3000/api/v1/proxies/185.220.101.5%3A1080" -H "X-API-Key: $KEY"
  ```

---

### Группа 2: Sources

#### `GET /api/v1/sources`
Список всех источников прокси с агрегированными метриками выхода (yield %), статусами и средней задержкой.

- **Query-параметры:** отсутствуют.
- **Response `200 OK` (JSON):**
  ```json
  [
    {
      "id": 1,
      "name": "premium_pool_v1",
      "url": "https://provider.example.com/feed.txt",
      "remark": "Primary corporate subnet proxies",
      "total_proxies": 1000,
      "alive_proxies": 850,
      "cold_queue_proxies": 50,
      "cooldown_proxies": 70,
      "dead_proxies": 30,
      "yield_pct": 85.0,
      "avg_rtt_ms": 145,
      "created_at": 1731200000,
      "last_added_at": 1731250000,
      "last_checked_at": 1731256800
    }
  ]
  ```
- **Ошибки:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/sources" -H "X-API-Key: $KEY"
  ```

---

#### `GET /api/v1/sources/{name}`
Подробная статистика конкретного источника по его системному имени.

- **Path-параметры:** `name` *(string)* — имя источника.
- **Response `200 OK` (JSON):** одиночный объект `SourceStatsItem` (структура идентична элементу массива в `GET /api/v1/sources`).
- **Ошибки:** `400 Bad Request` (пустое имя), `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/sources/premium_pool_v1" -H "X-API-Key: $KEY"
  ```

---

#### `DELETE /api/v1/sources/{name}`
Удаление источника. Прокси, привязанные исключительно к данному источнику, удаляются каскадно.

- **Path-параметры:** `name` *(string)* — имя источника.
- **Response:** `204 No Content`.
- **Ошибки:** `400 Bad Request`, `401 Unauthorized`, `404 Not Found`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -i -X DELETE "http://127.0.0.1:3000/api/v1/sources/premium_pool_v1" -H "X-API-Key: $KEY"
  ```

---

### Группа 3: Judges

#### `GET /api/v1/judges`
Список зарегистрированных judge-серверов (встроенных и внешних fallback) с метриками доступности и приоритетами.

- **Query-параметры:** отсутствуют.
- **Response `200 OK` (JSON):**
  ```json
  [
    {
      "id": "builtin",
      "name": "Built-in Hydra Judge",
      "http_url": "http://127.0.0.1:8080",
      "https_url": "https://127.0.0.1:8443",
      "is_builtin": true,
      "priority": 0,
      "supports_anonymity": true,
      "enabled": true,
      "status": "healthy",
      "latency_ms": 12,
      "consecutive_failures": 0,
      "consecutive_successes": 48,
      "last_checked_at": 1731256800,
      "last_error": null
    }
  ]
  ```
  - `status`: `healthy`, `degraded`, `unhealthy`, `unknown`.
  - `priority`: `0` — основной (builtin), `1+` — запасные fallback-серверы.

- **Ошибки:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/judges" -H "X-API-Key: $KEY"
  ```

---

#### `POST /api/v1/judges/health-check`
Принудительный параллельный опрос доступности всех судей и перевыбор активного проверяющего узла.

- **Request Body:** отсутствует.
- **Response `200 OK` (JSON):**
  ```json
  {
    "total_judges": 4,
    "healthy_judges": 4,
    "active_judge": "builtin",
    "judges": [
      {
        "id": "builtin",
        "name": "Built-in Hydra Judge",
        "http_url": "http://127.0.0.1:8080",
        "https_url": "https://127.0.0.1:8443",
        "is_builtin": true,
        "priority": 0,
        "supports_anonymity": true,
        "enabled": true,
        "status": "healthy",
        "latency_ms": 12,
        "consecutive_failures": 0,
        "consecutive_successes": 49,
        "last_checked_at": 1731256900,
        "last_error": null
      }
    ]
  }
  ```
- **Ошибки:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s -X POST "http://127.0.0.1:3000/api/v1/judges/health-check" -H "X-API-Key: $KEY"
  ```

---

### Группа 4: Stats

#### `GET /api/v1/stats`
Глобальная сводка: метрики движка, состояние пула, качество, срезы по протоколам, анонимности, ошибкам, странам и ASN.

- **Query-параметры:** отсутствуют.
- **Response `200 OK` (JSON):**
  ```json
  {
    "engine": {
      "active_workers": 128,
      "checks_per_sec": 45.2,
      "checks_completed": 15420,
      "batch_buffer_size": 15,
      "judge_healthy": true
    },
    "pool": {
      "total": 12500,
      "alive": 8400,
      "cold_queue": 1500,
      "cooldown": 1800,
      "dead_permanent": 800
    },
    "quality": {
      "total_checks": 85000,
      "total_checks_success": 81500,
      "uptime_pct": 95.88,
      "avg_rtt_ms": 115,
      "avg_rtt_tcp_ms": 45,
      "avg_rtt_handshake_ms": 70,
      "supports_https_count": 7800,
      "with_auth_count": 2100,
      "no_auth_count": 6300,
      "total_sources": 12
    },
    "by_protocol": {
      "socks5": 5200,
      "http": 3200
    },
    "by_anonymity": {
      "elite": 6800,
      "anonymous": 1400,
      "transparent": 200
    },
    "by_error": {
      "TIMEOUT_TCP": 850,
      "CONN_REFUSED": 430,
      "HANDSHAKE_TIMEOUT": 210
    },
    "top_countries": [
      { "country": "DE", "alive_count": 3200, "avg_rtt_ms": 85 },
      { "country": "US", "alive_count": 2500, "avg_rtt_ms": 130 }
    ],
    "top_asns": [
      { "asn": 24940, "asn_org": "Hetzner Online GmbH", "alive_count": 3200, "avg_rtt_ms": 85 }
    ]
  }
  ```
- **Ошибки:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/stats" -H "X-API-Key: $KEY"
  ```

---

#### `GET /api/v1/stats/engine`
Мгновенные оперативные метрики движка из памяти (in-memory, без обращений к базе данных).

- **Query-параметры:** отсутствуют.
- **Response `200 OK` (JSON):**
  ```json
  {
    "active_workers": 128,
    "checks_per_sec": 45.2,
    "checks_completed": 15420,
    "batch_buffer_size": 15,
    "judge_healthy": true
  }
  ```
- **Ошибки:** `401 Unauthorized`, `500 Internal Server Error`.
- **cURL:**
  ```bash
  curl -s "http://127.0.0.1:3000/api/v1/stats/engine" -H "X-API-Key: $KEY"
  ```

---

### Документация OpenAPI / Swagger

- **`GET /swagger-ui`**: Интерактивный UI спецификации Swagger UI в браузере.
- **`GET /api-docs/openapi.json`**: Машиночитаемая спецификация OpenAPI 3.0.

*Оба маршрута не требуют заголовка `X-API-Key`.*

---

## 3. Ошибки API (`ApiError`)

При возникновении ошибки сервис возвращает соответствующий HTTP-статус и унифицированное тело `ApiError`:

```json
{
  "error": "not_found",
  "message": "Proxy '185.220.101.5:1080' not found"
}
```

| HTTP Status | Поле `error` | Описание |
|---|---|---|
| `400 Bad Request` | `bad_request` | Ошибка валидации параметров запроса или некорректный синтаксис JSON. |
| `401 Unauthorized` | `unauthorized` | Отсутствует либо не совпадает заголовок `X-API-Key`. |
| `404 Not Found` | `not_found` | Запрашиваемая прокси или источник не найдены в базе данных. |
| `409 Conflict` | `conflict` | Конфликт уникальности или текущего состояния сущности. |
| `500 Internal Server Error` | `internal_error` | Сбой транзакции SQLite/libsql или внутренняя ошибка рантайма. |
