# Hydra Proxy Checker API Documentation

Спецификация REST API высокопроизводительного распределенного движка верификации, классификации и управления жизненным циклом прокси-серверов **Hydra**.

Интерактивная документация Swagger UI доступна по адресу: [`/swagger-ui`](http://127.0.0.1:3000/swagger-ui), машиночитаемая OpenAPI 3.0 схема: [`/api-docs/openapi.json`](http://127.0.0.1:3000/api-docs/openapi.json).

---

## 1. Аутентификация

Все операционные эндпоинты API защищены обязательным HTTP-заголовком `X-API-Key`.
Ключ задается в конфигурационном файле `.env` переменной `API_KEY`.

```http
GET /api/v1/proxies HTTP/1.1
Host: 127.0.0.1:3000
X-API-Key: your_secure_api_key_here
```

При отсутствии заголовка или некорректном значении сервер возвращает `401 Unauthorized`:
```json
{
  "code": 401,
  "message": "Missing X-API-Key header"
}
```

---

## 2. Модель жизненного цикла прокси (Lifecycle State Machine)

Каждый прокси-сервер в базе данных находится в одном из 4 состояний:

| Значение `state` | Числовой ID | Описание |
|------------------|-------------|----------|
| `cold_queue`     | `0`         | Новая прокси, ожидает первой проверки в очереди первичного тестирования. |
| `alive`          | `1`         | Рабочая, подтвержденная judge-сервером прокси в активном пуле. Готова к выдаче клиентам. |
| `cooldown`       | `2`         | Временный сбой проверки или клиентский fail-report. Находится в карантине перед повторным речеком. |
| `dead_permanent` | `3`         | Превышен лимит последовательных сбоев (`max_dead_strikes`). Исключена из очередей речека. |

---

## 3. Справочник API эндпоинтов

### 3.1. Управление прокси-серверами (Proxies)

#### `POST /api/v1/proxies/import` — Пакетный импорт сырых прокси
Принимает прокси списком в текстовом или структурированном виде, валидирует адреса (отсекает Bogon / частные подсети), дедуплицирует, привязывает к источнику и ставит в очередь `cold_queue`.

**Тело запроса (`ImportBatchRequest`):**
```json
{
  "source": "premium_pool_v1",
  "source_url": "https://provider.example.com/api/feed.txt",
  "remark": "Primary corporate subnet proxies",
  "revive_dead": true,
  "ignore_protocol": false,
  "policy": {
    "connect_timeout_ms": 2500,
    "handshake_timeout_ms": 3500,
    "rw_timeout_ms": 4000,
    "recheck_alive_sec": 45,
    "recheck_dead_sec": 900,
    "max_dead_strikes": 3
  },
  "proxies": [
    "socks5://user:pass@185.220.101.5:1080",
    "195.154.255.3:8080",
    "194.67.210.88:9050:vendor_user:vendor_pass",
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

**Ответ (`200 OK`, `ImportBatchResponse`):**
```json
{
  "source_id": 1,
  "total_received": 4,
  "inserted_new": 3,
  "updated_existing": 1,
  "revived": 0,
  "invalid_format": 0
}
```

---

#### `GET /api/v1/proxies` — Фильтрация и выгрузка списка прокси
Возвращает список прокси с полными параметрами состояния, RTT, аптаймом, счетчиками проверок и метками времени.

**Параметры строки запроса (Query Params):**
- `state`: фильтр по статусу (`alive`, `cold_queue`, `cooldown`, `dead_permanent`, по умолчанию `alive`).
- `country`: фильтр по ISO-коду страны или списку через запятую (например, `DE` или `DE,NL,FR`).
- `exclude_country`: исключение стран через запятую (например, `RU,CN`).
- `protocol`: фильтр по сетевому протоколу (`socks5`, `http`, `socks4`).
- `anon`: фильтр по уровню анонимности (`elite`, `anonymous`, `transparent`).
- `supports_https`: boolean флаг туннелирования CONNECT для HTTPS (`true` / `false`).
- `has_auth`: boolean фильтр приватных прокси с логином/паролем (`true` — приватные, `false` — публичные).
- `max_rtt`: максимально допустимый суммарный RTT в мс.
- `min_uptime`: минимальный процент аптайма (0.0 — 100.0).
- `source`: фильтр по названию источника импорта.
- `limit`: максимальное число записей (по умолчанию 50, передайте `0` для неограниченной выгрузки всего пула).
- `offset`: смещение пагинации (по умолчанию 0).

**Ответ (`200 OK`, `Vec<ProxyShortItem>`):**
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

---

#### `GET /api/v1/proxies/{id}` — Полная карточка прокси
Возвращает исчерпывающую информацию о прокси, включая политику проверки, RTT метрики, статистику проверок и детализированные связи с источниками.

> **Примечание по URL:** ID прокси в URL должен быть URL-encoded (особенно если содержит спецсимволы `@`, `:`, `#`, `/`). Например: `/api/v1/proxies/185.22.14.20%3A8080%3Amy_user%3Ap%40ss%23word`.

**Ответ (`200 OK`, `ProxyFullDetails`):**
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
    "max_dead_strikes": 3
  },
  "stats": {
    "checks_total": 450,
    "checks_success": 445,
    "uptime_pct": 98.88,
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
      {
        "name": "premium_pool_v1",
        "added_at": 1731200000
      },
      {
        "name": "backup_tor_feed",
        "added_at": 1731210000
      }
    ]
  }
}
```

---

#### `PATCH /api/v1/proxies/{id}` — Частичное обновление прокси
Позволяет изменить пользовательскую заметку (`remark`), логин/пароль, сбросить протокол на авто-детект (`ignore_protocol: true`), изменить индивидуальную политику тайм-аутов и принудительно запланировать проверку на текущий момент (`force_recheck: true`).

**Тело запроса (`PatchProxyRequest`):**
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
    "max_dead_strikes": 2
  }
}
```
**Ответ:** `200 OK`

---

#### `DELETE /api/v1/proxies/{id}` — Удаление прокси
Удаляет прокси и её ассоциации с источниками из базы данных.
**Ответ:** `204 No Content`

---

#### `POST /api/v1/proxies/report-fail` — Экстренный репорт о сбое прокси (клиентский фидбек)
Позволяет внешним клиентам (скрейперам, прокси-шлюзам) мгновенно уведомить систему о сбое одиночного или группы прокси. Прокси переводятся в статус `cooldown`, увеличивается счетчик `dead_strikes`, и назначается внеочередная проверка.

**Тело запроса (`ReportFailRequest`):**
```json
{
  "ids": [
    "185.220.101.5:1080:myuser:mypassword",
    "195.154.255.3:8080"
  ],
  "reason": "Connection reset by peer during target handshake"
}
```
**Ответ (`200 OK`, `ReportFailResponse`):**
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

---

### 3.2. Управление источниками (Sources)

#### `GET /api/v1/sources` — Список источников с метриками эффективности
Возвращает статистику по каждому источнику: процент выхода живых прокси (yield %), распределение по статусам, среднюю задержку, дату создания и временные метки активности.

**Ответ (`200 OK`, `Vec<SourceStatsItem>`):**
```json
[
  {
    "id": 1,
    "name": "premium_pool_v1",
    "url": "https://provider.example.com/api/feed.txt",
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

---

#### `GET /api/v1/sources/{name}` — Детальная статистика конкретного источника
Возвращает полную статистику и показатели выхода для источника по его имени. Если источник не найден — `404 Not Found`.

**Ответ (`200 OK`, `SourceStatsItem`):**
```json
{
  "id": 1,
  "name": "premium_pool_v1",
  "url": "https://provider.example.com/api/feed.txt",
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
```

---

#### `DELETE /api/v1/sources/{name}` — Удаление источника
Удаляет источник из базы данных. Прокси, привязанные исключительно к этому источнику, каскадно удаляются.
**Ответ:** `204 No Content`

---

### 3.3. Глобальная телеметрия и статистика (Stats)

#### `GET /api/v1/stats` — Телеметрия движка, состояние пула и метрики качества
Возвращает полную сводку в реальном времени:
- **`engine`**: производительность движка (активные воркеры, проверки/сек, суммарно выполненные проверки, размер очереди батч-райтера, доступность judge).
- **`pool`**: общее распределение пула по статусам (`total`, `alive`, `cold_queue`, `cooldown`, `dead_permanent`).
- **`quality`**: качество пула (суммарные проверки, процент аптайма, средний RTT по фазам: общий / TCP / Handshake, количество с поддержкой HTTPS, распределение приватных и публичных прокси, общее число источников).
- **`by_protocol`**: распределение живых прокси по протоколам (`socks5`, `http`, `socks4`).
- **`by_anonymity`**: распределение по уровням анонимности (`elite`, `anonymous`, `transparent`).
- **`by_error`**: топ причин сбоев и ошибок проверок (`TIMEOUT_TCP`, `CONN_REFUSED`, `HANDSHAKE_TIMEOUT` и др.).
- **`top_countries`**: рейтинг стран по количеству живых прокси и средней задержке.
- **`top_asns`**: рейтинг интернет-провайдеров / автономных систем (ASN) по количеству живых прокси и средней задержке.

**Ответ (`200 OK`, `GlobalStatsResponse`):**
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
    {
      "country": "DE",
      "alive_count": 3200,
      "avg_rtt_ms": 85
    },
    {
      "country": "US",
      "alive_count": 2500,
      "avg_rtt_ms": 130
    },
    {
      "country": "NL",
      "alive_count": 1400,
      "avg_rtt_ms": 75
    }
  ],
  "top_asns": [
    {
      "asn": 24940,
      "asn_org": "Hetzner Online GmbH",
      "alive_count": 3200,
      "avg_rtt_ms": 85
    },
    {
      "asn": 14061,
      "asn_org": "DigitalOcean, LLC",
      "alive_count": 1500,
      "avg_rtt_ms": 95
    }
  ]
}
```

---

### 3.4. Управление судьями (Judges)

#### `GET /api/v1/judges` — Список всех judge-серверов и их доступность
Возвращает список встроенного judge и внешних fallback-серверов с их приоритетами, текущим статусом (`healthy`, `degraded`, `unhealthy`, `unknown`), задержкой и счетчиками успехов/сбоев.

**Ответ (`200 OK`, `Vec<JudgeReportDto>`):**
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

---

#### `POST /api/v1/judges/health-check` — Принудительная проверка доступности всех судей
Запускает одновременную параллельную проверку доступности всех зарегистрированных судей в пуле и возвращает обновленный отчет.

**Ответ (`200 OK`, `JudgeHealthCheckResponse`):**
```json
{
  "total_judges": 4,
  "healthy_judges": 4,
  "active_judge": "builtin",
  "judges": [ ... ]
}
```
