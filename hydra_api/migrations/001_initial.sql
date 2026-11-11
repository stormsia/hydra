PRAGMA auto_vacuum = INCREMENTAL;

-- ============================================================
-- Таблица 1: sources (справочник листов/источников прокси)
-- ============================================================
CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    UNIQUE NOT NULL,       -- "github_monosans", "private_premium"
    url         TEXT,                          -- URL листа (опционально)
    remark      TEXT,                          -- пользовательская заметка
    created_at  INTEGER NOT NULL               -- Unix timestamp создания
);

-- ============================================================
-- Таблица 2: proxies (основной инвентарь + состояние + метрики)
-- ============================================================
-- WITHOUT ROWID: кластерный индекс по TEXT PK для O(log n) поиска по ip:port.
CREATE TABLE IF NOT EXISTS proxies (
    -- === Идентификация и доступ ===
    id              TEXT    PRIMARY KEY,       -- "185.22.14.9:1080" (кластерный ключ)
    ip              TEXT    NOT NULL,           -- входной IPv4 / IPv6
    port            INTEGER NOT NULL,          -- 1..65535
    auth_user       TEXT,                      -- логин (для приватных прокси)
    auth_pass       TEXT,                      -- пароль

    -- === Жизненный цикл ===
    -- 0=cold_queue, 1=alive, 2=cooldown, 3=dead_permanent
    state           INTEGER NOT NULL DEFAULT 0,

    -- === Сетевые характеристики (заполняются чекером) ===
    protocol        TEXT,                      -- "http"|"https"|"socks4"|"socks4a"|"socks5"
    supports_https  INTEGER NOT NULL DEFAULT 0,-- 1 = прокси умеет тунелировать HTTPS
    out_ip          TEXT,                      -- выходной IP через Judge
    country         TEXT,                      -- ISO 3166-1 alpha-2: "DE", "US"
    asn             INTEGER,                   -- AS number провайдера
    asn_org         TEXT,                      -- название организации ASN: "Hetzner Online GmbH"
    anon            TEXT,                      -- "transparent"|"anonymous"|"elite"

    -- === Детализированные метрики RTT (мс) ===
    rtt_tcp_ms      INTEGER,                   -- TCP SYN/SYN-ACK latency
    rtt_handshake_ms INTEGER,                  -- Protocol tunnel negotiation time
    rtt_total_ms    INTEGER,                   -- Total check time (L4 → L7 Judge)

    -- === Политика проверки ===
    connect_timeout_ms   INTEGER NOT NULL DEFAULT 3000,  -- L4 TCP connect timeout
    handshake_timeout_ms INTEGER NOT NULL DEFAULT 4000,  -- Protocol handshake timeout
    rw_timeout_ms        INTEGER NOT NULL DEFAULT 5000,  -- L7 read/write timeout
    recheck_alive_sec    INTEGER NOT NULL DEFAULT 60,    -- интервал речека живых
    recheck_dead_sec     INTEGER NOT NULL DEFAULT 1800,  -- карантин мёртвых (0 = не речекать)
    max_dead_strikes     INTEGER NOT NULL DEFAULT 3,     -- лимит ошибок до dead_permanent

    -- === Статистика ===
    checks_total    INTEGER NOT NULL DEFAULT 0,
    checks_success  INTEGER NOT NULL DEFAULT 0,
    dead_strikes    INTEGER NOT NULL DEFAULT 0,  -- текущий счётчик ошибок подряд
    last_error      TEXT,                        -- "TIMEOUT_TCP", "CONN_REFUSED", etc.

    -- === Метаданные ===
    remark          TEXT,                        -- пользовательская заметка
    first_seen_at   INTEGER NOT NULL,            -- Unix timestamp первого обнаружения
    last_checked_at INTEGER,                     -- Unix timestamp последнего чека
    next_check_at   INTEGER NOT NULL             -- Unix timestamp следующего чека
) WITHOUT ROWID;

-- ============================================================
-- Таблица 3: proxy_sources (M:N связь прокси ↔ источники)
-- ============================================================
CREATE TABLE IF NOT EXISTS proxy_sources (
    proxy_id    TEXT    NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
    source_id   INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    added_at    INTEGER NOT NULL,               -- когда прокси замечена в этом источнике
    PRIMARY KEY (proxy_id, source_id)
) WITHOUT ROWID;

-- ============================================================
-- Индексы
-- ============================================================

-- I1: Планировщик — выбирает прокси с приоритетом (alive=0, cold=1, cooldown=2) и наступившим next_check_at.
-- Устраняет временную сортировку (TEMP B-TREE) в fetch_due_proxies.
CREATE INDEX IF NOT EXISTS idx_scheduler_prio
    ON proxies ((CASE state WHEN 1 THEN 0 WHEN 0 THEN 1 ELSE 2 END), next_check_at)
    WHERE state IN (0, 1, 2);

-- I2: Мгновенная отдача быстрых живых прокси (устраняет USE TEMP B-TREE FOR ORDER BY при базовом GET /api/v1/proxies).
CREATE INDEX IF NOT EXISTS idx_alive_fastest
    ON proxies (rtt_total_ms ASC)
    WHERE state = 1;

-- I3: Прокси-Шлюз / API фильтрация — мгновенная выборка живых прокси по фильтрам.
CREATE INDEX IF NOT EXISTS idx_alive_routing
    ON proxies (country, protocol, anon, rtt_total_ms)
    WHERE state = 1;

-- I3b: Мгновенная выборка и сортировка по стране (GET /api/v1/proxies?country=XX).
CREATE INDEX IF NOT EXISTS idx_alive_country_rtt
    ON proxies (country, rtt_total_ms ASC)
    WHERE state = 1;

-- I4: Поиск по out_ip (для дедупликации по выходному IP / анти-фрод).
CREATE INDEX IF NOT EXISTS idx_out_ip
    ON proxies (out_ip)
    WHERE out_ip IS NOT NULL;

-- I5: Частичный индекс для быстрой очистки мертвых прокси в maintenance без full scan таблицы proxies.
CREATE INDEX IF NOT EXISTS idx_dead_purge
    ON proxies (last_checked_at)
    WHERE state = 3;

-- I6: Связи proxy_sources (FK lookup при удалении источника).
CREATE INDEX IF NOT EXISTS idx_ps_source
    ON proxy_sources (source_id);
