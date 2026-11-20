PRAGMA auto_vacuum = INCREMENTAL;

-- ============================================================
-- Table 1: sources (catalog of proxy lists/sources)
-- ============================================================
CREATE TABLE IF NOT EXISTS sources (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT    UNIQUE NOT NULL,       -- "github_monosans", "private_premium"
    url         TEXT,                          -- List URL (optional)
    remark      TEXT,                          -- User note/remark
    created_at  INTEGER NOT NULL               -- Creation Unix timestamp
);

-- ============================================================
-- Table 2: proxies (core inventory + state + metrics)
-- ============================================================
-- WITHOUT ROWID: Clustered index on TEXT PK for O(log n) lookup by ip:port.
CREATE TABLE IF NOT EXISTS proxies (
    -- === Identification and Access ===
    id              TEXT    PRIMARY KEY,       -- "185.22.14.9:1080" (clustered PK)
    ip              TEXT    NOT NULL,           -- Inbound IPv4 / IPv6
    port            INTEGER NOT NULL,          -- 1..65535
    auth_user       TEXT,                      -- Username (for private proxies)
    auth_pass       TEXT,                      -- Password

    -- === Lifecycle ===
    -- 0=cold_queue, 1=alive, 2=cooldown, 3=dead_permanent
    state           INTEGER NOT NULL DEFAULT 0,

    -- === Network Characteristics (populated by checker) ===
    protocol        TEXT,                      -- "http"|"https"|"socks4"|"socks4a"|"socks5"
    supports_https  INTEGER NOT NULL DEFAULT 0,-- 1 = proxy can tunnel HTTPS
    out_ip          TEXT,                      -- Outbound IP via Judge
    country         TEXT,                      -- ISO 3166-1 alpha-2: "DE", "US"
    asn             INTEGER,                   -- Provider AS number
    asn_org         TEXT,                      -- ASN organization name: "Hetzner Online GmbH"
    anon            TEXT,                      -- "transparent"|"anonymous"|"elite"

    -- === Detailed RTT Metrics (ms) ===
    rtt_tcp_ms      INTEGER,                   -- TCP SYN/SYN-ACK latency
    rtt_handshake_ms INTEGER,                  -- Protocol tunnel negotiation time
    rtt_total_ms    INTEGER,                   -- Total check time (L4 → L7 Judge)

    -- === Verification Policy ===
    connect_timeout_ms   INTEGER NOT NULL DEFAULT 3000,  -- L4 TCP connect timeout
    handshake_timeout_ms INTEGER NOT NULL DEFAULT 4000,  -- Protocol handshake timeout
    rw_timeout_ms        INTEGER NOT NULL DEFAULT 5000,  -- L7 read/write timeout
    recheck_alive_sec    INTEGER NOT NULL DEFAULT 60,    -- Alive proxy recheck interval
    recheck_dead_sec     INTEGER NOT NULL DEFAULT 1800,  -- Dead proxy cooldown interval (0 = do not recheck)
    max_dead_strikes_zero INTEGER NOT NULL DEFAULT 3,    -- Failure threshold for zero-uptime proxies (checks_success == 0)
    max_dead_strikes_active INTEGER NOT NULL DEFAULT 3,  -- Failure threshold for active proxies (checks_success > 0)
    stability_window_min INTEGER NOT NULL DEFAULT 5,     -- Stability window (in minutes)
    dead_backoff_mult_zero REAL NOT NULL DEFAULT 1.5,    -- Exponential backoff multiplier for zero-uptime proxies (checks_success == 0)
    dead_backoff_mult_active REAL NOT NULL DEFAULT 1.5,  -- Exponential backoff multiplier for active proxies (checks_success > 0)

    -- === Statistics ===
    checks_total    INTEGER NOT NULL DEFAULT 0,
    checks_success  INTEGER NOT NULL DEFAULT 0,
    dead_strikes    INTEGER NOT NULL DEFAULT 0,  -- Consecutive failure counter
    last_error      TEXT,                        -- "TIMEOUT_TCP", "CONN_REFUSED", etc.
    stability_pct   REAL NOT NULL DEFAULT 0.0,   -- Stability percentage within window (0.0 - 100.0)
    recent_checks   TEXT,                        -- Compact recent check history in window (ts:status,...)

    -- === Metadata ===
    remark          TEXT,                        -- User note/remark
    first_seen_at   INTEGER NOT NULL,            -- Initial discovery Unix timestamp
    last_checked_at INTEGER,                     -- Last check Unix timestamp
    next_check_at   INTEGER NOT NULL             -- Next scheduled check Unix timestamp
) WITHOUT ROWID;

-- ============================================================
-- Table 3: proxy_sources (M:N proxy <-> source relationships)
-- ============================================================
CREATE TABLE IF NOT EXISTS proxy_sources (
    proxy_id    TEXT    NOT NULL REFERENCES proxies(id) ON DELETE CASCADE,
    source_id   INTEGER NOT NULL REFERENCES sources(id) ON DELETE CASCADE,
    added_at    INTEGER NOT NULL,               -- When proxy was discovered from this source
    PRIMARY KEY (proxy_id, source_id)
) WITHOUT ROWID;

-- ============================================================
-- Indexes
-- ============================================================

-- I1: Scheduler — legacy index for fallback queries
CREATE INDEX IF NOT EXISTS idx_scheduler_prio
    ON proxies ((CASE state WHEN 1 THEN 0 WHEN 0 THEN 1 ELSE 2 END), next_check_at)
    WHERE state IN (0, 1, 2);

-- I1b: Scheduler Cold Queue — selects cold proxies (state=0) ordered by due next_check_at and first_seen_at.
CREATE INDEX IF NOT EXISTS idx_cold_queue
    ON proxies (next_check_at ASC, first_seen_at ASC)
    WHERE state = 0;

-- I1c: Scheduler Recheck Queue — selects recheck proxies (alive=0, cooldown=1) ordered by priority and waiting time.
CREATE INDEX IF NOT EXISTS idx_recheck_queue
    ON proxies ((CASE state WHEN 1 THEN 0 ELSE 1 END), next_check_at ASC)
    WHERE state IN (1, 2);

-- I2: Instant retrieval of fastest alive proxies (eliminates USE TEMP B-TREE FOR ORDER BY in GET /api/v1/proxies).
CREATE INDEX IF NOT EXISTS idx_alive_fastest
    ON proxies (rtt_total_ms ASC)
    WHERE state = 1;

-- I3: Proxy Gateway / API filtering — instant lookup of alive proxies by filter attributes.
CREATE INDEX IF NOT EXISTS idx_alive_routing
    ON proxies (country, protocol, anon, rtt_total_ms)
    WHERE state = 1;

-- I3b: Instant lookup and sorting by country (GET /api/v1/proxies?country=XX).
CREATE INDEX IF NOT EXISTS idx_alive_country_rtt
    ON proxies (country, rtt_total_ms ASC)
    WHERE state = 1;

-- I4: Outbound IP lookup (for egress IP deduplication / anti-fraud).
CREATE INDEX IF NOT EXISTS idx_out_ip
    ON proxies (out_ip)
    WHERE out_ip IS NOT NULL;

-- I5: Partial index for fast cleanup of dead proxies during maintenance without scanning full proxies table.
CREATE INDEX IF NOT EXISTS idx_dead_purge
    ON proxies (last_checked_at)
    WHERE state = 3;

-- I6: proxy_sources relations (FK lookup on source deletion).
CREATE INDEX IF NOT EXISTS idx_ps_source
    ON proxy_sources (source_id);

-- I7: Fast selection of alive proxies ordered by stability percentage within window.
CREATE INDEX IF NOT EXISTS idx_alive_stability
    ON proxies (stability_pct DESC, rtt_total_ms ASC)
    WHERE state = 1;
