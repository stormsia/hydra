use std::collections::HashMap;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use super::db::ProxyState;

fn default_connect_timeout() -> u32 { 3000 }
fn default_handshake_timeout() -> u32 { 4000 }
fn default_rw_timeout() -> u32 { 5000 }
fn default_recheck_alive() -> u32 { 60 }
fn default_recheck_dead() -> u32 { 1800 }
fn default_max_strikes() -> u32 { 3 }
fn default_stability_window_min() -> u32 { 5 }
fn default_dead_backoff_mult() -> f32 { 1.5 }

/// Политика тайм-аутов и расписания проверок прокси-серверов
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq)]
#[schema(example = json!({
    "connect_timeout_ms": 3000,
    "handshake_timeout_ms": 4000,
    "rw_timeout_ms": 5000,
    "recheck_alive_sec": 60,
    "recheck_dead_sec": 1800,
    "max_dead_strikes": 3,
    "stability_window_min": 5,
    "dead_backoff_mult": 1.5
}))]
pub struct CheckPolicyDto {
    /// Предельное время установки TCP-соединения (в миллисекундах)
    #[serde(default = "default_connect_timeout")]
    #[schema(example = 3000, minimum = 100, maximum = 60000, default = 3000)]
    pub connect_timeout_ms: u32,

    /// Предельное время завершения SSL/TLS или протокольного рукопожатия (в миллисекундах)
    #[serde(default = "default_handshake_timeout")]
    #[schema(example = 4000, minimum = 100, maximum = 60000, default = 4000)]
    pub handshake_timeout_ms: u32,

    /// Тайм-аут на чтение/запись данных при валидации через тестовый judge (в миллисекундах)
    #[serde(default = "default_rw_timeout")]
    #[schema(example = 5000, minimum = 100, maximum = 60000, default = 5000)]
    pub rw_timeout_ms: u32,

    /// Интервал регулярной фоновой перепроверки живых прокси (в секундах)
    #[serde(default = "default_recheck_alive")]
    #[schema(example = 60, minimum = 10, maximum = 86400, default = 60)]
    pub recheck_alive_sec: u32,

    /// Интервал перепроверки прокси в карантине (в секундах)
    #[serde(default = "default_recheck_dead")]
    #[schema(example = 1800, minimum = 30, maximum = 604800, default = 1800)]
    pub recheck_dead_sec: u32,

    /// Количество последовательных сбоев до отправки прокси в статус dead_permanent
    #[serde(default = "default_max_strikes")]
    #[schema(example = 3, minimum = 1, maximum = 50, default = 3)]
    pub max_dead_strikes: u32,

    /// Окно расчета показателя стабильности (в минутах, по умолчанию: 5)
    #[serde(default = "default_stability_window_min", alias = "stability_window", alias = "window_min", alias = "window_minutes")]
    #[schema(example = 5, minimum = 1, maximum = 1440, default = 5)]
    pub stability_window_min: u32,

    /// Множитель экспоненциального увеличения задержки речека для мертвых прокси в карантине (cooldown)
    #[serde(default = "default_dead_backoff_mult", alias = "backoff_multiplier", alias = "recheck_dead_multiplier", alias = "dead_multiplier", alias = "recheck_dead_mult", alias = "multiplier")]
    #[schema(example = 1.5, minimum = 1.0, maximum = 10.0, default = 1.5)]
    pub dead_backoff_mult: f32,
}

impl Default for CheckPolicyDto {
    fn default() -> Self {
        Self {
            connect_timeout_ms: default_connect_timeout(),
            handshake_timeout_ms: default_handshake_timeout(),
            rw_timeout_ms: default_rw_timeout(),
            recheck_alive_sec: default_recheck_alive(),
            recheck_dead_sec: default_recheck_dead(),
            max_dead_strikes: default_max_strikes(),
            stability_window_min: default_stability_window_min(),
            dead_backoff_mult: default_dead_backoff_mult(),
        }
    }
}

/// Структурированные параметры прокси при импорте
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "ip": "185.220.101.5",
    "port": 1080,
    "protocol": "socks5",
    "auth_user": "myuser",
    "auth_pass": "mypassword",
    "ignore_protocol": false
}))]
pub struct ProxyInputObject {
    /// IP-адрес хоста прокси (IPv4 или IPv6)
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub ip: String,

    /// Порт подключения (1..=65535)
    #[schema(example = 1080, minimum = 1, maximum = 65535)]
    pub port: u16,

    /// Ожидаемый протокол прокси (например: socks5, http, socks4)
    #[schema(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Логин пользователя для авторизации на приватном прокси
    #[schema(example = "myuser", max_length = 128)]
    pub auth_user: Option<String>,

    /// Пароль пользователя для авторизации на приватном прокси
    #[schema(example = "mypassword", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Игнорировать указанный протокол и перебирать в режиме авто-детекта (каскад)
    #[serde(default, alias = "ignore_type")]
    #[schema(example = false, default = false)]
    pub ignore_protocol: Option<bool>,
}

/// Элемент входного массива импорта: текстовая строка любого формата или структурированный JSON-объект
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[serde(untagged)]
pub enum ProxyInputItem {
    /// Текстовая строка в поддерживаемых форматах:
    /// - `protocol://user:pass@ip:port`
    /// - `ip:port:user:pass`
    /// - `user:pass@ip:port`
    /// - `protocol://ip:port`
    /// - `ip:port`
    /// - `[ipv6]:port`
    #[schema(example = "socks5://user:pass@185.220.101.5:1080")]
    String(String),

    /// Структурированный объект с явными полями хоста, порта и авторизации
    Object(ProxyInputObject),
}

impl From<String> for ProxyInputItem {
    fn from(s: String) -> Self {
        ProxyInputItem::String(s)
    }
}

impl From<&str> for ProxyInputItem {
    fn from(s: &str) -> Self {
        ProxyInputItem::String(s.to_string())
    }
}

/// Запрос на пакетный импорт сырых прокси-адресов
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
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
        "max_dead_strikes": 3,
        "stability_window_min": 5,
        "dead_backoff_mult": 1.5
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
}))]
pub struct ImportBatchRequest {
    /// Уникальное кодовое имя источника импорта (например, "free_spys_ru", "vendor_pack_1")
    #[schema(example = "premium_pool_v1", min_length = 1, max_length = 128)]
    pub source: String,

    /// URL-адрес внешнего фида или API источника (если применимо)
    #[schema(example = "https://provider.example.com/api/feed.txt", max_length = 2048)]
    pub source_url: Option<String>,

    /// Пользовательская заметка или комментарий к источнику
    #[schema(example = "Primary corporate subnet proxies", max_length = 512)]
    pub remark: Option<String>,

    /// Сбрасывать ли счетчик ошибок и воскрешать прокси, находившиеся в статусе dead_permanent
    #[serde(default)]
    #[schema(example = true, default = false)]
    pub revive_dead: bool,

    /// Флаг игнорирования указанного типа/протокола: если true, принудительно перебирать прокси в режиме авто-детекта (SOCKS5 -> SOCKS4 -> HTTP)
    #[serde(default, alias = "ignore_type")]
    #[schema(example = false, default = false)]
    pub ignore_protocol: bool,

    /// Индивидуальная политика проверки для импортируемого пула
    #[serde(default)]
    pub policy: CheckPolicyDto,

    /// Массив прокси. Поддерживаются как текстовые строки (с авторизацией и без):
    /// - `protocol://user:pass@ip:port`
    /// - `ip:port:user:pass`
    /// - `user:pass@ip:port`
    /// - `protocol://ip:port`
    /// - `ip:port`
    /// - `[ipv6]:port`
    ///
    /// так и структурированные JSON-объекты `{"ip": "...", "port": ..., "auth_user": "...", "auth_pass": "..."}`
    #[schema(example = json!(["socks5://user:pass@185.220.101.5:1080", "195.154.255.3:8080"]))]
    pub proxies: Vec<ProxyInputItem>,
}

/// Параметры фильтрации и пагинации списка прокси
#[derive(Debug, Clone, Default, Serialize, Deserialize, IntoParams)]
pub struct ProxyFilterQuery {
    /// Фильтр по текущему состоянию жизненного цикла
    #[param(example = "alive")]
    pub state: Option<ProxyState>,

    /// Двухбуквенный ISO 3166-1 alpha-2 код страны или список кодов через запятую (например, "DE" или "DE,NL,FR" для региональной выборки)
    #[param(example = "DE,NL,FR", min_length = 2, max_length = 128)]
    pub country: Option<String>,

    /// Исключить страны из выборки (ISO 3166-1 alpha-2 коды через запятую, например, "RU,CN")
    #[param(example = "RU,CN", min_length = 2, max_length = 128)]
    pub exclude_country: Option<String>,

    /// Сетевой протокол прокси (например, "socks5", "http", "socks4")
    #[param(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Уровень анонимности (elite, anonymous, transparent)
    #[param(example = "elite", max_length = 16)]
    pub anon: Option<String>,

    /// Поддержка CONNECT туннелирования для HTTPS
    #[param(example = true)]
    pub supports_https: Option<bool>,

    /// Фильтр по наличию авторизации (true — только приватные с логином/паролем, false — только публичные без авторизации)
    #[param(example = false)]
    pub has_auth: Option<bool>,

    /// Максимально допустимый суммарный RTT в миллисекундах
    #[param(example = 350, minimum = 1, maximum = 60000)]
    pub max_rtt: Option<u32>,

    /// Минимальный процент аптайма (0.0 — 100.0)
    #[param(example = 95.0, minimum = 0.0, maximum = 100.0)]
    pub min_uptime: Option<f32>,

    /// Минимальный процент стабильности в рамках плавающего окна N минут (0.0 — 100.0)
    #[param(example = 90.0, minimum = 0.0, maximum = 100.0)]
    pub min_stability: Option<f32>,

    /// Фильтр по размеру окна расчета стабильности (в минутах)
    #[param(example = 5, minimum = 1, maximum = 1440)]
    pub stability_window_min: Option<u32>,

    /// Фильтр по названию источника импорта
    #[param(example = "premium_pool_v1", min_length = 1, max_length = 128)]
    pub source: Option<String>,

    /// Максимальное количество записей в ответе (по умолчанию: 50, передайте 0 для неограниченной выгрузки всех прокси пула для Gateway)
    #[param(example = 50, minimum = 0, maximum = 100000, default = 50)]
    pub limit: Option<u32>,

    /// Смещение для пагинации результатов
    #[param(example = 0, minimum = 0, default = 0)]
    pub offset: Option<u32>,
}

/// Запрос на экстренное сообщение о сбое прокси из клиентского приложения (одиночный или пакетный)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "185.220.101.5:1080:myuser:mypassword",
    "ids": ["185.220.101.5:1080:myuser:mypassword", "195.154.255.3:8080"],
    "reason": "Connection reset by peer during target handshake"
}))]
pub struct ReportFailRequest {
    /// Одиночный идентификатор прокси (в формате `ip:port` или `ip:port:login:pwd`)
    #[schema(example = "185.220.101.5:1080:myuser:mypassword", max_length = 256)]
    pub id: Option<String>,

    /// Массив идентификаторов прокси для пакетной отправки сбоев (например, при падении узла провайдера)
    #[schema(example = json!(["185.220.101.5:1080:myuser:mypassword", "195.154.255.3:8080"]))]
    pub ids: Option<Vec<String>>,

    /// Причина или стек ошибки, зафиксированный клиентом
    #[schema(example = "Connection reset by peer during target handshake", min_length = 1, max_length = 1024)]
    pub reason: String,
}

/// Результат фиксации клиентского сбоя прокси
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "status": "reported",
    "affected_count": 2,
    "reported_ids": ["185.220.101.5:1080:myuser:mypassword", "195.154.255.3:8080"],
    "proxy_id": "185.220.101.5:1080:myuser:mypassword"
}))]
pub struct ReportFailResponse {
    /// Статус операции подтверждения регистрации сбоя
    #[schema(example = "reported", min_length = 1, max_length = 64)]
    pub status: String,

    /// Количество прокси, успешно переведенных в карантин (cooldown)
    #[schema(example = 2, minimum = 0)]
    pub affected_count: usize,

    /// Массив идентификаторов прокси, для которых зафиксирован сбой
    pub reported_ids: Vec<String>,

    /// Идентификатор прокси (сохраняется для обратной совместимости при одиночных запросах)
    #[schema(example = "185.220.101.5:1080:myuser:mypassword")]
    pub proxy_id: Option<String>,
}

/// Запрос на частичное обновление параметров прокси-сервера
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
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
        "dead_backoff_mult": 1.5
    }
}))]
pub struct PatchProxyRequest {
    /// Обновленный комментарий / заметка к прокси
    #[schema(example = "Reserved for scraper worker #4", max_length = 512)]
    pub remark: Option<String>,

    /// Логин пользователя для авторизации на приватном прокси
    #[schema(example = "myuser", max_length = 128)]
    pub auth_user: Option<String>,

    /// Пароль пользователя для авторизации на приватном прокси
    #[schema(example = "mypassword", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Сбросить протокол на авто-детект (каскадный перебор SOCKS5 -> SOCKS4 -> HTTP)
    #[serde(default, alias = "ignore_type")]
    #[schema(example = false, default = false)]
    pub ignore_protocol: Option<bool>,

    /// Обновленная политика тайм-аутов и периодичности проверок
    pub policy: Option<CheckPolicyDto>,

    /// Принудительно запланировать проверку прокси на текущий момент времени
    #[schema(example = true, default = false)]
    pub force_recheck: Option<bool>,
}

/// Результат обработки пакета сырых прокси
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "source_id": 1,
    "total_received": 100,
    "inserted_new": 78,
    "updated_existing": 20,
    "revived": 5,
    "invalid_format": 2
}))]
pub struct ImportBatchResponse {
    /// Первичный ключ источника в базе данных
    #[schema(example = 1, minimum = 1)]
    pub source_id: i64,

    /// Общее количество строк, переданных в запросе
    #[schema(example = 100, minimum = 0)]
    pub total_received: usize,

    /// Количество новых уникальных прокси, добавленных в очередь
    #[schema(example = 78, minimum = 0)]
    pub inserted_new: usize,

    /// Количество уже существовавших прокси, привязанных к новому источнику
    #[schema(example = 20, minimum = 0)]
    pub updated_existing: usize,

    /// Количество реанимированных прокси (переведенных из dead_permanent в cold_queue)
    #[schema(example = 5, minimum = 0)]
    pub revived: usize,

    /// Количество строк с некорректным форматом адреса или bogon IP
    #[schema(example = 2, minimum = 0)]
    pub invalid_format: usize,
}

/// Краткая информация о прокси в выборках и списках
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
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
}))]
pub struct ProxyShortItem {
    /// Полный уникальный идентификатор прокси (`ip:port` или `ip:port:login:pwd`)
    #[schema(example = "185.220.101.5:1080:user:secret123", min_length = 3, max_length = 256)]
    pub id: String,

    /// IP-адрес хоста прокси
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub ip: String,

    /// Порт подключения
    #[schema(example = 1080, minimum = 1, maximum = 65535)]
    pub port: u16,

    /// Готовый URL для подключения (содержит логин и пароль при наличии)
    #[schema(example = "socks5://user:secret123@185.220.101.5:1080", min_length = 7, max_length = 512)]
    pub url: String,

    /// Определенный сетевой протокол (socks5, socks4, http) или null, если еще не определен (в очереди cold_queue)
    #[schema(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Флаг наличия учетных данных авторизации (логин/пароль)
    #[schema(example = true)]
    pub has_auth: bool,

    /// Логин пользователя для авторизации (если прокси приватный)
    #[schema(example = "user", max_length = 128)]
    pub auth_user: Option<String>,

    /// Пароль пользователя для авторизации (если прокси приватный)
    #[schema(example = "secret123", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Текущее состояние жизненного цикла прокси в пуле (cold_queue, alive, cooldown, dead_permanent)
    pub state: ProxyState,

    /// Флаг поддержки туннелирования CONNECT для HTTPS
    #[schema(example = true)]
    pub supports_https: bool,

    /// Реальный исходящий IP-адрес, зафиксированный тестовым Judge
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub out_ip: Option<String>,

    /// Двухбуквенный ISO-код страны местонахождения
    #[schema(example = "DE", min_length = 2, max_length = 2)]
    pub country: Option<String>,

    /// Номер автономной системы (BGP ASN)
    #[schema(example = 24940, minimum = 1)]
    pub asn: Option<u32>,

    /// Название провайдера / владельца автономной системы
    #[schema(example = "Hetzner Online GmbH", max_length = 256)]
    pub asn_org: Option<String>,

    /// Уровень анонимности: elite (высокая), anonymous, transparent (прозрачная) или null, если еще не проверена
    #[schema(example = "elite", max_length = 16)]
    pub anon: Option<String>,

    /// Время установки базового TCP соединения (RTT в миллисекундах)
    #[schema(example = 42, minimum = 0)]
    pub rtt_tcp_ms: Option<u32>,

    /// Время завершения протокольного рукопожатия (в миллисекундах)
    #[schema(example = 68, minimum = 0)]
    pub rtt_handshake_ms: Option<u32>,

    /// Суммарная задержка до получения ответа от judge (в миллисекундах)
    #[schema(example = 110, minimum = 0)]
    pub rtt_total_ms: Option<u32>,

    /// Процент успешных проверок за все время жизни
    #[schema(example = 98.5, minimum = 0.0, maximum = 100.0)]
    pub uptime_pct: f32,

    /// Процент стабильности успешных проверок в рамках плавающего окна N минут (0.0 — 100.0)
    #[schema(example = 100.0, minimum = 0.0, maximum = 100.0)]
    pub stability_pct: f32,

    /// Окно расчета показателя стабильности (в минутах)
    #[schema(example = 5, minimum = 1, maximum = 1440, default = 5)]
    pub stability_window_min: u32,

    /// Общее количество выполненных проверок
    #[schema(example = 450, minimum = 0)]
    pub checks_total: u64,

    /// Количество успешных проверок
    #[schema(example = 445, minimum = 0)]
    pub checks_success: u64,

    /// Текущее число последовательных сбоев подряд
    #[schema(example = 0, minimum = 0)]
    pub dead_strikes: u32,

    /// Текст последней зафиксированной ошибки (если была)
    #[schema(example = "Connection timeout after 3000ms", max_length = 1024)]
    pub last_error: Option<String>,

    /// Пользовательская заметка / тег
    #[schema(example = "High performance German node", max_length = 512)]
    pub remark: Option<String>,

    /// Unix-timestamp первого обнаружения прокси в системе (в секундах)
    #[schema(example = 1731200000, minimum = 0)]
    pub first_seen_at: i64,

    /// Unix-timestamp последней завершенной проверки (в секундах)
    #[schema(example = 1731256800, minimum = 0)]
    pub last_checked_at: Option<i64>,

    /// Unix-timestamp запланированной следующей проверки (в секундах)
    #[schema(example = 1731256860, minimum = 0)]
    pub next_check_at: i64,
}

/// Полная карточка прокси со всей историей, метриками и источниками
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
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
        "sources": ["premium_pool_v1", "backup_tor_feed"]
    }
}))]
pub struct ProxyFullDetails {
    /// Полный уникальный идентификатор в формате `ip:port` или `ip:port:login:pwd`
    #[schema(example = "185.220.101.5:1080:user:secret123", min_length = 3, max_length = 256)]
    pub id: String,

    /// IP-адрес входящего хоста
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub ip: String,

    /// Порт подключения
    #[schema(example = 1080, minimum = 1, maximum = 65535)]
    pub port: u16,

    /// Форматированный URL подключения
    #[schema(example = "socks5://user:secret123@185.220.101.5:1080", min_length = 7, max_length = 512)]
    pub url: String,

    /// Флаг наличия учетных данных (логин/пароль)
    #[schema(example = true)]
    pub has_auth: bool,

    /// Логин пользователя для авторизации
    #[schema(example = "user", max_length = 128)]
    pub auth_user: Option<String>,

    /// Пароль пользователя для авторизации
    #[schema(example = "secret123", max_length = 128)]
    pub auth_pass: Option<String>,

    /// Текущее состояние прокси в пуле
    pub state: ProxyState,

    /// Подтвержденный протокол
    #[schema(example = "socks5", max_length = 16)]
    pub protocol: Option<String>,

    /// Поддержка CONNECT туннелирования для HTTPS
    #[schema(example = true)]
    pub supports_https: bool,

    /// Внешний IP-адрес, видимый целевым серверам
    #[schema(example = "185.220.101.5", min_length = 3, max_length = 45)]
    pub out_ip: Option<String>,

    /// Двухбуквенный ISO-код страны
    #[schema(example = "DE", min_length = 2, max_length = 2)]
    pub country: Option<String>,

    /// Номер автономной системы (ASN)
    #[schema(example = 24940, minimum = 1)]
    pub asn: Option<u32>,

    /// Организация-владелец автономной системы
    #[schema(example = "Hetzner Online GmbH", max_length = 256)]
    pub asn_org: Option<String>,

    /// Уровень анонимности (elite, anonymous, transparent)
    #[schema(example = "elite", max_length = 16)]
    pub anon: Option<String>,

    /// Сетевые задержки (RTT метрики)
    pub metrics: ProxyMetricsDto,

    /// Политика проверки прокси
    pub policy: CheckPolicyDto,

    /// Статистика проверок и доступности
    pub stats: ProxyStatsDto,

    /// Пользовательские метаданные и источники
    pub meta: ProxyMetaDto,
}

/// Задержки сети и отклика (RTT метрики)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "rtt_tcp_ms": 42,
    "rtt_handshake_ms": 68,
    "rtt_total_ms": 110
}))]
pub struct ProxyMetricsDto {
    /// RTT базового TCP подключения к прокси (мс)
    #[schema(example = 42, minimum = 0)]
    pub rtt_tcp_ms: Option<u32>,

    /// RTT прохождения протокольного хэндшейка (мс)
    #[schema(example = 68, minimum = 0)]
    pub rtt_handshake_ms: Option<u32>,

    /// Полный RTT от начала подключения до получения валидного ответа от judge (мс)
    #[schema(example = 110, minimum = 0)]
    pub rtt_total_ms: Option<u32>,
}

/// Статистика успешности и тайминги проверок прокси
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "checks_total": 450,
    "checks_success": 445,
    "uptime_pct": 98.88,
    "stability_pct": 100.0,
    "dead_strikes": 0,
    "last_error": null,
    "first_seen_at": 1731200000,
    "last_checked_at": 1731256800,
    "next_check_at": 1731256860
}))]
pub struct ProxyStatsDto {
    /// Общее количество выполненных проверок
    #[schema(example = 450, minimum = 0)]
    pub checks_total: u64,

    /// Количество успешных проверок
    #[schema(example = 445, minimum = 0)]
    pub checks_success: u64,

    /// Процент доступности (аптайм)
    #[schema(example = 98.88, minimum = 0.0, maximum = 100.0)]
    pub uptime_pct: f32,

    /// Процент стабильности успешных проверок в рамках плавающего окна N минут (0.0 — 100.0)
    #[schema(example = 100.0, minimum = 0.0, maximum = 100.0)]
    pub stability_pct: f32,

    /// Текущее число последовательных сбоев подряд
    #[schema(example = 0, minimum = 0)]
    pub dead_strikes: u32,

    /// Текст последней ошибки (если была)
    #[schema(example = "Connection timeout after 3000ms", max_length = 1024)]
    pub last_error: Option<String>,

    /// Unix-timestamp первого добавления в систему
    #[schema(example = 1731200000, minimum = 0)]
    pub first_seen_at: i64,

    /// Unix-timestamp последней проверки
    #[schema(example = 1731256800, minimum = 0)]
    pub last_checked_at: Option<i64>,

    /// Unix-timestamp запланированной следующей проверки
    #[schema(example = 1731256860, minimum = 0)]
    pub next_check_at: i64,
}

/// Детализированная информация о привязке прокси к источнику
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema, PartialEq, Eq)]
#[schema(example = json!({
    "name": "premium_pool_v1",
    "added_at": 1731200000
}))]
pub struct ProxySourceMetaDto {
    /// Наименование источника
    #[schema(example = "premium_pool_v1")]
    pub name: String,

    /// Unix-timestamp добавления прокси из этого источника
    #[schema(example = 1731200000, minimum = 0)]
    pub added_at: i64,
}

/// Метаинформация и связь с источниками
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "remark": "High performance German node",
    "sources": ["premium_pool_v1", "backup_tor_feed"],
    "source_details": [
        {"name": "premium_pool_v1", "added_at": 1731200000},
        {"name": "backup_tor_feed", "added_at": 1731210000}
    ]
}))]
pub struct ProxyMetaDto {
    /// Пользовательская заметка / тег
    #[schema(example = "High performance German node", max_length = 512)]
    pub remark: Option<String>,

    /// Список названий источников, в которых был обнаружен данный прокси
    #[schema(example = json!(["premium_pool_v1", "backup_tor_feed"]))]
    pub sources: Vec<String>,

    /// Детализированный список источников с меткой времени добавления
    pub source_details: Vec<ProxySourceMetaDto>,
}

/// Статистика качества и производительности источника прокси
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
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
}))]
pub struct SourceStatsItem {
    /// Первичный идентификатор источника
    #[schema(example = 1, minimum = 1)]
    pub id: i64,

    /// Уникальное наименование источника
    #[schema(example = "premium_pool_v1", min_length = 1, max_length = 128)]
    pub name: String,

    /// URL-адрес источника (если настроен)
    #[schema(example = "https://provider.example.com/api/feed.txt", max_length = 2048)]
    pub url: Option<String>,

    /// Заметка об источнике
    #[schema(example = "Primary corporate subnet proxies", max_length = 512)]
    pub remark: Option<String>,

    /// Общее количество прокси, привязанных к источнику
    #[schema(example = 1000, minimum = 0)]
    pub total_proxies: u64,

    /// Количество рабочих (alive) прокси
    #[schema(example = 850, minimum = 0)]
    pub alive_proxies: u64,

    /// Количество прокси в первичной очереди (cold_queue)
    #[schema(example = 50, minimum = 0)]
    pub cold_queue_proxies: u64,

    /// Количество прокси на карантине (cooldown)
    #[schema(example = 70, minimum = 0)]
    pub cooldown_proxies: u64,

    /// Количество окончательно мертвых прокси (dead_permanent)
    #[schema(example = 30, minimum = 0)]
    pub dead_proxies: u64,

    /// Процент выхода живых прокси (alive / total * 100)
    #[schema(example = 85.0, minimum = 0.0, maximum = 100.0)]
    pub yield_pct: f32,

    /// Средняя задержка (RTT) по всем живым прокси данного источника (мс)
    #[schema(example = 145, minimum = 0)]
    pub avg_rtt_ms: Option<u32>,

    /// Unix-timestamp создания источника в базе данных
    #[schema(example = 1731200000, minimum = 0)]
    pub created_at: i64,

    /// Unix-timestamp последнего добавления/импорта прокси в этот источник
    #[schema(example = 1731250000, minimum = 0)]
    pub last_added_at: Option<i64>,

    /// Unix-timestamp последней проверки любого прокси из этого источника
    #[schema(example = 1731256800, minimum = 0)]
    pub last_checked_at: Option<i64>,
}

/// Статистика доступности прокси по провайдерам / автономным системам (ASN)
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "asn": 24940,
    "asn_org": "Hetzner Online GmbH",
    "alive_count": 3200,
    "avg_rtt_ms": 85
}))]
pub struct AsnStatsDto {
    /// Номер автономной системы (ASN)
    #[schema(example = 24940, minimum = 1)]
    pub asn: u32,

    /// Название организации / интернет-провайдера (ASN Org)
    #[schema(example = "Hetzner Online GmbH", max_length = 256)]
    pub asn_org: Option<String>,

    /// Количество доступных (alive) прокси в этой автономной системе
    #[schema(example = 3200, minimum = 0)]
    pub alive_count: u64,

    /// Средний суммарный RTT для прокси этого ASN (мс)
    #[schema(example = 85, minimum = 0)]
    pub avg_rtt_ms: u32,
}

/// Метрики качества, задержек и возможностей пула прокси
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
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
}))]
pub struct PoolQualityDto {
    /// Суммарное количество выполненных проверок по всем прокси пула
    #[schema(example = 85000, minimum = 0)]
    pub total_checks: u64,

    /// Количество успешных проверок по всем прокси пула
    #[schema(example = 81500, minimum = 0)]
    pub total_checks_success: u64,

    /// Общий процент доступности (uptime) по всему пулу
    #[schema(example = 95.88, minimum = 0.0, maximum = 100.0)]
    pub uptime_pct: f32,

    /// Средняя суммарная задержка (RTT) по всем живым прокси (мс)
    #[schema(example = 115, minimum = 0)]
    pub avg_rtt_ms: Option<u32>,

    /// Средняя задержка TCP SYN/SYN-ACK по всем живым прокси (мс)
    #[schema(example = 45, minimum = 0)]
    pub avg_rtt_tcp_ms: Option<u32>,

    /// Средняя задержка рукопожатия протокола по всем живым прокси (мс)
    #[schema(example = 70, minimum = 0)]
    pub avg_rtt_handshake_ms: Option<u32>,

    /// Количество живых прокси с поддержкой CONNECT для HTTPS
    #[schema(example = 7800, minimum = 0)]
    pub supports_https_count: u64,

    /// Количество живых приватных прокси с учетными данными авторизации
    #[schema(example = 2100, minimum = 0)]
    pub with_auth_count: u64,

    /// Количество живых публичных прокси без авторизации
    #[schema(example = 6300, minimum = 0)]
    pub no_auth_count: u64,

    /// Общее количество зарегистрированных источников прокси в системе
    #[schema(example = 12, minimum = 0)]
    pub total_sources: u64,
}

/// Глобальная телеметрия и статистика системы
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
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
        {"country": "DE", "alive_count": 3200, "avg_rtt_ms": 85},
        {"country": "US", "alive_count": 2500, "avg_rtt_ms": 130},
        {"country": "NL", "alive_count": 1400, "avg_rtt_ms": 75}
    ],
    "top_asns": [
        {"asn": 24940, "asn_org": "Hetzner Online GmbH", "alive_count": 3200, "avg_rtt_ms": 85},
        {"asn": 14061, "asn_org": "DigitalOcean, LLC", "alive_count": 1500, "avg_rtt_ms": 95}
    ]
}))]
pub struct GlobalStatsResponse {
    /// Состояние и показатели движка проверок
    pub engine: EngineStatsDto,

    /// Распределение общего пула прокси по статусам
    pub pool: PoolCountsDto,

    /// Метрики качества, задержек и возможностей пула
    pub quality: PoolQualityDto,

    /// Распределение живых прокси по протоколам (socks5, http, socks4)
    #[schema(example = json!({"socks5": 5200, "http": 3200}))]
    pub by_protocol: HashMap<String, u64>,

    /// Распределение живых прокси по уровням анонимности
    #[schema(example = json!({"elite": 6800, "anonymous": 1400, "transparent": 200}))]
    pub by_anonymity: HashMap<String, u64>,

    /// Распределение зафиксированных причин сбоев и ошибок проверок
    #[schema(example = json!({"TIMEOUT_TCP": 850, "CONN_REFUSED": 430, "HANDSHAKE_TIMEOUT": 210}))]
    pub by_error: HashMap<String, u64>,

    /// Топ стран по количеству доступных прокси
    pub top_countries: Vec<CountryStatsDto>,

    /// Топ интернет-провайдеров / ASN по количеству доступных прокси
    pub top_asns: Vec<AsnStatsDto>,
}

/// Метрики производительности асинхронного движка
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "active_workers": 128,
    "checks_per_sec": 45.2,
    "checks_completed": 15420,
    "batch_buffer_size": 15,
    "judge_healthy": true
}))]
pub struct EngineStatsDto {
    /// Количество параллельных воркеров проверки
    #[schema(example = 128, minimum = 0)]
    pub active_workers: u32,

    /// Текущая скорость проверки (проверок в секунду)
    #[schema(example = 45.2, minimum = 0.0)]
    pub checks_per_sec: f32,

    /// Суммарное количество проверок, выполненных движком с момента запуска сервиса
    #[schema(example = 15420, minimum = 0)]
    pub checks_completed: u64,

    /// Текущий размер буфера результатов, ожидающих пакетной записи в БД
    #[schema(example = 15, minimum = 0)]
    pub batch_buffer_size: usize,

    /// Флаг доступности тестового judge-сервера
    #[schema(example = true)]
    pub judge_healthy: bool,
}

/// Количественное распределение пула по состояниям
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "total": 12500,
    "alive": 8400,
    "cold_queue": 1500,
    "cooldown": 1800,
    "dead_permanent": 800
}))]
pub struct PoolCountsDto {
    /// Общее количество прокси всех состояний в базе данных
    #[schema(example = 12500, minimum = 0)]
    pub total: u64,

    /// Количество рабочих прокси, готовых к использованию
    #[schema(example = 8400, minimum = 0)]
    pub alive: u64,

    /// Количество новых прокси в очереди на первичную проверку
    #[schema(example = 1500, minimum = 0)]
    pub cold_queue: u64,

    /// Количество прокси на карантине после временных сбоев
    #[schema(example = 1800, minimum = 0)]
    pub cooldown: u64,

    /// Количество окончательно мертвых прокси, исключенных из проверок
    #[schema(example = 800, minimum = 0)]
    pub dead_permanent: u64,
}

/// Статистика доступности прокси по стране
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "country": "DE",
    "alive_count": 3200,
    "avg_rtt_ms": 85
}))]
pub struct CountryStatsDto {
    /// Двухбуквенный ISO-код страны
    #[schema(example = "DE", min_length = 2, max_length = 2)]
    pub country: String,

    /// Количество доступных (alive) прокси в этой стране
    #[schema(example = 3200, minimum = 0)]
    pub alive_count: u64,

    /// Средний суммарный RTT для прокси этой страны (мс)
    #[schema(example = 85, minimum = 0)]
    pub avg_rtt_ms: u32,
}

/// Информация о judge-сервере и его текущей доступности
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "id": "azenv_net",
    "name": "AZenv.net",
    "http_url": "http://azenv.net/",
    "https_url": "https://azenv.net/",
    "is_builtin": false,
    "priority": 1,
    "supports_anonymity": true,
    "enabled": true,
    "status": "healthy",
    "latency_ms": 420,
    "consecutive_failures": 0,
    "consecutive_successes": 12,
    "last_checked_at": 1794400500,
    "last_error": null
}))]
pub struct JudgeReportDto {
    /// Уникальный идентификатор judge-сервера
    #[schema(example = "azenv_net")]
    pub id: String,

    /// Человекочитаемое имя
    #[schema(example = "AZenv.net")]
    pub name: String,

    /// HTTP эндпоинт
    #[schema(example = "http://azenv.net/")]
    pub http_url: String,

    /// HTTPS эндпоинт
    #[schema(example = "https://azenv.net/")]
    pub https_url: String,

    /// Флаг встроенного локального judge
    #[schema(example = false)]
    pub is_builtin: bool,

    /// Приоритет выбора (0 = наивысший, 1+ = резервные)
    #[schema(example = 1)]
    pub priority: u32,

    /// Поддержка классификации анонимности по заголовкам
    #[schema(example = true)]
    pub supports_anonymity: bool,

    /// Флаг активности в пуле
    #[schema(example = true)]
    pub enabled: bool,

    /// Текущий статус доступности: healthy, degraded, unhealthy, unknown
    #[schema(example = "healthy")]
    pub status: String,

    /// Задержка ответа при последней проверке доступности (мс)
    #[schema(example = 420)]
    pub latency_ms: Option<u64>,

    /// Количество последовательных сбоев
    #[schema(example = 0)]
    pub consecutive_failures: u32,

    /// Количество последовательных успешных проверок
    #[schema(example = 12)]
    pub consecutive_successes: u32,

    /// Время последней проверки доступности (Unix timestamp)
    #[schema(example = 1794400500)]
    pub last_checked_at: Option<u64>,

    /// Текст последней ошибки при проверке доступности
    pub last_error: Option<String>,
}

/// Результат проверки доступности пула судей
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct JudgeHealthCheckResponse {
    /// Количество проверенных judge-серверов
    #[schema(example = 6)]
    pub total_judges: usize,

    /// Количество доступных и здоровых judge-серверов
    #[schema(example = 5)]
    pub healthy_judges: usize,

    /// Идентификатор активного судьи, выбранного текущей стратегией
    #[schema(example = "builtin")]
    pub active_judge: Option<String>,

    /// Детальный список статусов всех судей
    pub judges: Vec<JudgeReportDto>,
}

