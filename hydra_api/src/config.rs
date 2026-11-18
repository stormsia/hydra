use std::env;
use std::net::SocketAddr;
use std::path::Path;

#[derive(Debug, Clone)]
pub struct ApiConfig {
    // Server
    pub listen_addr: SocketAddr,
    pub api_key: String,

    // Database (local file)
    pub db_path: String,

    // Checker / Judge
    pub judge_http_url: String,
    pub judge_https_url: String,
    pub judge_secret_token: String,
    pub judge_secret_key: Option<String>,
    pub checker_concurrency: usize,

    // Third-party Judges & Availability
    pub enable_third_party_judges: bool,
    pub judge_health_check_interval_secs: u64,
    pub judge_selection_strategy: String,
    pub additional_judges: Option<String>,

    // Embedded Judge option (auto-run internal judge instance)
    pub embed_judge: bool,
    pub embed_judge_port: u16,

    // GeoIP
    pub geoip_country_path: Option<String>,
    pub geoip_asn_path: Option<String>,
    pub geoip_reload_secs: u64,
    pub geoip_auto_update: bool,
    pub geoip_update_interval_secs: u64,
    pub geoip_country_url: String,
    pub geoip_asn_url: String,

    // Scheduler & Batch Writer
    pub scheduler_batch_size: usize,
    pub batch_flush_interval_ms: u64,

    // Database Maintenance & Retention
    pub dead_proxy_retention_days: u32,
    pub db_maintenance_interval_secs: u64,
}

impl ApiConfig {
    pub fn from_env() -> Result<Self, String> {
        let listen_addr: SocketAddr = env::var("LISTEN_ADDR")
            .unwrap_or_else(|_| "0.0.0.0:3000".to_string())
            .parse()
            .map_err(|e| format!("Invalid LISTEN_ADDR: {e}"))?;

        let api_key = env::var("API_KEY")
            .map_err(|_| "API_KEY environment variable is required".to_string())?;

        let db_path = env::var("DB_PATH").unwrap_or_else(|_| "./data/hydra.db".to_string());

        let judge_http_url =
            env::var("JUDGE_HTTP_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

        let judge_https_url =
            env::var("JUDGE_HTTPS_URL").unwrap_or_else(|_| "http://127.0.0.1:8080".to_string());

        let judge_secret_token =
            env::var("JUDGE_SECRET_TOKEN").unwrap_or_else(|_| "hydra_secret_token".to_string());

        let judge_secret_key = env::var("JUDGE_SECRET_KEY").ok();

        let checker_concurrency: usize = env::var("CHECKER_CONCURRENCY")
            .unwrap_or_else(|_| "5000".to_string())
            .parse()
            .map_err(|e| format!("Invalid CHECKER_CONCURRENCY: {e}"))?;

        let enable_third_party_judges = env::var("ENABLE_THIRD_PARTY_JUDGES")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(true);

        let judge_health_check_interval_secs: u64 = env::var("JUDGE_HEALTH_CHECK_INTERVAL_SECS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .map_err(|e| format!("Invalid JUDGE_HEALTH_CHECK_INTERVAL_SECS: {e}"))?;

        let judge_selection_strategy =
            env::var("JUDGE_SELECTION_STRATEGY").unwrap_or_else(|_| "lowest_latency".to_string());

        let additional_judges = env::var("ADDITIONAL_JUDGES").ok();

        let embed_judge = env::var("EMBED_JUDGE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(false);

        let embed_judge_port: u16 = env::var("EMBED_JUDGE_PORT")
            .unwrap_or_else(|_| "8080".to_string())
            .parse()
            .map_err(|e| format!("Invalid EMBED_JUDGE_PORT: {e}"))?;

        let geoip_auto_update = env::var("GEOIP_AUTO_UPDATE")
            .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
            .unwrap_or(true);

        let mut geoip_country_path = env::var("GEOIP_COUNTRY_PATH").ok();
        let mut geoip_asn_path = env::var("GEOIP_ASN_PATH").ok();

        if geoip_auto_update {
            if geoip_country_path.is_none() {
                geoip_country_path = Some("./geo/GeoLite2-Country.mmdb".to_string());
            }
            if geoip_asn_path.is_none() {
                geoip_asn_path = Some("./geo/GeoLite2-ASN.mmdb".to_string());
            }
        }

        let geoip_reload_secs: u64 = env::var("GEOIP_RELOAD_SECS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .map_err(|e| format!("Invalid GEOIP_RELOAD_SECS: {e}"))?;

        let geoip_update_interval_secs: u64 = env::var("GEOIP_UPDATE_INTERVAL_SECS")
            .unwrap_or_else(|_| "86400".to_string())
            .parse()
            .map_err(|e| format!("Invalid GEOIP_UPDATE_INTERVAL_SECS: {e}"))?;

        let geoip_country_url = env::var("GEOIP_COUNTRY_URL").unwrap_or_else(|_| {
            "https://cdn.jsdelivr.net/npm/geolite2-country/GeoLite2-Country.mmdb.gz".to_string()
        });

        let geoip_asn_url = env::var("GEOIP_ASN_URL").unwrap_or_else(|_| {
            "https://cdn.jsdelivr.net/npm/geolite2-asn/GeoLite2-ASN.mmdb.gz".to_string()
        });

        let scheduler_batch_size: usize = env::var("SCHEDULER_BATCH_SIZE")
            .unwrap_or_else(|_| "10000".to_string())
            .parse()
            .map_err(|e| format!("Invalid SCHEDULER_BATCH_SIZE: {e}"))?;

        let batch_flush_interval_ms: u64 = env::var("BATCH_FLUSH_INTERVAL_MS")
            .unwrap_or_else(|_| "100".to_string())
            .parse()
            .map_err(|e| format!("Invalid BATCH_FLUSH_INTERVAL_MS: {e}"))?;

        let dead_proxy_retention_days: u32 = env::var("DEAD_PROXY_RETENTION_DAYS")
            .unwrap_or_else(|_| "30".to_string())
            .parse()
            .map_err(|e| format!("Invalid DEAD_PROXY_RETENTION_DAYS: {e}"))?;

        let db_maintenance_interval_secs: u64 = env::var("DB_MAINTENANCE_INTERVAL_SECS")
            .unwrap_or_else(|_| "3600".to_string())
            .parse()
            .map_err(|e| format!("Invalid DB_MAINTENANCE_INTERVAL_SECS: {e}"))?;

        Ok(Self {
            listen_addr,
            api_key,
            db_path,
            judge_http_url,
            judge_https_url,
            judge_secret_token,
            judge_secret_key,
            checker_concurrency,
            enable_third_party_judges,
            judge_health_check_interval_secs,
            judge_selection_strategy,
            additional_judges,
            embed_judge,
            embed_judge_port,
            geoip_country_path,
            geoip_asn_path,
            geoip_reload_secs,
            geoip_auto_update,
            geoip_update_interval_secs,
            geoip_country_url,
            geoip_asn_url,
            scheduler_batch_size,
            batch_flush_interval_ms,
            dead_proxy_retention_days,
            db_maintenance_interval_secs,
        })
    }

    /// Ensures that essential application directories (`data`, `geo`, and parent directories
    /// of configured database and GeoIP database files) exist on disk.
    pub fn ensure_directories(&self) -> std::io::Result<()> {
        self.ensure_directories_in(Path::new("."))
    }

    /// Ensures that essential directories exist relative to the given base directory.
    pub fn ensure_directories_in(&self, base_dir: &Path) -> std::io::Result<()> {
        // Ensure standard base data and geo directories exist
        std::fs::create_dir_all(base_dir.join("data"))?;
        std::fs::create_dir_all(base_dir.join("geo"))?;

        // If custom db_path is configured and not :memory:, ensure its parent exists
        if self.db_path != ":memory:" {
            let p = Path::new(&self.db_path);
            let full_p = if p.is_relative() {
                base_dir.join(p)
            } else {
                p.to_path_buf()
            };
            if let Some(parent) = full_p.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
        }

        // If custom geoip_country_path is configured, ensure its parent exists
        if let Some(ref path) = self.geoip_country_path {
            let p = Path::new(path);
            let full_p = if p.is_relative() {
                base_dir.join(p)
            } else {
                p.to_path_buf()
            };
            if let Some(parent) = full_p.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
        }

        // If custom geoip_asn_path is configured, ensure its parent exists
        if let Some(ref path) = self.geoip_asn_path {
            let p = Path::new(path);
            let full_p = if p.is_relative() {
                base_dir.join(p)
            } else {
                p.to_path_buf()
            };
            if let Some(parent) = full_p.parent()
                && !parent.as_os_str().is_empty()
            {
                std::fs::create_dir_all(parent)?;
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_config(db_path: &str, geo_country: Option<&str>, geo_asn: Option<&str>) -> ApiConfig {
        ApiConfig {
            listen_addr: "127.0.0.1:3000".parse().unwrap(),
            api_key: "test_key".to_string(),
            db_path: db_path.to_string(),
            judge_http_url: "http://127.0.0.1:8080".to_string(),
            judge_https_url: "http://127.0.0.1:8080".to_string(),
            judge_secret_token: "test_token".to_string(),
            judge_secret_key: None,
            checker_concurrency: 5000,
            enable_third_party_judges: true,
            judge_health_check_interval_secs: 30,
            judge_selection_strategy: "lowest_latency".to_string(),
            additional_judges: None,
            embed_judge: false,
            embed_judge_port: 8080,
            geoip_country_path: geo_country.map(|s| s.to_string()),
            geoip_asn_path: geo_asn.map(|s| s.to_string()),
            geoip_reload_secs: 3600,
            geoip_auto_update: true,
            geoip_update_interval_secs: 86400,
            geoip_country_url: String::new(),
            geoip_asn_url: String::new(),
            scheduler_batch_size: 10000,
            batch_flush_interval_ms: 100,
            dead_proxy_retention_days: 30,
            db_maintenance_interval_secs: 3600,
        }
    }

    #[test]
    fn test_ensure_directories_creates_geo_and_data() {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "hydra_test_dirs_{}_{}",
            std::process::id(),
            unique_id
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let config = dummy_config(
            "./data/hydra.db",
            Some("./geo/GeoLite2-Country.mmdb"),
            Some("./geo/GeoLite2-ASN.mmdb"),
        );

        let data_dir = temp_dir.join("data");
        let geo_dir = temp_dir.join("geo");

        assert!(!data_dir.exists());
        assert!(!geo_dir.exists());

        config.ensure_directories_in(&temp_dir).unwrap();

        assert!(data_dir.exists(), "data directory must exist");
        assert!(data_dir.is_dir(), "data must be a directory");
        assert!(geo_dir.exists(), "geo directory must exist");
        assert!(geo_dir.is_dir(), "geo must be a directory");

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ensure_directories_creates_custom_nested_paths() {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "hydra_test_custom_dirs_{}_{}",
            std::process::id(),
            unique_id
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let config = dummy_config(
            "custom_storage/sqlite/db.sqlite",
            Some("custom_geo/dbs/country.mmdb"),
            None,
        );

        let data_dir = temp_dir.join("data");
        let geo_dir = temp_dir.join("geo");
        let custom_db_dir = temp_dir.join("custom_storage").join("sqlite");
        let custom_geo_dir = temp_dir.join("custom_geo").join("dbs");

        config.ensure_directories_in(&temp_dir).unwrap();

        assert!(data_dir.is_dir());
        assert!(geo_dir.is_dir());
        assert!(custom_db_dir.is_dir());
        assert!(custom_geo_dir.is_dir());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }

    #[test]
    fn test_ensure_directories_handles_in_memory_and_none() {
        let unique_id = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let temp_dir = std::env::temp_dir().join(format!(
            "hydra_test_mem_dirs_{}_{}",
            std::process::id(),
            unique_id
        ));
        let _ = std::fs::remove_dir_all(&temp_dir);
        std::fs::create_dir_all(&temp_dir).unwrap();

        let config = dummy_config(":memory:", None, None);

        let data_dir = temp_dir.join("data");
        let geo_dir = temp_dir.join("geo");

        config.ensure_directories_in(&temp_dir).unwrap();

        assert!(data_dir.is_dir());
        assert!(geo_dir.is_dir());

        let _ = std::fs::remove_dir_all(&temp_dir);
    }
}
