use std::fs;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime};

use arc_swap::ArcSwap;
use parking_lot::Mutex;
use tokio_util::sync::CancellationToken;

struct GeoIpInner {
    country_reader: Option<maxminddb::Reader<Vec<u8>>>,
    asn_reader: Option<maxminddb::Reader<Vec<u8>>>,
}

#[derive(Debug, Clone, Default)]
pub struct GeoIpResult {
    pub country: Option<String>,
    pub asn: Option<u32>,
    pub asn_org: Option<String>,
}

pub struct GeoIpResolver {
    inner: ArcSwap<GeoIpInner>,
    country_path: Option<PathBuf>,
    asn_path: Option<PathBuf>,
    last_country_mtime: Mutex<Option<SystemTime>>,
    last_asn_mtime: Mutex<Option<SystemTime>>,
}

impl GeoIpResolver {
    /// Tries to load MaxMind GeoLite2 databases. Returns None if neither path is configured.
    pub fn try_load(
        country_path: Option<&str>,
        asn_path: Option<&str>,
    ) -> Option<Arc<Self>> {
        if country_path.is_none() && asn_path.is_none() {
            return None;
        }

        let country_pb = country_path.map(PathBuf::from);
        let asn_pb = asn_path.map(PathBuf::from);

        let country_reader = country_pb.as_deref().and_then(Self::load_reader);
        let asn_reader = asn_pb.as_deref().and_then(Self::load_reader);

        let country_mtime = country_pb.as_deref().and_then(Self::get_mtime);
        let asn_mtime = asn_pb.as_deref().and_then(Self::get_mtime);

        let inner = GeoIpInner {
            country_reader,
            asn_reader,
        };

        Some(Arc::new(Self {
            inner: ArcSwap::from_pointee(inner),
            country_path: country_pb,
            asn_path: asn_pb,
            last_country_mtime: Mutex::new(country_mtime),
            last_asn_mtime: Mutex::new(asn_mtime),
        }))
    }

    fn load_reader(path: &Path) -> Option<maxminddb::Reader<Vec<u8>>> {
        match fs::read(path) {
            Ok(bytes) => match maxminddb::Reader::from_source(bytes) {
                Ok(reader) => {
                    tracing::info!("Loaded GeoIP database: {}", path.display());
                    Some(reader)
                }
                Err(err) => {
                    tracing::warn!("Failed to parse GeoIP database {}: {err}", path.display());
                    None
                }
            },
            Err(err) => {
                tracing::warn!("Failed to read GeoIP file {}: {err}", path.display());
                None
            }
        }
    }

    fn get_mtime(path: &Path) -> Option<SystemTime> {
        fs::metadata(path).and_then(|m| m.modified()).ok()
    }

    pub fn lookup(&self, ip: IpAddr) -> GeoIpResult {
        let guard = self.inner.load();
        let mut result = GeoIpResult::default();

        if let Some(ref cr) = guard.country_reader
            && let Ok(lookup) = cr.lookup(ip)
            && let Ok(Some(country)) = lookup.decode::<maxminddb::geoip2::Country>()
        {
            result.country = country.country.iso_code.map(|s| s.to_string());
        }

        if let Some(ref ar) = guard.asn_reader
            && let Ok(lookup) = ar.lookup(ip)
            && let Ok(Some(asn)) = lookup.decode::<maxminddb::geoip2::Asn>()
        {
            result.asn = asn.autonomous_system_number;
            result.asn_org = asn.autonomous_system_organization.map(|s| s.to_string());
        }

        result
    }

    pub fn hot_reload(&self) -> bool {
        let mut changed = false;

        let current_country_mtime = self.country_path.as_deref().and_then(Self::get_mtime);
        let current_asn_mtime = self.asn_path.as_deref().and_then(Self::get_mtime);

        let mut last_c = self.last_country_mtime.lock();
        let mut last_a = self.last_asn_mtime.lock();

        if current_country_mtime != *last_c {
            changed = true;
        }
        if current_asn_mtime != *last_a {
            changed = true;
        }

        if !changed {
            return false;
        }

        let new_country_reader = self.country_path.as_deref().and_then(Self::load_reader);
        let new_asn_reader = self.asn_path.as_deref().and_then(Self::load_reader);

        *last_c = current_country_mtime;
        *last_a = current_asn_mtime;

        self.inner.store(Arc::new(GeoIpInner {
            country_reader: new_country_reader,
            asn_reader: new_asn_reader,
        }));

        tracing::info!("GeoIP databases hot reloaded");
        true
    }
}

pub async fn geoip_reload_loop(
    resolver: Arc<GeoIpResolver>,
    reload_interval: Duration,
    cancel: CancellationToken,
) {
    let mut interval = tokio::time::interval(reload_interval);
    interval.tick().await; // skip initial tick

    loop {
        tokio::select! {
            _ = interval.tick() => {
                resolver.hot_reload();
            }
            _ = cancel.cancelled() => break,
        }
    }
}
