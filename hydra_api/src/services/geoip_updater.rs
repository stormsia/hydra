use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use flate2::read::GzDecoder;
use reqwest::StatusCode;
use reqwest::header::{ETAG, IF_NONE_MATCH, USER_AGENT};
use tokio_util::sync::CancellationToken;

use crate::services::geoip::GeoIpResolver;

/// User-Agent header sent to GeoIP mirrors and CDNs
const HYDRA_USER_AGENT: &str = "HydraProxyChecker/0.1.0";

/// Gzip magic header bytes
const GZIP_MAGIC: [u8; 2] = [0x1f, 0x8b];

/// Downloads a GeoIP database archive (.mmdb.gz or raw .mmdb) conditionally using ETag,
/// decompresses it if gzipped, verifies database integrity with MaxMind Reader,
/// and atomically moves it to `dest_path`.
///
/// Returns `Ok(true)` if the file was newly downloaded/updated.
/// Returns `Ok(false)` if the server returned 304 Not Modified or file is up to date.
/// Returns `Err` if the download, decompression, validation, or file writing failed.
pub async fn download_and_extract_db(
    client: &reqwest::Client,
    url: &str,
    dest_path: &Path,
) -> Result<bool, String> {
    let etag_file = get_etag_path(dest_path);

    // Read stored ETag if destination database and .etag file both exist
    let existing_etag = if dest_path.exists() && etag_file.exists() {
        fs::read_to_string(&etag_file)
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    };

    let mut req = client.get(url).header(USER_AGENT, HYDRA_USER_AGENT);
    if let Some(ref etag) = existing_etag {
        req = req.header(IF_NONE_MATCH, etag.as_str());
    }

    let response = req
        .send()
        .await
        .map_err(|e| format!("Failed to send HTTP request to {url}: {e}"))?;

    let status = response.status();
    if status == StatusCode::NOT_MODIFIED {
        tracing::debug!(
            "GeoIP database for {} is up to date (ETag matched, HTTP 304)",
            dest_path.display()
        );
        return Ok(false);
    }

    if !status.is_success() {
        return Err(format!(
            "Unexpected HTTP status {status} when fetching GeoIP database from {url}"
        ));
    }

    let new_etag = response
        .headers()
        .get(ETAG)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim().to_string());

    let raw_bytes = response
        .bytes()
        .await
        .map_err(|e| format!("Failed to read response body from {url}: {e}"))?;

    // Decompress if gzip format is detected, otherwise use raw bytes
    let decompressed = if raw_bytes.len() >= 2 && raw_bytes[0..2] == GZIP_MAGIC {
        let mut decoder = GzDecoder::new(&raw_bytes[..]);
        let mut buffer = Vec::new();
        decoder
            .read_to_end(&mut buffer)
            .map_err(|e| format!("Failed to decompress gzip GeoIP archive from {url}: {e}"))?;
        buffer
    } else {
        raw_bytes.to_vec()
    };

    // Verify validity with maxminddb reader before touching the filesystem
    if let Err(e) = maxminddb::Reader::from_source(decompressed.clone()) {
        return Err(format!(
            "Downloaded GeoIP database for {} failed MaxMind format verification: {e}",
            dest_path.display()
        ));
    }

    // Ensure parent directory exists
    if let Some(parent) = dest_path.parent()
        && !parent.as_os_str().is_empty()
        && !parent.exists()
    {
        fs::create_dir_all(parent)
            .map_err(|e| format!("Failed to create directory {}: {e}", parent.display()))?;
    }

    // Write to a temporary file first for atomic swap
    let tmp_path = dest_path.with_extension("tmp");
    fs::write(&tmp_path, &decompressed)
        .map_err(|e| format!("Failed to write temporary file {}: {e}", tmp_path.display()))?;

    // Atomic rename into target path
    fs::rename(&tmp_path, dest_path).map_err(|e| {
        let _ = fs::remove_file(&tmp_path);
        format!(
            "Failed to atomically rename {} to {}: {e}",
            tmp_path.display(),
            dest_path.display()
        )
    })?;

    // Store new ETag
    if let Some(etag) = new_etag {
        let _ = fs::write(&etag_file, etag);
    }

    tracing::info!(
        "Successfully updated GeoIP database {} (decompressed size: {} bytes)",
        dest_path.display(),
        decompressed.len()
    );

    Ok(true)
}

/// Helper to generate companion ETag file path: `<dest_path>.etag`
pub fn get_etag_path(dest_path: &Path) -> PathBuf {
    dest_path.with_extension("etag")
}

/// Checks and updates all configured GeoIP databases (Country and ASN).
/// Returns true if at least one database was updated.
pub async fn check_and_update_all(
    client: &reqwest::Client,
    country_url: &str,
    country_path: Option<&Path>,
    asn_url: &str,
    asn_path: Option<&Path>,
) -> bool {
    let mut updated = false;

    if let Some(cp) = country_path {
        tracing::debug!("Checking Country GeoIP updates from {}...", country_url);
        match download_and_extract_db(client, country_url, cp).await {
            Ok(true) => updated = true,
            Ok(false) => {}
            Err(e) => tracing::warn!("Country GeoIP update check failed: {e}"),
        }
    }

    if let Some(ap) = asn_path {
        tracing::debug!("Checking ASN GeoIP updates from {}...", asn_url);
        match download_and_extract_db(client, asn_url, ap).await {
            Ok(true) => updated = true,
            Ok(false) => {}
            Err(e) => tracing::warn!("ASN GeoIP update check failed: {e}"),
        }
    }

    updated
}

/// Creates an HTTP client configured specifically for binary mmdb downloads
/// (disabling transparent gzip/brotli decoding to preserve raw archive stream)
pub fn build_http_client() -> reqwest::Client {
    crate::init_crypto_provider();
    reqwest::Client::builder()
        .no_gzip()
        .no_brotli()
        .no_deflate()
        .connect_timeout(Duration::from_secs(15))
        .timeout(Duration::from_secs(180))
        .build()
        .unwrap_or_default()
}

/// Background loop that periodically checks for GeoIP database updates and triggers
/// zero-downtime hot-reloading on the resolver when changes are applied.
pub async fn geoip_auto_update_loop(
    country_url: String,
    country_path: Option<PathBuf>,
    asn_url: String,
    asn_path: Option<PathBuf>,
    interval: Duration,
    resolver: Option<Arc<GeoIpResolver>>,
    cancel: CancellationToken,
) {
    let client = build_http_client();

    tracing::info!(
        "GeoIP auto-updater background task active (check interval: {}s)",
        interval.as_secs()
    );

    // Initial check runs in background to completely avoid blocking API server boot
    tracing::info!("Running initial background GeoIP database check...");
    let updated = check_and_update_all(
        &client,
        &country_url,
        country_path.as_deref(),
        &asn_url,
        asn_path.as_deref(),
    )
    .await;

    if updated && let Some(ref res) = resolver {
        res.hot_reload();
    }

    let mut ticker = tokio::time::interval(interval);
    ticker.tick().await; // consume first tick

    loop {
        tokio::select! {
            _ = ticker.tick() => {
                tracing::info!("Executing scheduled GeoIP database update check...");
                let updated = check_and_update_all(
                    &client,
                    &country_url,
                    country_path.as_deref(),
                    &asn_url,
                    asn_path.as_deref(),
                ).await;

                if updated
                    && let Some(ref res) = resolver
                {
                    res.hot_reload();
                }
            }
            _ = cancel.cancelled() => {
                tracing::info!("GeoIP auto-update loop received cancellation signal, stopping...");
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use flate2::Compression;
    use flate2::write::GzEncoder;
    use std::io::Write;

    #[test]
    fn test_gzip_detection_and_decompression() {
        let original_data = b"Hydra GeoIP test payload data 1234567890";
        let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(original_data).unwrap();
        let compressed = encoder.finish().unwrap();

        assert!(compressed.len() >= 2);
        assert_eq!(&compressed[0..2], &GZIP_MAGIC);

        let mut decoder = GzDecoder::new(&compressed[..]);
        let mut decompressed = Vec::new();
        decoder.read_to_end(&mut decompressed).unwrap();

        assert_eq!(decompressed, original_data);
    }

    #[test]
    fn test_etag_path_generation() {
        let path = Path::new("data/GeoLite2-Country.mmdb");
        let etag_path = get_etag_path(path);
        assert_eq!(etag_path, PathBuf::from("data/GeoLite2-Country.etag"));
    }
}
