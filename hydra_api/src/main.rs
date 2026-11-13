use std::sync::Arc;
use std::time::Duration;
use tokio_util::sync::CancellationToken;

use hydra_checker::{CheckerConfig, CheckerEngine};
use hydra_api::app_state::{AppState, SchedulerStats};
use hydra_api::config::ApiConfig;
use hydra_api::db::init_db;
use hydra_api::router::build_router;
use hydra_api::services::batch_writer::batch_writer_loop;
use hydra_api::services::geoip::{geoip_reload_loop, GeoIpResolver};
use hydra_api::services::geoip_updater::geoip_auto_update_loop;
use hydra_api::services::maintenance::db_maintenance_loop;
use hydra_api::services::scheduler::scheduler_loop;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    hydra_api::init_crypto_provider();
    dotenvy::dotenv().ok();

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,hydra_api=debug,hydra_judge=debug".into()),
        )
        .init();

    let config = Arc::new(ApiConfig::from_env()?);

    config.ensure_directories()?;
    tracing::info!("Ensured application directories exist (data, geo)");

    let cancel = CancellationToken::new();

    // Optionally spawn embedded Judge server for all-in-one local development
    if config.embed_judge {
        let judge_bind: std::net::SocketAddr = format!("0.0.0.0:{}", config.embed_judge_port).parse()?;
        let mut judge_builder = hydra_judge::JudgeConfig::builder(judge_bind, &config.judge_secret_token);
        if let Some(ref key) = config.judge_secret_key {
            judge_builder = judge_builder.secret_key(key);
        }
        let judge_cfg = judge_builder.build();
        let judge_server = hydra_judge::JudgeServer::new(judge_cfg)?;
        let judge_cancel = cancel.clone();
        tokio::spawn(async move {
            tracing::info!("Embedded Hydra Judge running on http://{}", judge_bind);
            if let Err(e) = judge_server.run(judge_cancel).await {
                tracing::error!("Embedded Hydra Judge server error: {e}");
            }
        });
    }

    let db = Arc::new(init_db(&config.db_path).await?);

    let mut builder = CheckerConfig::builder(
        config.judge_http_url.parse()?,
        config.judge_https_url.parse()?,
        &config.judge_secret_token,
    );
    builder = builder.concurrency_limit(config.checker_concurrency);
    builder = builder.enable_third_party_judges(config.enable_third_party_judges);
    if config.judge_selection_strategy.eq_ignore_ascii_case("round_robin") || config.judge_selection_strategy.eq_ignore_ascii_case("roundrobin") {
        builder = builder.judge_selection_strategy(hydra_checker::JudgeSelectionStrategy::RoundRobin);
    } else if config.judge_selection_strategy.eq_ignore_ascii_case("priority") {
        builder = builder.judge_selection_strategy(hydra_checker::JudgeSelectionStrategy::Priority);
    } else {
        builder = builder.judge_selection_strategy(hydra_checker::JudgeSelectionStrategy::LowestLatency);
    }
    if let Some(ref add_judges_str) = config.additional_judges {
        for (idx, entry) in add_judges_str.split(',').enumerate() {
            let parts: Vec<&str> = entry.trim().split('|').collect();
            if !parts.is_empty() {
                if let Ok(http_url) = parts[0].trim().parse::<url::Url>() {
                    let https_url = if parts.len() > 1 {
                        parts[1].trim().parse::<url::Url>().unwrap_or_else(|_| http_url.clone())
                    } else {
                        http_url.clone()
                    };
                    let custom_ep = hydra_checker::JudgeEndpoint::third_party(
                        format!("custom_{}", idx + 1),
                        format!("Custom Judge {}", idx + 1),
                        http_url,
                        https_url,
                        10 + idx as u32,
                        true,
                    );
                    builder = builder.add_judge(custom_ep);
                }
            }
        }
    }
    if let Some(ref key) = config.judge_secret_key {
        builder = builder.judge_secret_key(key);
    }
    if let Ok(ip_str) = std::env::var("CHECKER_REAL_IP") {
        if let Ok(ip) = ip_str.parse::<std::net::IpAddr>() {
            builder = builder.real_ip(ip);
        }
    }
    let checker_config = builder.build().await?;
    let engine = Arc::new(CheckerEngine::new(checker_config)?);

    // Spawn periodic Judge availability check & live health monitoring loop
    let judge_pool = engine.judge_pool().clone();
    let tls_connector = engine.tls_connector().clone();
    let health_interval = Duration::from_secs(config.judge_health_check_interval_secs);
    let health_cancel = cancel.clone();
    tokio::spawn(async move {
        tracing::info!("Running initial judge availability probe...");
        let reports = judge_pool.check_availability_all(Duration::from_secs(5), &tls_connector).await;
        for r in &reports {
            tracing::info!(
                "Judge '{}' ({}) -> Status: {:?}, Latency: {:?}ms",
                r.name, r.id, r.status, r.latency_ms
            );
        }
        judge_pool.start_health_check_loop(health_interval, tls_connector, health_cancel).await;
    });

    let geoip = GeoIpResolver::try_load(
        config.geoip_country_path.as_deref(),
        config.geoip_asn_path.as_deref(),
    );

    let (result_tx, result_rx) = tokio::sync::mpsc::unbounded_channel();
    let scheduler_stats = Arc::new(SchedulerStats::default());

    let state = AppState {
        config: config.clone(),
        db: db.clone(),
        engine,
        geoip: geoip.clone(),
        result_tx,
        scheduler_stats: scheduler_stats.clone(),
    };

    tokio::spawn(batch_writer_loop(
        result_rx,
        db.clone(),
        config.batch_flush_interval_ms,
        scheduler_stats.clone(),
    ));

    tokio::spawn(scheduler_loop(
        state.clone(),
        cancel.clone(),
    ));

    tokio::spawn(db_maintenance_loop(
        db.clone(),
        config.dead_proxy_retention_days,
        config.db_maintenance_interval_secs,
        cancel.clone(),
    ));

    if let Some(ref g) = geoip {
        tokio::spawn(geoip_reload_loop(
            Arc::clone(g),
            Duration::from_secs(config.geoip_reload_secs),
            cancel.clone(),
        ));
    }

    if config.geoip_auto_update {
        tokio::spawn(geoip_auto_update_loop(
            config.geoip_country_url.clone(),
            config.geoip_country_path.clone().map(std::path::PathBuf::from),
            config.geoip_asn_url.clone(),
            config.geoip_asn_path.clone().map(std::path::PathBuf::from),
            Duration::from_secs(config.geoip_update_interval_secs),
            geoip.clone(),
            cancel.clone(),
        ));
    }

    let app = build_router(state);
    let listener = tokio::net::TcpListener::bind(&config.listen_addr).await?;
    tracing::info!("Hydra API server listening on http://{}", config.listen_addr);
    tracing::info!("Swagger UI available at http://{}/swagger-ui", config.listen_addr);

    let shutdown_cancel = cancel.clone();
    axum::serve(listener, app)
        .with_graceful_shutdown(async move {
            let _ = tokio::signal::ctrl_c().await;
            tracing::info!("Shutdown signal received, draining...");
            shutdown_cancel.cancel();
        })
        .await?;

    Ok(())
}
