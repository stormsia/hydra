use chrono::Utc;
use hydra_api::app_state::{AppState, SchedulerStats};
use hydra_api::config::ApiConfig;
use hydra_api::db::*;
use hydra_api::models::{ProxyRow, ProxyState};
use hydra_api::services::batch_writer::{
    CheckResultWithMeta, flush_batch, prepare_batch_statements, update_recent_checks,
};
use hydra_api::services::geoip::GeoIpResult;
use hydra_api::services::scheduler::{row_to_target, scheduler_loop};
use hydra_checker::{
    AnonymityLevel, CheckMetrics, CheckResult, CheckerConfig, CheckerEngine, ErrorReason,
    ProxyProtocol, TargetHost,
};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

#[tokio::test]
async fn test_row_to_target_mapping() {
    let row = ProxyRow {
        id: "198.51.100.5:8080".to_string(),
        ip: "198.51.100.5".to_string(),
        port: 8080,
        auth_user: Some("testuser".to_string()),
        auth_pass: Some("testpass".to_string()),
        state: ProxyState::ColdQueue,
        protocol: Some("socks5".to_string()),
        supports_https: true,
        out_ip: None,
        country: None,
        asn: None,
        asn_org: None,
        anon: None,
        rtt_tcp_ms: None,
        rtt_handshake_ms: None,
        rtt_total_ms: None,
        connect_timeout_ms: 2500,
        handshake_timeout_ms: 3500,
        rw_timeout_ms: 4500,
        recheck_alive_sec: 90,
        recheck_dead_sec: 1200,
        max_dead_strikes: 2,
        stability_window_min: 5,
        dead_backoff_mult: 1.5,
        checks_total: 0,
        checks_success: 0,
        dead_strikes: 0,
        last_error: None,
        stability_pct: 0.0,
        recent_checks: None,
        remark: None,
        first_seen_at: 1000,
        last_checked_at: None,
        next_check_at: 1000,
    };

    let target = row_to_target(&row);
    assert_eq!(target.port, 8080);
    assert_eq!(target.expected_protocol, Some(ProxyProtocol::Socks5));
    assert_eq!(target.auth.as_ref().unwrap().username, "testuser");
    assert_eq!(target.auth.as_ref().unwrap().password, "testpass");

    let cfg = target.config_override.unwrap();
    assert_eq!(cfg.connect_timeout.unwrap().as_millis(), 2500);
    assert_eq!(cfg.handshake_timeout.unwrap().as_millis(), 3500);
    assert_eq!(cfg.read_write_timeout.unwrap().as_millis(), 4500);
}

#[tokio::test]
async fn test_batch_writer_alive_and_dead_transitions() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let (mut stmt_alive, mut stmt_dead) = prepare_batch_statements(&conn).await.unwrap();
    let stats = Arc::new(SchedulerStats::default());
    let now = Utc::now().timestamp();

    // 1. Insert initial cold_queue proxy
    let proxy = ProxyRow {
        id: "198.51.100.10:1080".to_string(),
        ip: "198.51.100.10".to_string(),
        port: 1080,
        auth_user: None,
        auth_pass: None,
        state: ProxyState::ColdQueue,
        protocol: None,
        supports_https: false,
        out_ip: None,
        country: None,
        asn: None,
        asn_org: None,
        anon: None,
        rtt_tcp_ms: None,
        rtt_handshake_ms: None,
        rtt_total_ms: None,
        connect_timeout_ms: 3000,
        handshake_timeout_ms: 4000,
        rw_timeout_ms: 5000,
        recheck_alive_sec: 60,
        recheck_dead_sec: 300,
        max_dead_strikes: 2,
        stability_window_min: 5,
        dead_backoff_mult: 1.5,
        checks_total: 0,
        checks_success: 0,
        dead_strikes: 0,
        last_error: None,
        stability_pct: 0.0,
        recent_checks: None,
        remark: None,
        first_seen_at: now,
        last_checked_at: None,
        next_check_at: now,
    };
    insert_proxy_if_not_exists(&conn, &proxy, false)
        .await
        .unwrap();

    // 2. Simulate successful check result
    let cr_alive = CheckResult {
        target_host: TargetHost::parse(&proxy.ip),
        target_port: proxy.port,
        is_alive: true,
        detected_protocol: Some(ProxyProtocol::Socks5),
        anonymity_level: Some(AnonymityLevel::Elite),
        external_ip: Some("198.51.100.99".parse().unwrap()),
        metrics: CheckMetrics {
            tcp_connect_rtt_ms: 20,
            handshake_rtt_ms: 30,
            total_rtt_ms: 50,
        },
        supports_https: true,
        error_reason: None,
    };

    let meta_alive = CheckResultWithMeta {
        proxy_id: proxy.id.clone(),
        result: cr_alive,
        geoip: GeoIpResult {
            country: Some("FR".to_string()),
            asn: Some(1234),
            asn_org: Some("OVH".to_string()),
        },
        recheck_alive_sec: proxy.recheck_alive_sec,
        recheck_dead_sec: proxy.recheck_dead_sec,
        max_dead_strikes: proxy.max_dead_strikes,
        current_strikes: 0,
        stability_window_min: proxy.stability_window_min,
        dead_backoff_mult: proxy.dead_backoff_mult,
        recent_checks: proxy.recent_checks.clone(),
    };

    let mut buf = vec![meta_alive];
    flush_batch(&mut buf, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;

    let p_alive = get_proxy_by_id(&conn, &proxy.id).await.unwrap().unwrap();
    assert_eq!(p_alive.state, ProxyState::Alive);
    assert_eq!(p_alive.protocol, Some("socks5".to_string()));
    assert!(p_alive.supports_https);
    assert_eq!(p_alive.country, Some("FR".to_string()));
    assert_eq!(p_alive.rtt_total_ms, Some(50));
    assert_eq!(p_alive.checks_total, 1);
    assert_eq!(p_alive.checks_success, 1);
    assert_eq!(p_alive.dead_strikes, 0);

    // 3. Simulate first check failure -> Cooldown (strike 1 of 2)
    let cr_fail1 = CheckResult::failure(
        TargetHost::parse(&proxy.ip),
        proxy.port,
        ErrorReason::TimeoutTcp,
        CheckMetrics::default(),
    );
    let meta_fail1 = CheckResultWithMeta {
        proxy_id: proxy.id.clone(),
        result: cr_fail1,
        geoip: GeoIpResult::default(),
        recheck_alive_sec: proxy.recheck_alive_sec,
        recheck_dead_sec: proxy.recheck_dead_sec,
        max_dead_strikes: proxy.max_dead_strikes,
        current_strikes: 0,
        stability_window_min: proxy.stability_window_min,
        dead_backoff_mult: proxy.dead_backoff_mult,
        recent_checks: p_alive.recent_checks.clone(),
    };
    let mut buf = vec![meta_fail1];
    flush_batch(&mut buf, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;

    let p_cool = get_proxy_by_id(&conn, &proxy.id).await.unwrap().unwrap();
    assert_eq!(p_cool.state, ProxyState::Cooldown);
    assert_eq!(p_cool.dead_strikes, 1);
    assert_eq!(p_cool.last_error, Some("TIMEOUT_TCP".to_string()));

    // 4. Simulate second check failure -> DeadPermanent (strike 2 of 2)
    let cr_fail2 = CheckResult::failure(
        TargetHost::parse(&proxy.ip),
        proxy.port,
        ErrorReason::ConnRefused,
        CheckMetrics::default(),
    );
    let meta_fail2 = CheckResultWithMeta {
        proxy_id: proxy.id.clone(),
        result: cr_fail2,
        geoip: GeoIpResult::default(),
        recheck_alive_sec: proxy.recheck_alive_sec,
        recheck_dead_sec: proxy.recheck_dead_sec,
        max_dead_strikes: proxy.max_dead_strikes,
        current_strikes: 1, // current is now 1 -> next is 2 >= max
        stability_window_min: proxy.stability_window_min,
        dead_backoff_mult: proxy.dead_backoff_mult,
        recent_checks: p_cool.recent_checks.clone(),
    };
    let mut buf = vec![meta_fail2];
    flush_batch(&mut buf, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;

    let p_dead = get_proxy_by_id(&conn, &proxy.id).await.unwrap().unwrap();
    assert_eq!(p_dead.state, ProxyState::DeadPermanent);
    assert_eq!(p_dead.dead_strikes, 2);
    assert_eq!(p_dead.last_error, Some("CONN_REFUSED".to_string()));
}

#[tokio::test]
async fn test_batch_writer_transaction_failure_retains_buffer() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let (mut stmt_alive, mut stmt_dead) = prepare_batch_statements(&conn).await.unwrap();
    let stats = Arc::new(SchedulerStats::default());
    let now = Utc::now().timestamp();

    // 1. Insert initial cold_queue proxy
    let proxy = ProxyRow {
        id: "198.51.100.99:1080".to_string(),
        ip: "198.51.100.99".to_string(),
        port: 1080,
        auth_user: None,
        auth_pass: None,
        state: ProxyState::ColdQueue,
        protocol: None,
        supports_https: false,
        out_ip: None,
        country: None,
        asn: None,
        asn_org: None,
        anon: None,
        rtt_tcp_ms: None,
        rtt_handshake_ms: None,
        rtt_total_ms: None,
        connect_timeout_ms: 3000,
        handshake_timeout_ms: 4000,
        rw_timeout_ms: 5000,
        recheck_alive_sec: 60,
        recheck_dead_sec: 300,
        max_dead_strikes: 2,
        stability_window_min: 5,
        dead_backoff_mult: 1.5,
        checks_total: 0,
        checks_success: 0,
        dead_strikes: 0,
        last_error: None,
        stability_pct: 0.0,
        recent_checks: None,
        remark: None,
        first_seen_at: now,
        last_checked_at: None,
        next_check_at: now,
    };
    insert_proxy_if_not_exists(&conn, &proxy, false)
        .await
        .unwrap();

    let meta = CheckResultWithMeta {
        proxy_id: proxy.id.clone(),
        result: CheckResult::failure(
            TargetHost::parse(&proxy.ip),
            proxy.port,
            ErrorReason::TimeoutTcp,
            CheckMetrics::default(),
        ),
        geoip: GeoIpResult::default(),
        recheck_alive_sec: proxy.recheck_alive_sec,
        recheck_dead_sec: proxy.recheck_dead_sec,
        max_dead_strikes: proxy.max_dead_strikes,
        current_strikes: 0,
        stability_window_min: proxy.stability_window_min,
        dead_backoff_mult: proxy.dead_backoff_mult,
        recent_checks: proxy.recent_checks.clone(),
    };

    let mut buf = vec![meta];

    // Install an abort trigger to simulate write error in batch writer
    conn.execute(
        "CREATE TRIGGER test_fail_update BEFORE UPDATE ON proxies
         BEGIN
             SELECT RAISE(ABORT, 'simulated write error');
         END;",
        (),
    )
    .await
    .unwrap();

    // Flush batch should fail due to trigger, rollback, and KEEP items in buffer
    flush_batch(&mut buf, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;

    assert_eq!(
        buf.len(),
        1,
        "Buffer must retain items when transaction rolls back"
    );
    assert_eq!(
        stats
            .batch_buffer_size
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Drop trigger so subsequent flush can succeed
    conn.execute("DROP TRIGGER test_fail_update;", ())
        .await
        .unwrap();

    // Now flush should succeed and clear buffer
    flush_batch(&mut buf, &conn, &mut stmt_alive, &mut stmt_dead, &stats).await;

    assert_eq!(buf.len(), 0, "Buffer should be cleared on success");
    assert_eq!(
        stats
            .batch_buffer_size
            .load(std::sync::atomic::Ordering::Relaxed),
        0
    );
    assert_eq!(
        stats
            .checks_completed
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );
}

#[test]
fn test_stability_window_calculation_and_expiration() {
    let now = 10_000i64;
    let window_min = 5; // 300 seconds

    // 1. Initial check (success) -> 100%
    let (h1, p1) = update_recent_checks(None, true, now, window_min);
    assert_eq!(p1, 100.0);
    assert_eq!(h1, format!("{now}:1"));

    // 2. Second check 60s later (success) -> 100%
    let (h2, p2) = update_recent_checks(Some(&h1), true, now + 60, window_min);
    assert_eq!(p2, 100.0);
    assert_eq!(h2, format!("{now}:1,{}:1", now + 60));

    // 3. Third check 60s later (failure) -> 2 out of 3 = 66.66667%
    let (h3, p3) = update_recent_checks(Some(&h2), false, now + 120, window_min);
    assert!((p3 - 66.66667).abs() < 0.01);

    // 4. Fourth check 60s later (success) -> 3 out of 4 = 75.0%
    let (h4, p4) = update_recent_checks(Some(&h3), true, now + 180, window_min);
    assert_eq!(p4, 75.0);

    // 5. Check at now + 350s (success) -> first check (at now) is 350s old (> 300s window), so dropped!
    // Remaining in window: now+60 (ok), now+120 (fail), now+180 (ok), now+350 (ok) -> 3 out of 4 = 75.0%
    let (h5, p5) = update_recent_checks(Some(&h4), true, now + 350, window_min);
    assert_eq!(p5, 75.0);
    assert!(!h5.contains(&format!("{now}:1"))); // original check dropped
    assert!(h5.contains(&format!("{}:1", now + 60)));
    assert!(h5.contains(&format!("{}:0", now + 120)));
    assert!(h5.contains(&format!("{}:1", now + 180)));
    assert!(h5.contains(&format!("{}:1", now + 350)));

    // 6. Proxy revived after a long downtime (e.g. 1 hour later) -> previous checks all expire!
    let (h6, p6) = update_recent_checks(Some(&h5), true, now + 5000, window_min);
    assert_eq!(p6, 100.0);
    assert_eq!(h6, format!("{}:1", now + 5000));
}

#[test]
fn test_exponential_dead_backoff_calculation() {
    use hydra_api::services::batch_writer::calculate_dead_next_check;

    let now = 10_000i64;
    let base_sec = 300u32; // 5 minutes

    // 1. Multiplier 2.0 (doubling delay)
    // Strike 1: delay = 300 * 2^0 = 300
    assert_eq!(calculate_dead_next_check(now, base_sec, 2.0, 1), now + 300);
    // Strike 2: delay = 300 * 2^1 = 600
    assert_eq!(calculate_dead_next_check(now, base_sec, 2.0, 2), now + 600);
    // Strike 3: delay = 300 * 2^2 = 1200
    assert_eq!(calculate_dead_next_check(now, base_sec, 2.0, 3), now + 1200);
    // Strike 4: delay = 300 * 2^3 = 2400
    assert_eq!(calculate_dead_next_check(now, base_sec, 2.0, 4), now + 2400);

    // 2. Multiplier 1.5 (default)
    // Strike 1: 300 * 1.5^0 = 300
    assert_eq!(calculate_dead_next_check(now, base_sec, 1.5, 1), now + 300);
    // Strike 2: 300 * 1.5^1 = 450
    assert_eq!(calculate_dead_next_check(now, base_sec, 1.5, 2), now + 450);
    // Strike 3: 300 * 1.5^2 = 675
    assert_eq!(calculate_dead_next_check(now, base_sec, 1.5, 3), now + 675);

    // 3. Multiplier 1.0 or less -> fixed interval (no backoff)
    assert_eq!(calculate_dead_next_check(now, base_sec, 1.0, 1), now + 300);
    assert_eq!(calculate_dead_next_check(now, base_sec, 1.0, 5), now + 300);
    assert_eq!(calculate_dead_next_check(now, base_sec, 0.5, 5), now + 300);

    // 4. recheck_dead_sec == 0 -> permanent (365 days)
    assert_eq!(calculate_dead_next_check(now, 0, 2.0, 1), now + 365 * 86400);

    // 5. Huge strikes capped at 30 days
    assert_eq!(
        calculate_dead_next_check(now, base_sec, 2.0, 50),
        now + 30 * 86400
    );
}

#[tokio::test]
async fn test_continuous_scheduler_pipeline_and_shutdown() {
    let db = Arc::new(init_db(":memory:").await.unwrap());
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();

    let now = Utc::now().timestamp();

    // Insert 5 test proxies that are due for checking
    for i in 1..=5 {
        let proxy = ProxyRow {
            id: format!("127.0.0.1:{}", 9000 + i),
            ip: "127.0.0.1".to_string(),
            port: 9000 + i,
            auth_user: None,
            auth_pass: None,
            state: ProxyState::ColdQueue,
            protocol: None,
            supports_https: false,
            out_ip: None,
            country: None,
            asn: None,
            asn_org: None,
            anon: None,
            rtt_tcp_ms: None,
            rtt_handshake_ms: None,
            rtt_total_ms: None,
            connect_timeout_ms: 100,
            handshake_timeout_ms: 100,
            rw_timeout_ms: 100,
            recheck_alive_sec: 60,
            recheck_dead_sec: 300,
            max_dead_strikes: 2,
            stability_window_min: 5,
            dead_backoff_mult: 1.5,
            checks_total: 0,
            checks_success: 0,
            dead_strikes: 0,
            last_error: None,
            stability_pct: 0.0,
            recent_checks: None,
            remark: None,
            first_seen_at: now,
            last_checked_at: None,
            next_check_at: now,
        };
        insert_proxy_if_not_exists(&conn, &proxy, false)
            .await
            .unwrap();
    }

    let checker_config = CheckerConfig::builder(
        "http://127.0.0.1:8080".parse().unwrap(),
        "https://127.0.0.1:8443".parse().unwrap(),
        "test_judge_token",
    )
    .build()
    .await
    .unwrap();
    let engine = Arc::new(CheckerEngine::new(checker_config).unwrap());

    let (result_tx, mut result_rx) = mpsc::unbounded_channel();
    let scheduler_stats = Arc::new(SchedulerStats::default());

    let config = Arc::new(ApiConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        api_key: "test_key".to_string(),
        db_path: ":memory:".to_string(),
        judge_http_url: "http://127.0.0.1:8080".to_string(),
        judge_https_url: "https://127.0.0.1:8443".to_string(),
        judge_secret_token: "test_judge_token".to_string(),
        judge_secret_key: None,
        checker_concurrency: 5,
        enable_third_party_judges: false,
        enable_builtin_judge: false,
        judge_health_check_interval_secs: 30,
        judge_selection_strategy: "priority".to_string(),
        additional_judges: None,
        embed_judge: false,
        embed_judge_port: 8080,
        geoip_country_path: None,
        geoip_asn_path: None,
        geoip_reload_secs: 3600,
        geoip_auto_update: false,
        geoip_update_interval_secs: 86400,
        geoip_country_url: "https://example.com/country.mmdb.gz".to_string(),
        geoip_asn_url: "https://example.com/asn.mmdb.gz".to_string(),
        scheduler_batch_size: 10,
        batch_flush_interval_ms: 100,
        dead_proxy_retention_days: 30,
        db_maintenance_interval_secs: 3600,
    });

    let state = AppState {
        config,
        db,
        engine,
        geoip: None,
        result_tx,
        scheduler_stats: scheduler_stats.clone(),
    };

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    let scheduler_handle = tokio::spawn(async move {
        scheduler_loop(state, cancel_clone).await;
    });

    // Receive the 5 results processed by the pipeline
    let mut received_count = 0;
    while received_count < 5 {
        tokio::select! {
            res = result_rx.recv() => {
                if res.is_some() {
                    received_count += 1;
                } else {
                    break;
                }
            }
            _ = tokio::time::sleep(Duration::from_secs(5)) => {
                break;
            }
        }
    }

    assert_eq!(received_count, 5, "Expected all 5 proxies to be processed by continuous pipeline");

    // Test graceful shutdown
    cancel.cancel();

    // The scheduler task should exit promptly
    let shutdown_result = tokio::time::timeout(Duration::from_secs(3), scheduler_handle).await;
    assert!(shutdown_result.is_ok(), "Scheduler must gracefully shut down within timeout");
}
