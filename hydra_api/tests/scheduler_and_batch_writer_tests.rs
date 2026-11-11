use std::sync::Arc;
use chrono::Utc;
use hydra_checker::{
    AnonymityLevel, CheckMetrics, CheckResult, ErrorReason, ProxyProtocol, TargetHost,
};
use hydra_api::app_state::SchedulerStats;
use hydra_api::db::*;
use hydra_api::models::{ProxyRow, ProxyState};
use hydra_api::services::batch_writer::{flush_batch, CheckResultWithMeta};
use hydra_api::services::geoip::GeoIpResult;
use hydra_api::services::scheduler::row_to_target;

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
        checks_total: 0,
        checks_success: 0,
        dead_strikes: 0,
        last_error: None,
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
        checks_total: 0,
        checks_success: 0,
        dead_strikes: 0,
        last_error: None,
        remark: None,
        first_seen_at: now,
        last_checked_at: None,
        next_check_at: now,
    };
    insert_proxy_if_not_exists(&conn, &proxy, false).await.unwrap();

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
    };

    let mut buf = vec![meta_alive];
    flush_batch(&mut buf, &db, &stats).await;

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
    };
    let mut buf = vec![meta_fail1];
    flush_batch(&mut buf, &db, &stats).await;

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
    };
    let mut buf = vec![meta_fail2];
    flush_batch(&mut buf, &db, &stats).await;

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
        checks_total: 0,
        checks_success: 0,
        dead_strikes: 0,
        last_error: None,
        remark: None,
        first_seen_at: now,
        last_checked_at: None,
        next_check_at: now,
    };
    insert_proxy_if_not_exists(&conn, &proxy, false).await.unwrap();

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
    flush_batch(&mut buf, &db, &stats).await;

    assert_eq!(buf.len(), 1, "Buffer must retain items when transaction rolls back");
    assert_eq!(stats.batch_buffer_size.load(std::sync::atomic::Ordering::Relaxed), 1);

    // Drop trigger so subsequent flush can succeed
    conn.execute("DROP TRIGGER test_fail_update;", ()).await.unwrap();

    // Now flush should succeed and clear buffer
    flush_batch(&mut buf, &db, &stats).await;

    assert_eq!(buf.len(), 0, "Buffer should be cleared on success");
    assert_eq!(stats.batch_buffer_size.load(std::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.checks_completed.load(std::sync::atomic::Ordering::Relaxed), 1);
}
