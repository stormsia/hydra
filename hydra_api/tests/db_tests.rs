use chrono::Utc;
use hydra_api::db::*;
use hydra_api::models::{PatchProxyRequest, ProxyFilterQuery, ProxyRow, ProxyState};

#[tokio::test]
async fn test_db_init_and_migrations() {
    let db = init_db(":memory:")
        .await
        .expect("Failed to init in-memory DB");
    let conn = db.connect().expect("Failed to connect");
    configure_conn(&conn).await.unwrap();

    // Verify tables exist
    let mut rows = conn
        .query(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;",
            (),
        )
        .await
        .expect("Query failed");

    let mut tables = Vec::new();
    while let Some(row) = rows.next().await.unwrap() {
        tables.push(row.get::<String>(0).unwrap());
    }

    assert!(tables.contains(&"proxies".to_string()));
    assert!(tables.contains(&"sources".to_string()));
    assert!(tables.contains(&"proxy_sources".to_string()));
}

#[tokio::test]
async fn test_sources_crud_and_cascade() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let now = Utc::now().timestamp();

    // 1. Upsert source
    let s1_id = upsert_source(
        &conn,
        "src_free",
        Some("http://free.list"),
        Some("Free proxies"),
        now,
    )
    .await
    .unwrap();
    assert!(s1_id > 0);

    // 2. Upsert same source updates remark/url without duplicate ID
    let s2_id = upsert_source(
        &conn,
        "src_free",
        Some("http://free.list/updated"),
        None,
        now,
    )
    .await
    .unwrap();
    assert_eq!(s1_id, s2_id);

    let src = get_source_by_name(&conn, "src_free")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(src.name, "src_free");
    assert_eq!(src.url, Some("http://free.list/updated".to_string()));
    assert_eq!(src.remark, Some("Free proxies".to_string()));

    // 3. Link proxy to source
    let proxy = ProxyRow {
        id: "198.51.100.1:8080".to_string(),
        ip: "198.51.100.1".to_string(),
        port: 8080,
        auth_user: None,
        auth_pass: None,
        state: ProxyState::Alive,
        protocol: Some("http".to_string()),
        supports_https: true,
        out_ip: Some("198.51.100.1".to_string()),
        country: Some("DE".to_string()),
        asn: Some(12345),
        asn_org: Some("Hetzner".to_string()),
        anon: Some("elite".to_string()),
        rtt_tcp_ms: Some(25),
        rtt_handshake_ms: Some(30),
        rtt_total_ms: Some(55),
        connect_timeout_ms: 3000,
        handshake_timeout_ms: 4000,
        rw_timeout_ms: 5000,
        recheck_alive_sec: 60,
        recheck_dead_sec: 1800,
        max_dead_strikes: 3,
        stability_window_min: 5,
        dead_backoff_mult: 1.5,
        checks_total: 10,
        checks_success: 10,
        dead_strikes: 0,
        last_error: None,
        stability_pct: 100.0,
        recent_checks: None,
        remark: None,
        first_seen_at: now,
        last_checked_at: Some(now),
        next_check_at: now + 60,
    };
    insert_proxy_if_not_exists(&conn, &proxy, false)
        .await
        .unwrap();
    link_proxy_to_source(&conn, &proxy.id, s1_id, now)
        .await
        .unwrap();

    let sources_for_p = get_sources_for_proxy(&conn, &proxy.id).await.unwrap();
    assert_eq!(sources_for_p, vec!["src_free".to_string()]);

    let source_details_for_p = get_source_details_for_proxy(&conn, &proxy.id)
        .await
        .unwrap();
    assert_eq!(source_details_for_p.len(), 1);
    assert_eq!(source_details_for_p[0].name, "src_free");
    assert_eq!(source_details_for_p[0].added_at, now);

    let stats = list_source_stats(&conn).await.unwrap();
    assert_eq!(stats.len(), 1);
    assert_eq!(stats[0].name, "src_free");
    assert_eq!(stats[0].total_proxies, 1);
    assert_eq!(stats[0].alive_proxies, 1);
    assert_eq!(stats[0].yield_pct, 100.0);
    assert_eq!(stats[0].created_at, now);
    assert_eq!(stats[0].last_added_at, Some(now));

    let single = get_source_stats_by_name(&conn, "src_free")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(single.name, "src_free");
    assert_eq!(single.total_proxies, 1);
    assert_eq!(single.created_at, now);

    // 4. Delete source cascades to proxy_sources and cleans up orphan proxies
    let deleted = delete_source(&conn, "src_free").await.unwrap();
    assert!(deleted);
    let p_after = get_proxy_by_id(&conn, &proxy.id).await.unwrap();
    assert!(p_after.is_none());
}

#[tokio::test]
async fn test_proxies_crud_and_query() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let now = Utc::now().timestamp();

    let p1 = ProxyRow {
        id: "198.51.100.2:1080:usr:pwd".to_string(),
        ip: "198.51.100.2".to_string(),
        port: 1080,
        auth_user: Some("usr".to_string()),
        auth_pass: Some("pwd".to_string()),
        state: ProxyState::Alive,
        protocol: Some("socks5".to_string()),
        supports_https: true,
        out_ip: Some("198.51.100.2".to_string()),
        country: Some("US".to_string()),
        asn: Some(54321),
        asn_org: Some("DigitalOcean".to_string()),
        anon: Some("anonymous".to_string()),
        rtt_tcp_ms: Some(40),
        rtt_handshake_ms: Some(50),
        rtt_total_ms: Some(90),
        connect_timeout_ms: 3000,
        handshake_timeout_ms: 4000,
        rw_timeout_ms: 5000,
        recheck_alive_sec: 60,
        recheck_dead_sec: 1800,
        max_dead_strikes: 3,
        stability_window_min: 5,
        dead_backoff_mult: 1.5,
        checks_total: 5,
        checks_success: 4,
        dead_strikes: 0,
        last_error: None,
        stability_pct: 80.0,
        recent_checks: None,
        remark: Some("Premium US".to_string()),
        first_seen_at: now,
        last_checked_at: Some(now),
        next_check_at: now + 60,
    };
    assert!(insert_proxy_if_not_exists(&conn, &p1, false).await.unwrap());

    // Fetch by id
    let fetched = get_proxy_by_id(&conn, &p1.id).await.unwrap().unwrap();
    assert_eq!(fetched.id, "198.51.100.2:1080:usr:pwd");
    assert_eq!(fetched.auth_user, Some("usr".to_string()));
    assert_eq!(fetched.auth_pass, Some("pwd".to_string()));
    assert_eq!(fetched.state, ProxyState::Alive);

    // Query with filters
    let filter = ProxyFilterQuery {
        state: Some(ProxyState::Alive),
        country: Some("US".to_string()),
        exclude_country: None,
        protocol: Some("socks5".to_string()),
        anon: None,
        supports_https: Some(true),
        has_auth: Some(true),
        max_rtt: Some(150),
        min_uptime: Some(70.0),
        min_stability: None,
        stability_window_min: None,
        source: None,
        limit: Some(10),
        offset: Some(0),
    };
    let items = query_proxies(&conn, &filter).await.unwrap();
    assert_eq!(items.len(), 1);
    assert_eq!(items[0].id, "198.51.100.2:1080:usr:pwd");
    assert_eq!(items[0].ip, "198.51.100.2");
    assert_eq!(items[0].port, 1080);
    assert_eq!(items[0].url, "socks5://usr:pwd@198.51.100.2:1080");
    assert!(items[0].has_auth);
    assert_eq!(items[0].auth_user, Some("usr".to_string()));
    assert_eq!(items[0].auth_pass, Some("pwd".to_string()));
    assert_eq!(items[0].uptime_pct, 80.0);
    assert_eq!(items[0].stability_pct, 80.0);
    assert_eq!(items[0].stability_window_min, 5);
    assert_eq!(items[0].state, ProxyState::Alive);
    assert_eq!(items[0].checks_total, 5);
    assert_eq!(items[0].checks_success, 4);
    assert_eq!(items[0].dead_strikes, 0);
    assert_eq!(items[0].first_seen_at, now);
    assert_eq!(items[0].remark, Some("Premium US".to_string()));

    // Filter with has_auth = false should return empty
    let filter_no_auth = ProxyFilterQuery {
        state: Some(ProxyState::Alive),
        country: None,
        exclude_country: None,
        protocol: None,
        anon: None,
        supports_https: None,
        has_auth: Some(false),
        max_rtt: None,
        min_uptime: None,
        min_stability: None,
        stability_window_min: None,
        source: None,
        limit: Some(10),
        offset: Some(0),
    };
    let no_auth_items = query_proxies(&conn, &filter_no_auth).await.unwrap();
    assert_eq!(no_auth_items.len(), 0);

    // Patch proxy
    let patch = PatchProxyRequest {
        remark: Some("Updated remark".to_string()),
        auth_user: Some("new_usr".to_string()),
        auth_pass: Some("new_pwd".to_string()),
        ignore_protocol: Some(true),
        policy: None,
        force_recheck: Some(true),
    };
    assert!(patch_proxy(&conn, &p1.id, &patch, now).await.unwrap());
    let patched = get_proxy_by_id(&conn, &p1.id).await.unwrap().unwrap();
    assert_eq!(patched.remark, Some("Updated remark".to_string()));
    assert_eq!(patched.auth_user, Some("new_usr".to_string()));
    assert_eq!(patched.auth_pass, Some("new_pwd".to_string()));
    assert_eq!(patched.protocol, None); // ignore_protocol reset it to None
    assert_eq!(patched.next_check_at, now);

    // Report fail
    assert!(
        report_fail(&conn, &p1.id, "TIMEOUT_TCP", now)
            .await
            .unwrap()
    );
    let failed = get_proxy_by_id(&conn, &p1.id).await.unwrap().unwrap();
    assert_eq!(failed.state, ProxyState::Cooldown);
    assert_eq!(failed.dead_strikes, 1);
    assert_eq!(failed.last_error, Some("TIMEOUT_TCP".to_string()));

    // Delete proxy
    assert!(delete_proxy(&conn, &p1.id).await.unwrap());
    assert!(get_proxy_by_id(&conn, &p1.id).await.unwrap().is_none());
}

#[tokio::test]
async fn test_multicountry_csv_exclusion_and_limit_zero() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let now = Utc::now().timestamp();

    let make_proxy = |id: &str, country: Option<&str>| ProxyRow {
        id: id.to_string(),
        ip: id.split(':').next().unwrap().to_string(),
        port: 8080,
        auth_user: None,
        auth_pass: None,
        state: ProxyState::Alive,
        protocol: Some("http".to_string()),
        supports_https: true,
        out_ip: None,
        country: country.map(|s| s.to_string()),
        asn: None,
        asn_org: None,
        anon: Some("elite".to_string()),
        rtt_tcp_ms: Some(50),
        rtt_handshake_ms: Some(50),
        rtt_total_ms: Some(100),
        connect_timeout_ms: 3000,
        handshake_timeout_ms: 4000,
        rw_timeout_ms: 5000,
        recheck_alive_sec: 60,
        recheck_dead_sec: 1800,
        max_dead_strikes: 3,
        stability_window_min: 5,
        dead_backoff_mult: 1.5,
        checks_total: 10,
        checks_success: 10,
        dead_strikes: 0,
        last_error: None,
        stability_pct: 100.0,
        recent_checks: None,
        remark: None,
        first_seen_at: now,
        last_checked_at: Some(now),
        next_check_at: now + 60,
    };

    insert_proxy_if_not_exists(&conn, &make_proxy("10.0.0.1:8080", Some("DE")), false)
        .await
        .unwrap();
    insert_proxy_if_not_exists(&conn, &make_proxy("10.0.0.2:8080", Some("NL")), false)
        .await
        .unwrap();
    insert_proxy_if_not_exists(&conn, &make_proxy("10.0.0.3:8080", Some("FR")), false)
        .await
        .unwrap();
    insert_proxy_if_not_exists(&conn, &make_proxy("10.0.0.4:8080", Some("RU")), false)
        .await
        .unwrap();
    insert_proxy_if_not_exists(&conn, &make_proxy("10.0.0.5:8080", None), false)
        .await
        .unwrap();

    // 1. Query with multi-country CSV: DE,NL
    let filter_csv = ProxyFilterQuery {
        state: Some(ProxyState::Alive),
        country: Some("DE, NL".to_string()),
        exclude_country: None,
        protocol: None,
        anon: None,
        supports_https: None,
        has_auth: None,
        max_rtt: None,
        min_uptime: None,
        min_stability: None,
        stability_window_min: None,
        source: None,
        limit: Some(50),
        offset: Some(0),
    };
    let items = query_proxies(&conn, &filter_csv).await.unwrap();
    assert_eq!(items.len(), 2);
    let countries: Vec<_> = items
        .iter()
        .map(|i| i.country.as_deref().unwrap())
        .collect();
    assert!(countries.contains(&"DE"));
    assert!(countries.contains(&"NL"));

    // 2. Query with exclude_country: RU
    let filter_ex = ProxyFilterQuery {
        state: Some(ProxyState::Alive),
        country: None,
        exclude_country: Some("RU".to_string()),
        protocol: None,
        anon: None,
        supports_https: None,
        has_auth: None,
        max_rtt: None,
        min_uptime: None,
        min_stability: None,
        stability_window_min: None,
        source: None,
        limit: Some(50),
        offset: Some(0),
    };
    let ex_items = query_proxies(&conn, &filter_ex).await.unwrap();
    assert_eq!(ex_items.len(), 4); // DE, NL, FR, None
    assert!(ex_items.iter().all(|i| i.country.as_deref() != Some("RU")));

    // 3. Query with limit = 0 (unlimited for Proxy Gateway pool sync)
    let filter_zero = ProxyFilterQuery {
        state: Some(ProxyState::Alive),
        country: None,
        exclude_country: None,
        protocol: None,
        anon: None,
        supports_https: None,
        has_auth: None,
        max_rtt: None,
        min_uptime: None,
        min_stability: None,
        stability_window_min: None,
        source: None,
        limit: Some(0),
        offset: Some(0),
    };
    let all_items = query_proxies(&conn, &filter_zero).await.unwrap();
    assert_eq!(all_items.len(), 5);
}

#[tokio::test]
async fn test_batch_report_fail_and_db_maintenance() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let now = Utc::now().timestamp();

    let make_proxy = |id: &str, state: ProxyState, last_checked: Option<i64>| ProxyRow {
        id: id.to_string(),
        ip: id.split(':').next().unwrap().to_string(),
        port: 8080,
        auth_user: None,
        auth_pass: None,
        state,
        protocol: Some("http".to_string()),
        supports_https: true,
        out_ip: None,
        country: Some("DE".to_string()),
        asn: None,
        asn_org: None,
        anon: Some("elite".to_string()),
        rtt_tcp_ms: Some(50),
        rtt_handshake_ms: Some(50),
        rtt_total_ms: Some(100),
        connect_timeout_ms: 3000,
        handshake_timeout_ms: 4000,
        rw_timeout_ms: 5000,
        recheck_alive_sec: 60,
        recheck_dead_sec: 1800,
        max_dead_strikes: 3,
        stability_window_min: 5,
        dead_backoff_mult: 1.5,
        checks_total: 10,
        checks_success: 10,
        dead_strikes: 0,
        last_error: None,
        stability_pct: 100.0,
        recent_checks: None,
        remark: None,
        first_seen_at: now - 10000,
        last_checked_at: last_checked,
        next_check_at: now + 60,
    };

    // Insert 2 alive proxies
    insert_proxy_if_not_exists(
        &conn,
        &make_proxy("1.1.1.1:8080", ProxyState::Alive, Some(now)),
        false,
    )
    .await
    .unwrap();
    insert_proxy_if_not_exists(
        &conn,
        &make_proxy("2.2.2.2:8080", ProxyState::Alive, Some(now)),
        false,
    )
    .await
    .unwrap();

    // Batch report fail on both
    let reported = report_fails_batch(
        &conn,
        &[
            "1.1.1.1:8080".to_string(),
            "2.2.2.2:8080".to_string(),
            "nonexistent:8080".to_string(),
        ],
        "GATEWAY_TARGET_ERROR",
        now,
    )
    .await
    .unwrap();

    assert_eq!(reported.len(), 2);
    assert!(reported.contains(&"1.1.1.1:8080".to_string()));
    assert!(reported.contains(&"2.2.2.2:8080".to_string()));

    let p1 = get_proxy_by_id(&conn, "1.1.1.1:8080")
        .await
        .unwrap()
        .unwrap();
    assert_eq!(p1.state, ProxyState::Cooldown);
    assert_eq!(p1.dead_strikes, 1);
    assert_eq!(p1.last_error, Some("GATEWAY_TARGET_ERROR".to_string()));

    // Insert dead_permanent proxies: one 40 days old, one 5 days old
    let forty_days_ago = now - (40 * 86400);
    let five_days_ago = now - (5 * 86400);

    insert_proxy_if_not_exists(
        &conn,
        &make_proxy(
            "dead.old:8080",
            ProxyState::DeadPermanent,
            Some(forty_days_ago),
        ),
        false,
    )
    .await
    .unwrap();
    insert_proxy_if_not_exists(
        &conn,
        &make_proxy(
            "dead.recent:8080",
            ProxyState::DeadPermanent,
            Some(five_days_ago),
        ),
        false,
    )
    .await
    .unwrap();

    // Run maintenance with retention = 30 days
    let stats = run_db_maintenance(&conn, 30).await.unwrap();
    assert_eq!(stats.purged_dead_proxies, 1);

    // Verify 40 days old is purged, 5 days old is preserved
    assert!(
        get_proxy_by_id(&conn, "dead.old:8080")
            .await
            .unwrap()
            .is_none()
    );
    assert!(
        get_proxy_by_id(&conn, "dead.recent:8080")
            .await
            .unwrap()
            .is_some()
    );
}

#[tokio::test]
async fn test_indexes_and_query_plans() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();

    // Verify pragmas
    let mut rows = conn.query("PRAGMA foreign_keys;", ()).await.unwrap();
    let fk: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(fk, 1, "foreign_keys should be ON");

    let mut rows = conn.query("PRAGMA auto_vacuum;", ()).await.unwrap();
    let av: i64 = rows.next().await.unwrap().unwrap().get(0).unwrap();
    assert_eq!(av, 2, "auto_vacuum should be 2 (INCREMENTAL)");

    // 1. EXPLAIN QUERY PLAN for fetch_due_proxies query
    let sql_scheduler = "
        EXPLAIN QUERY PLAN
        SELECT id FROM proxies
        WHERE state IN (0, 1, 2) AND next_check_at <= ?1
        ORDER BY
          CASE state WHEN 1 THEN 0 WHEN 0 THEN 1 ELSE 2 END,
          next_check_at ASC
        LIMIT ?2;
    ";
    let mut plan_rows = conn
        .query(sql_scheduler, libsql::params![1000i64, 100i64])
        .await
        .unwrap();
    let mut plan_details = Vec::new();
    while let Some(row) = plan_rows.next().await.unwrap() {
        let detail: String = row.get(3).unwrap();
        plan_details.push(detail);
    }
    let combined_plan = plan_details.join(" | ");
    println!("Scheduler plan: {combined_plan}");
    assert!(
        combined_plan.contains("idx_scheduler_prio"),
        "Scheduler query should use idx_scheduler_prio, got: {combined_plan}"
    );
    assert!(
        !combined_plan.contains("USE TEMP B-TREE FOR ORDER BY"),
        "Scheduler query must not use temporary B-tree for sorting, got: {combined_plan}"
    );

    // 2. EXPLAIN QUERY PLAN for fastest alive proxies
    let sql_fastest = "
        EXPLAIN QUERY PLAN
        SELECT id FROM proxies
        WHERE state = 1
        ORDER BY rtt_total_ms ASC
        LIMIT 100;
    ";
    let mut plan_rows = conn.query(sql_fastest, ()).await.unwrap();
    let mut plan_details = Vec::new();
    while let Some(row) = plan_rows.next().await.unwrap() {
        let detail: String = row.get(3).unwrap();
        plan_details.push(detail);
    }
    let combined_plan = plan_details.join(" | ");
    println!("Fastest alive plan: {combined_plan}");
    assert!(
        combined_plan.contains("idx_alive_fastest"),
        "Fastest alive query should use idx_alive_fastest, got: {combined_plan}"
    );
    assert!(
        !combined_plan.contains("USE TEMP B-TREE FOR ORDER BY"),
        "Fastest alive query must not use temporary B-tree for sorting, got: {combined_plan}"
    );

    // 3. EXPLAIN QUERY PLAN for dead purge
    let sql_purge = "
        EXPLAIN QUERY PLAN
        SELECT id FROM proxies
        WHERE state = 3 AND last_checked_at IS NOT NULL AND last_checked_at < ?1;
    ";
    let mut plan_rows = conn
        .query(sql_purge, libsql::params![1000i64])
        .await
        .unwrap();
    let mut plan_details = Vec::new();
    while let Some(row) = plan_rows.next().await.unwrap() {
        let detail: String = row.get(3).unwrap();
        plan_details.push(detail);
    }
    let combined_plan = plan_details.join(" | ");
    println!("Dead purge plan: {combined_plan}");
    assert!(
        combined_plan.contains("idx_dead_purge"),
        "Dead purge query should use idx_dead_purge, got: {combined_plan}"
    );
}

#[tokio::test]
async fn test_stability_filtering_and_window_queries() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let now = Utc::now().timestamp();

    let make_proxy = |id: &str, last_checked: Option<i64>, stab_pct: f32, win_min: u32| ProxyRow {
        id: id.to_string(),
        ip: id.split(':').next().unwrap().to_string(),
        port: 8080,
        auth_user: None,
        auth_pass: None,
        state: ProxyState::Alive,
        protocol: Some("socks5".to_string()),
        supports_https: true,
        out_ip: None,
        country: Some("US".to_string()),
        asn: None,
        asn_org: None,
        anon: Some("elite".to_string()),
        rtt_tcp_ms: Some(30),
        rtt_handshake_ms: Some(40),
        rtt_total_ms: Some(70),
        connect_timeout_ms: 3000,
        handshake_timeout_ms: 4000,
        rw_timeout_ms: 5000,
        recheck_alive_sec: 15,
        recheck_dead_sec: 300,
        max_dead_strikes: 3,
        stability_window_min: win_min,
        dead_backoff_mult: 1.5,
        checks_total: 100,
        checks_success: 10, // Lifetime uptime is low (10%)!
        dead_strikes: 0,
        last_error: None,
        stability_pct: stab_pct,
        recent_checks: None,
        remark: None,
        first_seen_at: now - 3600,
        last_checked_at: last_checked,
        next_check_at: now + 15,
    };

    // 1. Just revived proxy: checked 30s ago, 100% stable in 5m window
    insert_proxy_if_not_exists(
        &conn,
        &make_proxy("198.51.100.101:8080", Some(now - 30), 100.0, 5),
        false,
    )
    .await
    .unwrap();
    // 2. Flickering proxy: checked 30s ago, 50% stable in 5m window
    insert_proxy_if_not_exists(
        &conn,
        &make_proxy("198.51.100.102:8080", Some(now - 30), 50.0, 5),
        false,
    )
    .await
    .unwrap();
    // 3. Expired proxy: last checked 10m ago (outside 5m window)
    insert_proxy_if_not_exists(
        &conn,
        &make_proxy("198.51.100.103:8080", Some(now - 600), 100.0, 5),
        false,
    )
    .await
    .unwrap();
    // 4. Proxy with 10m window: checked 7m ago, 100% stable in 10m window
    insert_proxy_if_not_exists(
        &conn,
        &make_proxy("198.51.100.104:8080", Some(now - 420), 100.0, 10),
        false,
    )
    .await
    .unwrap();

    // Query 1: Filter by min_stability = 90.0
    // Must return the recently revived 100% stable proxy (198.51.100.101) and the 10m window proxy (198.51.100.104)
    // Must EXCLUDE 198.51.100.102 (50% < 90%) and 198.51.100.103 (last checked 10m ago > 5m window)
    let q_high = ProxyFilterQuery {
        min_stability: Some(90.0),
        ..Default::default()
    };
    let items_high = query_proxies(&conn, &q_high).await.unwrap();
    assert_eq!(items_high.len(), 2);
    let ids: Vec<_> = items_high.iter().map(|i| i.id.as_str()).collect();
    assert!(ids.contains(&"198.51.100.101:8080"));
    assert!(ids.contains(&"198.51.100.104:8080"));

    // Verify proxy that "just came alive" has 10% lifetime uptime but 100% window stability
    let revived = items_high
        .iter()
        .find(|i| i.id == "198.51.100.101:8080")
        .unwrap();
    assert_eq!(revived.uptime_pct, 10.0);
    assert_eq!(revived.stability_pct, 100.0);
    assert_eq!(revived.stability_window_min, 5);

    // Query 2: Filter by min_stability = 90.0 AND stability_window_min = 5
    let q_window5 = ProxyFilterQuery {
        min_stability: Some(90.0),
        stability_window_min: Some(5),
        ..Default::default()
    };
    let items_win5 = query_proxies(&conn, &q_window5).await.unwrap();
    assert_eq!(items_win5.len(), 1);
    assert_eq!(items_win5[0].id, "198.51.100.101:8080");

    // Query 3: All proxies without stability filter -> verify expired proxy receives effective stability 0.0
    let q_all = ProxyFilterQuery::default();
    let all_items = query_proxies(&conn, &q_all).await.unwrap();
    assert_eq!(all_items.len(), 4);
    let expired = all_items
        .iter()
        .find(|i| i.id == "198.51.100.103:8080")
        .unwrap();
    assert_eq!(
        expired.stability_pct, 0.0,
        "Expired check must result in 0.0 effective stability"
    );
}

#[tokio::test]
async fn test_fetch_due_proxies_fair_share_and_longest_waiting() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let now = 1000i64;

    fn make_proxy(id: &str, state: ProxyState, next_check_at: i64, first_seen_at: i64) -> ProxyRow {
        ProxyRow {
            id: id.to_string(),
            ip: "192.0.2.1".to_string(),
            port: 8080,
            auth_user: None,
            auth_pass: None,
            state,
            protocol: Some("http".to_string()),
            supports_https: true,
            out_ip: None,
            country: Some("US".to_string()),
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
            recheck_dead_sec: 1800,
            max_dead_strikes: 3,
            stability_window_min: 5,
            dead_backoff_mult: 1.5,
            checks_total: 0,
            checks_success: 0,
            dead_strikes: 0,
            last_error: None,
            stability_pct: 0.0,
            recent_checks: None,
            remark: None,
            first_seen_at,
            last_checked_at: None,
            next_check_at,
        }
    }

    // Insert 10 Cold proxies (state = 0) with next_check_at <= now
    for i in 1..=10 {
        let p = make_proxy(&format!("10.0.0.{i}:80"), ProxyState::ColdQueue, 900 + i, 800 + i);
        insert_proxy_if_not_exists(&conn, &p, false).await.unwrap();
    }

    // Insert 10 Alive proxies (state = 1) with next_check_at <= now
    for i in 1..=10 {
        let p = make_proxy(&format!("20.0.0.{i}:80"), ProxyState::Alive, 700 + i, 600 + i);
        insert_proxy_if_not_exists(&conn, &p, false).await.unwrap();
    }

    // Insert 5 Cooldown proxies (state = 2) with next_check_at <= now
    for i in 1..=5 {
        let p = make_proxy(&format!("30.0.0.{i}:80"), ProxyState::Cooldown, 500 + i, 400 + i);
        insert_proxy_if_not_exists(&conn, &p, false).await.unwrap();
    }

    // Case 1: Limit = 10. Cold quota = 7 (70%), Recheck = 3 (30%)
    let due = fetch_due_proxies(&conn, now, 10).await.unwrap();
    assert_eq!(due.len(), 10);
    let cold_count = due.iter().filter(|p| p.state == ProxyState::ColdQueue).count();
    let alive_count = due.iter().filter(|p| p.state == ProxyState::Alive).count();
    let cooldown_count = due.iter().filter(|p| p.state == ProxyState::Cooldown).count();

    assert_eq!(cold_count, 7, "Exactly 70% (7 slots) must be reserved for Cold queue");
    assert_eq!(alive_count, 3, "Remaining 3 slots must be given to Recheck (Alive prioritized over Cooldown)");
    assert_eq!(cooldown_count, 0);

    // Verify ordering in Recheck: Alive proxies waiting the longest (smallest next_check_at) come first!
    let alive_ids: Vec<&str> = due.iter().filter(|p| p.state == ProxyState::Alive).map(|p| p.id.as_str()).collect();
    assert_eq!(alive_ids, vec!["20.0.0.1:80", "20.0.0.2:80", "20.0.0.3:80"]);

    // Verify lease pattern: all fetched proxies are leased for 60 seconds (next_check_at = now + 60)
    for p in &due {
        assert_eq!(p.next_check_at, now + 60, "Fetched proxies must be leased until now + 60");
    }

    // Reset next_check_at to original timestamps to test Case 2 on the full pool
    for i in 1..=10 {
        conn.execute("UPDATE proxies SET next_check_at = ?1 WHERE id = ?2;", libsql::params![900 + i, format!("10.0.0.{i}:80")]).await.unwrap();
        conn.execute("UPDATE proxies SET next_check_at = ?1 WHERE id = ?2;", libsql::params![700 + i, format!("20.0.0.{i}:80")]).await.unwrap();
    }
    for i in 1..=5 {
        conn.execute("UPDATE proxies SET next_check_at = ?1 WHERE id = ?2;", libsql::params![500 + i, format!("30.0.0.{i}:80")]).await.unwrap();
    }

    // Case 2: Zero-waste backfill when Recheck has fewer items than its capacity
    // Query limit = 20: Cold has 10 (hits its 70% quota of 14), Recheck has 10 alive + 5 cooldown = 15.
    let due20 = fetch_due_proxies(&conn, now, 20).await.unwrap();
    assert_eq!(due20.len(), 20);
    let cold_count20 = due20.iter().filter(|p| p.state == ProxyState::ColdQueue).count();
    let recheck_count20 = due20.iter().filter(|p| p.state != ProxyState::ColdQueue).count();
    assert_eq!(cold_count20, 10, "All available 10 cold proxies should be fetched");
    assert_eq!(recheck_count20, 10, "Remaining 10 slots filled by Recheck");
}

#[tokio::test]
async fn test_fetch_due_proxies_lease_mechanism() {
    let db = init_db(":memory:").await.unwrap();
    let conn = db.connect().unwrap();
    configure_conn(&conn).await.unwrap();
    let now = 1000i64;

    fn make_proxy(id: &str, next_check_at: i64) -> ProxyRow {
        ProxyRow {
            id: id.to_string(),
            ip: "192.0.2.1".to_string(),
            port: 8080,
            auth_user: None,
            auth_pass: None,
            state: ProxyState::ColdQueue,
            protocol: Some("http".to_string()),
            supports_https: true,
            out_ip: None,
            country: Some("US".to_string()),
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
            recheck_dead_sec: 1800,
            max_dead_strikes: 3,
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
            next_check_at,
        }
    }

    insert_proxy_if_not_exists(&conn, &make_proxy("1.1.1.1:80", 1000), false).await.unwrap();
    insert_proxy_if_not_exists(&conn, &make_proxy("2.2.2.2:80", 1000), false).await.unwrap();

    // 1. Fetch with now = 1000 -> returns both proxies and leases them until 1060
    let fetched = fetch_due_proxies(&conn, now, 10).await.unwrap();
    assert_eq!(fetched.len(), 2);
    assert_eq!(fetched[0].next_check_at, 1060);
    assert_eq!(fetched[1].next_check_at, 1060);

    // Verify DB reflects next_check_at = 1060
    let p1 = get_proxy_by_id(&conn, "1.1.1.1:80").await.unwrap().unwrap();
    assert_eq!(p1.next_check_at, 1060);

    // 2. Immediate re-fetch at now = 1000 -> returns 0 (both are currently leased)
    let leased = fetch_due_proxies(&conn, now, 10).await.unwrap();
    assert_eq!(leased.len(), 0);

    // 3. Re-fetch at now = 1059 -> returns 0 (lease still active)
    let leased_59 = fetch_due_proxies(&conn, 1059, 10).await.unwrap();
    assert_eq!(leased_59.len(), 0);

    // 4. Re-fetch at now = 1060 -> lease expired, both returned again!
    let expired = fetch_due_proxies(&conn, 1060, 10).await.unwrap();
    assert_eq!(expired.len(), 2);
    assert_eq!(expired[0].next_check_at, 1120);
    assert_eq!(expired[1].next_check_at, 1120);

    // 5. Proxy with custom large timeouts: (10s + 10s + 10s) * 4 protocols = 120s lease
    let mut custom_large_proxy = make_proxy("3.3.3.3:80", 2000);
    custom_large_proxy.connect_timeout_ms = 10000;
    custom_large_proxy.handshake_timeout_ms = 10000;
    custom_large_proxy.rw_timeout_ms = 10000;
    insert_proxy_if_not_exists(&conn, &custom_large_proxy, false).await.unwrap();

    let fetched_custom = fetch_due_proxies(&conn, 2000, 10).await.unwrap();
    let p3 = fetched_custom.iter().find(|p| p.id == "3.3.3.3:80").unwrap();
    assert_eq!(p3.next_check_at, 2120); // 2000 + 120s
}
