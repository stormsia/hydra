use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use hydra_api::app_state::{AppState, SchedulerStats};
use hydra_api::config::ApiConfig;
use hydra_api::db::init_db;
use hydra_api::models::{
    CheckPolicyDto, GlobalStatsResponse, ImportBatchRequest, ImportBatchResponse,
    PatchProxyRequest, ProxyFullDetails, ProxyInputItem, ProxyInputObject, ProxyShortItem,
    ReportFailRequest, SourceStatsItem,
};
use hydra_api::router::build_router;
use hydra_checker::{CheckerConfig, CheckerEngine};

async fn spawn_test_server() -> (String, String) {
    let api_key = "test_secret_key_12345".to_string();

    let db = Arc::new(init_db(":memory:").await.unwrap());

    // Dummy urls for checker config in test server
    let checker_config = CheckerConfig::builder(
        "http://127.0.0.1:8080".parse().unwrap(),
        "https://127.0.0.1:8443".parse().unwrap(),
        "test_judge_token",
    )
    .build()
    .await
    .unwrap();
    let engine = Arc::new(CheckerEngine::new(checker_config).unwrap());

    let (result_tx, _result_rx) = mpsc::unbounded_channel();
    let scheduler_stats = Arc::new(SchedulerStats::default());

    let config = Arc::new(ApiConfig {
        listen_addr: "127.0.0.1:0".parse().unwrap(),
        api_key: api_key.clone(),
        db_path: ":memory:".to_string(),
        judge_http_url: "http://127.0.0.1:8080".to_string(),
        judge_https_url: "https://127.0.0.1:8443".to_string(),
        judge_secret_token: "test_judge_token".to_string(),
        judge_secret_key: None,
        checker_concurrency: 50,
        enable_third_party_judges: true,
        enable_builtin_judge: true,
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
        scheduler_batch_size: 100,
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
        scheduler_stats,
    };

    let app = build_router(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();

    let cancel = CancellationToken::new();
    let cancel_clone = cancel.clone();

    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(async move {
                cancel_clone.cancelled().await;
            })
            .await
            .unwrap();
    });

    (format!("http://{addr}"), api_key)
}

#[tokio::test]
async fn test_full_api_workflow() {
    let (base_url, api_key) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // 1. Check OpenAPI specification endpoint (should not require auth)
    let openapi_res = client
        .get(format!("{base_url}/api-docs/openapi.json"))
        .send()
        .await
        .unwrap();
    assert_eq!(openapi_res.status(), 200);
    let openapi_json: serde_json::Value = openapi_res.json().await.unwrap();
    assert!(openapi_json.get("openapi").is_some());
    assert!(openapi_json.get("paths").is_some());

    // Verify all endpoints are grouped under Proxies, Sources, Stats without unmapped handlers::
    if let Some(paths) = openapi_json.get("paths").and_then(|p| p.as_object()) {
        for (_path, item) in paths {
            if let Some(ops) = item.as_object() {
                for (_method, op) in ops {
                    if let Some(tags) = op.get("tags").and_then(|t| t.as_array()) {
                        for t in tags {
                            let tag_str = t.as_str().unwrap();
                            assert!(
                                !tag_str.contains("handlers::"),
                                "Found unexpected unmapped tag: {tag_str}"
                            );
                            assert!(
                                tag_str == "Proxies"
                                    || tag_str == "Sources"
                                    || tag_str == "Stats"
                                    || tag_str == "Judges",
                                "Tag '{tag_str}' is not one of expected groups"
                            );
                        }
                    }
                }
            }
        }
    }

    // 2. Check Auth: No header -> 401
    let unauth_res = client
        .get(format!("{base_url}/api/v1/proxies"))
        .send()
        .await
        .unwrap();
    assert_eq!(unauth_res.status(), 401);

    // 3. Check Auth: Wrong key -> 401
    let wrong_auth_res = client
        .get(format!("{base_url}/api/v1/proxies"))
        .header("X-API-Key", "wrong_key")
        .send()
        .await
        .unwrap();
    assert_eq!(wrong_auth_res.status(), 401);

    // 4. Check Auth: Correct key -> 200
    let auth_res = client
        .get(format!("{base_url}/api/v1/proxies"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    let status = auth_res.status();
    let text = auth_res.text().await.unwrap();
    assert_eq!(status, 200, "Error body: {text}");

    // 5. Import proxies
    let import_req = ImportBatchRequest {
        source: "premium_source".to_string(),
        source_url: Some("https://proxies.example.com/list.txt".to_string()),
        remark: Some("Initial premium list".to_string()),
        revive_dead: true,
        ignore_protocol: false,
        policy: CheckPolicyDto::default(),
        proxies: vec![
            "185.22.14.10:8080".into(),
            "socks5://185.22.14.11:1080".into(),
            "http://user:pass@185.22.14.12:3128".into(),
            "invalid_proxy_format".into(),
        ],
    };

    let import_res = client
        .post(format!("{base_url}/api/v1/proxies/import"))
        .header("X-API-Key", &api_key)
        .json(&import_req)
        .send()
        .await
        .unwrap();

    assert_eq!(import_res.status(), 200);
    let import_data: ImportBatchResponse = import_res.json().await.unwrap();
    println!("Import data received: {:?}", import_data);
    assert_eq!(import_data.total_received, 4);
    assert_eq!(import_data.inserted_new, 3);
    assert_eq!(import_data.invalid_format, 1);

    // 6. Query imported proxies (state=cold_queue)
    let list_res = client
        .get(format!("{base_url}/api/v1/proxies?state=cold_queue"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(list_res.status(), 200);
    let list_data: Vec<ProxyShortItem> = list_res.json().await.unwrap();
    assert_eq!(list_data.len(), 3);

    let auth_item = list_data
        .iter()
        .find(|p| p.id == "185.22.14.12:3128:user:pass")
        .unwrap();
    assert!(auth_item.has_auth);
    assert_eq!(auth_item.auth_user, Some("user".to_string()));
    assert_eq!(auth_item.auth_pass, Some("pass".to_string()));
    assert_eq!(auth_item.ip, "185.22.14.12");
    assert_eq!(auth_item.port, 3128);
    assert_eq!(auth_item.url, "http://user:pass@185.22.14.12:3128");
    assert_eq!(auth_item.state, hydra_api::models::ProxyState::ColdQueue);
    assert_eq!(auth_item.checks_total, 0);
    assert_eq!(auth_item.checks_success, 0);
    assert_eq!(auth_item.dead_strikes, 0);
    assert_eq!(auth_item.last_error, None);
    assert_eq!(auth_item.stability_pct, 0.0);
    assert_eq!(auth_item.stability_window_min, 5);
    assert!(auth_item.first_seen_at > 0);
    assert!(auth_item.next_check_at > 0);

    let non_auth = list_data
        .iter()
        .find(|p| p.id == "185.22.14.10:8080")
        .unwrap();
    assert!(!non_auth.has_auth);
    assert_eq!(non_auth.auth_user, None);
    assert_eq!(non_auth.auth_pass, None);
    assert_eq!(non_auth.protocol, None);
    assert_eq!(non_auth.anon, None);
    assert_eq!(non_auth.ip, "185.22.14.10");
    assert_eq!(non_auth.port, 8080);
    assert_eq!(non_auth.state, hydra_api::models::ProxyState::ColdQueue);

    // 7. Get details by ID
    let details_res = client
        .get(format!(
            "{base_url}/api/v1/proxies/185.22.14.12:3128:user:pass"
        ))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(details_res.status(), 200);
    let details: ProxyFullDetails = details_res.json().await.unwrap();
    assert_eq!(details.id, "185.22.14.12:3128:user:pass");
    assert_eq!(details.ip, "185.22.14.12");
    assert_eq!(details.port, 3128);
    assert!(details.has_auth);
    assert_eq!(details.auth_user, Some("user".to_string()));
    assert_eq!(details.auth_pass, Some("pass".to_string()));
    assert_eq!(details.url, "http://user:pass@185.22.14.12:3128");
    assert_eq!(details.policy.stability_window_min, 5);
    assert_eq!(details.stats.stability_pct, 0.0);
    assert_eq!(details.meta.sources, vec!["premium_source".to_string()]);
    assert_eq!(details.meta.source_details.len(), 1);
    assert_eq!(details.meta.source_details[0].name, "premium_source");
    assert!(details.meta.source_details[0].added_at > 0);

    // 8. Patch proxy
    let patch_req = PatchProxyRequest {
        remark: Some("Custom customer note".to_string()),
        auth_user: None,
        auth_pass: None,
        ignore_protocol: None,
        policy: None,
        force_recheck: Some(true),
    };
    let patch_res = client
        .patch(format!(
            "{base_url}/api/v1/proxies/185.22.14.12:3128:user:pass"
        ))
        .header("X-API-Key", &api_key)
        .json(&patch_req)
        .send()
        .await
        .unwrap();
    assert_eq!(patch_res.status(), 200);

    let details_after_patch: ProxyFullDetails = client
        .get(format!(
            "{base_url}/api/v1/proxies/185.22.14.12:3128:user:pass"
        ))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        details_after_patch.meta.remark,
        Some("Custom customer note".to_string())
    );

    // 8b. Report fail on non-alive -> 404
    let report_fail_req = ReportFailRequest {
        id: Some("185.22.14.12:3128:user:pass".to_string()),
        ids: None,
        reason: "timeout".to_string(),
    };
    let fail_res = client
        .post(format!("{base_url}/api/v1/proxies/report-fail"))
        .header("X-API-Key", &api_key)
        .json(&report_fail_req)
        .send()
        .await
        .unwrap();
    assert_eq!(fail_res.status(), 404);

    // 9. Sources list
    let sources_res = client
        .get(format!("{base_url}/api/v1/sources"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(sources_res.status(), 200);
    let sources: Vec<SourceStatsItem> = sources_res.json().await.unwrap();
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].name, "premium_source");
    assert_eq!(sources[0].total_proxies, 3);
    assert!(sources[0].created_at > 0);
    assert!(sources[0].last_added_at.is_some());

    // 9b. Get source by name
    let single_source_res = client
        .get(format!("{base_url}/api/v1/sources/premium_source"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(single_source_res.status(), 200);
    let single_source: SourceStatsItem = single_source_res.json().await.unwrap();
    assert_eq!(single_source.name, "premium_source");
    assert_eq!(single_source.total_proxies, 3);
    assert!(single_source.created_at > 0);

    // 9c. Get non-existent source by name -> 404
    let not_found_source_res = client
        .get(format!("{base_url}/api/v1/sources/non_existent_source"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(not_found_source_res.status(), 404);

    // 10. Global stats
    let stats_res = client
        .get(format!("{base_url}/api/v1/stats"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(stats_res.status(), 200);
    let stats: GlobalStatsResponse = stats_res.json().await.unwrap();
    assert_eq!(stats.pool.total, 3);
    assert_eq!(stats.pool.cold_queue, 3);
    assert_eq!(stats.quality.total_sources, 1);
    assert_eq!(stats.quality.total_checks, 0);
    assert_eq!(stats.engine.checks_completed, 0);

    // 11. Delete proxy
    let del_proxy_res = client
        .delete(format!("{base_url}/api/v1/proxies/185.22.14.10:8080"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(del_proxy_res.status(), 204);

    let get_del_res = client
        .get(format!("{base_url}/api/v1/proxies/185.22.14.10:8080"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(get_del_res.status(), 404);

    // 12. Delete source
    let del_source_res = client
        .delete(format!("{base_url}/api/v1/sources/premium_source"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(del_source_res.status(), 204);
}

#[tokio::test]
async fn test_special_chars_encoded_url_and_batch_report_fail() {
    let (base_url, api_key) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // 1. Batch report fail with empty ids -> 400 Bad Request
    let empty_fail = ReportFailRequest {
        id: None,
        ids: Some(vec![]),
        reason: "timeout".to_string(),
    };
    let empty_fail_res = client
        .post(format!("{base_url}/api/v1/proxies/report-fail"))
        .header("X-API-Key", &api_key)
        .json(&empty_fail)
        .send()
        .await
        .unwrap();
    assert_eq!(empty_fail_res.status(), 400);

    // 2. Batch report fail with multiple non-alive -> 404
    let batch_fail = ReportFailRequest {
        id: None,
        ids: Some(vec![
            "185.22.14.10:8080".to_string(),
            "185.22.14.11:8080".to_string(),
        ]),
        reason: "gateway_timeout".to_string(),
    };
    let batch_fail_res = client
        .post(format!("{base_url}/api/v1/proxies/report-fail"))
        .header("X-API-Key", &api_key)
        .json(&batch_fail)
        .send()
        .await
        .unwrap();
    assert_eq!(batch_fail_res.status(), 404);

    // 3. Import proxy with special characters in credentials: '@', '#', '/'
    let special_import = ImportBatchRequest {
        source: "special_source".to_string(),
        source_url: None,
        remark: None,
        revive_dead: false,
        ignore_protocol: false,
        policy: CheckPolicyDto::default(),
        proxies: vec![ProxyInputItem::Object(ProxyInputObject {
            ip: "185.22.14.20".to_string(),
            port: 8080,
            protocol: Some("socks5".to_string()),
            auth_user: Some("my_user".to_string()),
            auth_pass: Some("p@ss#word".to_string()),
            ignore_protocol: Some(false),
        })],
    };
    let imp_res = client
        .post(format!("{base_url}/api/v1/proxies/import"))
        .header("X-API-Key", &api_key)
        .json(&special_import)
        .send()
        .await
        .unwrap();
    assert_eq!(imp_res.status(), 200);

    // 4. Request with URL-encoded characters: '@' -> %40, '#' -> %23, ':' -> %3A
    let encoded_url =
        format!("{base_url}/api/v1/proxies/185.22.14.20%3A8080%3Amy_user%3Ap%40ss%23word");
    let get_special_res = client
        .get(&encoded_url)
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(get_special_res.status(), 200);
    let special_details: ProxyFullDetails = get_special_res.json().await.unwrap();
    assert_eq!(special_details.id, "185.22.14.20:8080:my_user:p@ss#word");
    assert_eq!(special_details.auth_user, Some("my_user".to_string()));
    assert_eq!(special_details.auth_pass, Some("p@ss#word".to_string()));
    assert!(special_details.has_auth);
}

#[tokio::test]
async fn test_judges_api_list() {
    let (base_url, api_key) = spawn_test_server().await;
    let client = reqwest::Client::new();

    let res = client
        .get(format!("{base_url}/api/v1/judges"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();

    assert_eq!(res.status(), 200);
    let judges: Vec<hydra_api::models::JudgeReportDto> = res.json().await.unwrap();
    // Built-in + 5 default third party judges = 6 judges
    assert_eq!(judges.len(), 6);
    assert_eq!(judges[0].id, "builtin");
    assert_eq!(judges[0].priority, 0);
    assert!(judges.iter().any(|j| j.id == "httpbingo_org"));
    assert!(judges.iter().any(|j| j.id == "httpbin_rs"));
    assert!(judges.iter().any(|j| j.id == "httpbun_com"));
    assert!(judges.iter().any(|j| j.id == "httpbin_org"));
    assert!(judges.iter().any(|j| j.id == "httpbin_dev"));
}

#[tokio::test]
async fn test_import_with_stability_policy_and_api_responses() {
    let (base_url, api_key) = spawn_test_server().await;
    let client = reqwest::Client::new();

    // 1. Import with custom stability_window_min (10 min), dead_backoff_mult (2.5), and recheck_alive_sec (15 sec)
    let import_req = serde_json::json!({
        "source": "fast_recheck_pool",
        "policy": {
            "recheck_alive_sec": 15,
            "stability_window_min": 10,
            "dead_backoff_mult": 2.5
        },
        "proxies": ["185.22.15.201:8080", "185.22.15.202:8080"]
    });

    let imp_res = client
        .post(format!("{base_url}/api/v1/proxies/import"))
        .header("X-API-Key", &api_key)
        .json(&import_req)
        .send()
        .await
        .unwrap();
    assert_eq!(imp_res.status(), 200);

    // 2. Query list by source and cold_queue state
    let list_res = client
        .get(format!(
            "{base_url}/api/v1/proxies?source=fast_recheck_pool&state=cold_queue"
        ))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(list_res.status(), 200);
    let items: Vec<ProxyShortItem> = list_res.json().await.unwrap();
    assert_eq!(items.len(), 2);
    for item in &items {
        assert_eq!(item.stability_window_min, 10);
        assert_eq!(item.stability_pct, 0.0);
    }

    // 3. Query details by ID
    let details_res = client
        .get(format!("{base_url}/api/v1/proxies/185.22.15.201:8080"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    assert_eq!(details_res.status(), 200);
    let details: ProxyFullDetails = details_res.json().await.unwrap();
    assert_eq!(details.policy.recheck_alive_sec, 15);
    assert_eq!(details.policy.stability_window_min, 10);
    assert_eq!(details.policy.dead_backoff_mult, 2.5);
    assert_eq!(details.stats.stability_pct, 0.0);

    // 4. Update policy via PATCH
    let patch_req = serde_json::json!({
        "policy": {
            "connect_timeout_ms": 3000,
            "handshake_timeout_ms": 4000,
            "rw_timeout_ms": 5000,
            "recheck_alive_sec": 10,
            "recheck_dead_sec": 300,
            "max_dead_strikes": 2,
            "stability_window_min": 3,
            "dead_backoff_mult": 1.75
        }
    });
    let patch_res = client
        .patch(format!("{base_url}/api/v1/proxies/185.22.15.201:8080"))
        .header("X-API-Key", &api_key)
        .json(&patch_req)
        .send()
        .await
        .unwrap();
    assert_eq!(patch_res.status(), 200);

    // 5. Verify patched policy
    let patched_details_res = client
        .get(format!("{base_url}/api/v1/proxies/185.22.15.201:8080"))
        .header("X-API-Key", &api_key)
        .send()
        .await
        .unwrap();
    let patched: ProxyFullDetails = patched_details_res.json().await.unwrap();
    assert_eq!(patched.policy.stability_window_min, 3);
    assert_eq!(patched.policy.recheck_alive_sec, 10);
    assert_eq!(patched.policy.dead_backoff_mult, 1.75);
}
