use hydra_api::models::*;
use hydra_api::services::parser::{
    parse_input_item, parse_proxy_string, parse_proxy_string_opt,
};

#[test]
fn test_proxy_parser_all_variations() {
    // 1. IP:Port plain
    let p1 = parse_proxy_string("185.22.14.9:1080").unwrap();
    assert_eq!(p1.id, "185.22.14.9:1080");
    assert_eq!(p1.ip, "185.22.14.9");
    assert_eq!(p1.port, 1080);
    assert_eq!(p1.protocol_hint, None);
    assert_eq!(p1.auth_user, None);
    assert_eq!(p1.auth_pass, None);

    // 2. Protocol prefix
    let p2 = parse_proxy_string("socks5://185.22.14.9:1080").unwrap();
    assert_eq!(p2.protocol_hint, Some("socks5".to_string()));

    let p2a = parse_proxy_string("socks4a://185.22.14.9:1080").unwrap();
    assert_eq!(p2a.protocol_hint, Some("socks4a".to_string()));

    let p2b = parse_proxy_string("https://185.22.14.9:443").unwrap();
    assert_eq!(p2b.protocol_hint, Some("https".to_string()));

    // 3. Auth with protocol
    let p3 = parse_proxy_string("http://admin:secret123@185.22.14.9:8080").unwrap();
    assert_eq!(p3.id, "185.22.14.9:8080:admin:secret123");
    assert_eq!(p3.protocol_hint, Some("http".to_string()));
    assert_eq!(p3.auth_user, Some("admin".to_string()));
    assert_eq!(p3.auth_pass, Some("secret123".to_string()));

    // 4. Vendor format ip:port:user:pass
    let p4 = parse_proxy_string("185.22.14.9:3128:user1:pass2").unwrap();
    assert_eq!(p4.id, "185.22.14.9:3128:user1:pass2");
    assert_eq!(p4.auth_user, Some("user1".to_string()));
    assert_eq!(p4.auth_pass, Some("pass2".to_string()));

    // 5. IPv6 bracketed
    let p5 = parse_proxy_string_opt("[2001:db8::1]:8080", true).unwrap();
    assert_eq!(p5.id, "[2001:db8::1]:8080");
    assert_eq!(p5.ip, "2001:db8::1");
    assert_eq!(p5.port, 8080);

    // 6. Structured ProxyInputObject
    let struct_item = ProxyInputItem::Object(ProxyInputObject {
        ip: "185.22.14.9".to_string(),
        port: 1080,
        protocol: Some("socks5".to_string()),
        auth_user: Some("myuser".to_string()),
        auth_pass: Some("mypass".to_string()),
        ignore_protocol: None,
    });
    let parsed_struct = parse_input_item(&struct_item).unwrap();
    assert_eq!(parsed_struct.id, "185.22.14.9:1080:myuser:mypass");
    assert_eq!(parsed_struct.ip, "185.22.14.9");
    assert_eq!(parsed_struct.port, 1080);
    assert_eq!(parsed_struct.protocol_hint, Some("socks5".to_string()));
    assert_eq!(parsed_struct.auth_user, Some("myuser".to_string()));
    assert_eq!(parsed_struct.auth_pass, Some("mypass".to_string()));

    // 6b. Same IP & Port with different logins (Rotational Gateway support)
    let rot1 = parse_proxy_string("socks5://user_de:pass1@185.22.14.9:1080").unwrap();
    let rot2 = parse_proxy_string("socks5://user_us:pass2@185.22.14.9:1080").unwrap();
    assert_eq!(rot1.id, "185.22.14.9:1080:user_de:pass1");
    assert_eq!(rot2.id, "185.22.14.9:1080:user_us:pass2");
    assert_ne!(rot1.id, rot2.id);

    // 6c. Ignore protocol flag -> resets hint to None for auto-detect
    let auto_item = ProxyInputItem::Object(ProxyInputObject {
        ip: "185.22.14.9".to_string(),
        port: 1080,
        protocol: Some("socks5".to_string()),
        auth_user: None,
        auth_pass: None,
        ignore_protocol: Some(true),
    });
    let parsed_auto = parse_input_item(&auto_item).unwrap();
    assert_eq!(parsed_auto.protocol_hint, None);

    // 7. Invalid inputs
    assert!(parse_proxy_string("not_an_ip:8080").is_none());
    assert!(parse_proxy_string("185.22.14.9:999999").is_none());
    assert!(parse_proxy_string("185.22.14.9:0").is_none());
    assert!(parse_proxy_string("   ").is_none());
    assert!(parse_proxy_string("127.0.0.1:8080").is_none()); // bogon rejected by default
    assert!(parse_proxy_string("10.1.2.3:8080").is_none()); // private rejected
}

#[test]
fn test_models_defaults_and_serde() {
    let policy: CheckPolicyDto = serde_json::from_str("{}").unwrap();
    assert_eq!(policy.connect_timeout_ms, 3000);
    assert_eq!(policy.handshake_timeout_ms, 4000);
    assert_eq!(policy.rw_timeout_ms, 5000);
    assert_eq!(policy.recheck_alive_sec, 60);
    assert_eq!(policy.recheck_dead_sec, 1800);
    assert_eq!(policy.max_dead_strikes, 3);
    assert_eq!(policy.stability_window_min, 5);

    let custom_policy: CheckPolicyDto = serde_json::from_str(r#"{"window_min": 10}"#).unwrap();
    assert_eq!(custom_policy.stability_window_min, 10);

    let state = ProxyState::from_i64(1);
    assert_eq!(state, ProxyState::Alive);
    assert_eq!(state.to_i64(), 1);

    let json = serde_json::to_string(&state).unwrap();
    assert_eq!(json, "\"alive\"");
}

#[test]
fn test_openapi_spec_structure_and_completeness() {
    use utoipa::OpenApi;
    use hydra_api::ApiDoc;

    let doc = ApiDoc::openapi();
    let v = serde_json::to_value(&doc).expect("serialize OpenAPI doc to JSON");

    // Verify info metadata
    assert_eq!(v["info"]["title"], "Hydra Proxy Checker API");
    assert_eq!(v["info"]["version"], "1.0.0");
    let desc = v["info"]["description"].as_str().expect("description string");
    assert!(desc.contains("Hydra"));
    assert!(desc.contains("Authentication"));
    assert_eq!(v["info"]["contact"]["name"], "Hydra Core Team");
    assert_eq!(v["info"]["license"]["name"], "MIT OR Apache-2.0");

    // Verify servers
    let servers = v["servers"].as_array().expect("servers array");
    assert_eq!(servers.len(), 2);
    assert_eq!(servers[0]["url"], "http://127.0.0.1:3000");

    // Verify tags
    let tags = v["tags"].as_array().expect("tags array");
    let tag_names: Vec<&str> = tags.iter().filter_map(|t| t["name"].as_str()).collect();
    assert_eq!(tag_names, vec!["Proxies", "Sources", "Stats", "Judges"]);

    // Verify schemas
    let schemas = v["components"]["schemas"].as_object().expect("schemas object");

    let expected_schemas = [
        "ImportBatchRequest",
        "ImportBatchResponse",
        "ProxyInputItem",
        "ProxyInputObject",
        "ReportFailRequest",
        "ReportFailResponse",
        "PatchProxyRequest",
        "ProxyShortItem",
        "ProxyFullDetails",
        "ProxyMetricsDto",
        "ProxyStatsDto",
        "ProxyMetaDto",
        "ProxySourceMetaDto",
        "CheckPolicyDto",
        "ProxyState",
        "SourceStatsItem",
        "GlobalStatsResponse",
        "EngineStatsDto",
        "PoolCountsDto",
        "PoolQualityDto",
        "CountryStatsDto",
        "AsnStatsDto",
        "JudgeReportDto",
        "JudgeHealthCheckResponse",
        "ApiError",
    ];

    for name in &expected_schemas {
        assert!(
            schemas.contains_key(*name),
            "Missing schema in OpenAPI spec: {name}"
        );
    }

    // Verify security scheme
    assert!(v["components"]["securitySchemes"]["api_key"].is_object());
    assert_eq!(
        v["components"]["securitySchemes"]["api_key"]["name"],
        "X-API-Key"
    );

    // Verify operations across paths
    let paths = v["paths"].as_object().expect("paths object");
    let expected_operation_ids = [
        "import_proxies",
        "list_proxies",
        "get_proxy_by_id",
        "patch_proxy",
        "delete_proxy",
        "report_proxy_failure",
        "list_sources",
        "get_source_by_name",
        "delete_source",
        "get_global_stats",
        "list_judges",
        "trigger_judge_health_check",
    ];

    let mut found_ops = Vec::new();
    for (_path_str, path_item) in paths {
        if let Some(methods) = path_item.as_object() {
            for (_method, op) in methods {
                if let Some(op_id) = op["operationId"].as_str() {
                    found_ops.push(op_id.to_string());
                    assert!(op["summary"].is_string(), "Op {op_id} missing summary");
                    assert!(op["description"].is_string(), "Op {op_id} missing description");

                    let op_tags = op["tags"].as_array().expect("op tags array");
                    assert!(!op_tags.is_empty(), "Op {op_id} missing tags");
                    for t in op_tags {
                        let t_str = t.as_str().unwrap();
                        assert!(
                            ["Proxies", "Sources", "Stats", "Judges"].contains(&t_str),
                            "Invalid tag {t_str} on operation {op_id}"
                        );
                    }

                    assert!(
                        op["security"].is_array(),
                        "Op {op_id} missing security definition"
                    );

                    let responses = op["responses"].as_object().expect("responses object");
                    assert!(
                        responses.contains_key("401"),
                        "Op {op_id} missing 401 unauthorized response"
                    );
                    assert!(
                        responses.contains_key("500"),
                        "Op {op_id} missing 500 internal error response"
                    );
                }
            }
        }
    }

    for op_id in &expected_operation_ids {
        assert!(
            found_ops.contains(&op_id.to_string()),
            "Missing operation in OpenAPI spec: {op_id}"
        );
    }
}
