use std::sync::Arc;
use url::Url;

use hydra_checker::judge::{JudgeEndpoint, JudgeHealthStatus, JudgePool, JudgeSelectionStrategy};

#[test]
fn test_judge_pool_priority_selection_and_failover() {
    let builtin = JudgeEndpoint::builtin(
        Url::parse("http://127.0.0.1:8080").unwrap(),
        Url::parse("https://127.0.0.1:8080").unwrap(),
        Some("secret_token"),
    );

    let third_party = vec![
        JudgeEndpoint::third_party(
            "azenv_net",
            "AZenv",
            Url::parse("http://azenv.net/").unwrap(),
            Url::parse("https://azenv.net/").unwrap(),
            1,
            true,
        ),
        JudgeEndpoint::third_party(
            "proxyjudge_us",
            "ProxyJudge",
            Url::parse("http://proxyjudge.us/azenv.php").unwrap(),
            Url::parse("https://proxyjudge.us/azenv.php").unwrap(),
            2,
            true,
        ),
    ];

    let pool = Arc::new(JudgePool::new(
        builtin,
        third_party,
        JudgeSelectionStrategy::Priority,
    ));

    // Initially, builtin has priority 0 and status Unknown (not yet failed)
    let selected = pool.select_judge().expect("judge selected");
    assert_eq!(selected.id, "builtin");

    // Record 1 failure -> status becomes Degraded (strike_limit is 2)
    pool.record_failure("builtin", "connection refused");
    let reports = pool.get_health_reports();
    let builtin_rep = reports.iter().find(|r| r.id == "builtin").unwrap();
    assert_eq!(builtin_rep.status, JudgeHealthStatus::Degraded);
    assert_eq!(builtin_rep.consecutive_failures, 1);

    // Degraded is still tried before complete failure
    let selected = pool.select_judge().expect("judge selected");
    assert_eq!(selected.id, "builtin");

    // Record 2nd consecutive failure -> status becomes Unhealthy
    pool.record_failure("builtin", "connection refused");
    let reports = pool.get_health_reports();
    let builtin_rep = reports.iter().find(|r| r.id == "builtin").unwrap();
    assert_eq!(builtin_rep.status, JudgeHealthStatus::Unhealthy);
    assert_eq!(builtin_rep.consecutive_failures, 2);

    // Now builtin is Unhealthy, select_judge MUST automatically failover to azenv_net (priority 1)!
    let selected = pool.select_judge().expect("fallback judge selected");
    assert_eq!(selected.id, "azenv_net");

    // If azenv_net also fails twice:
    pool.record_failure("azenv_net", "timeout");
    pool.record_failure("azenv_net", "timeout");
    let selected = pool.select_judge().expect("next fallback judge selected");
    assert_eq!(selected.id, "proxyjudge_us");

    // When builtin recovers and records success:
    pool.record_success("builtin", 45);
    let selected = pool.select_judge().expect("recovered judge selected");
    assert_eq!(selected.id, "builtin");
    let reports = pool.get_health_reports();
    let builtin_rep = reports.iter().find(|r| r.id == "builtin").unwrap();
    assert_eq!(builtin_rep.status, JudgeHealthStatus::Healthy);
    assert_eq!(builtin_rep.latency_ms, Some(45));
}

#[test]
fn test_fallback_judges_ordering_and_exclusion() {
    let builtin = JudgeEndpoint::builtin(
        Url::parse("http://127.0.0.1:8080").unwrap(),
        Url::parse("https://127.0.0.1:8080").unwrap(),
        Some("secret"),
    );

    let third_party = JudgeEndpoint::default_third_party_judges();
    let pool = JudgePool::new(builtin, third_party, JudgeSelectionStrategy::Priority);

    // Fallbacks excluding builtin should return all third-party judges in priority order
    let fallbacks = pool.fallback_judges("builtin");
    assert_eq!(fallbacks.len(), 5);
    assert_eq!(fallbacks[0].id, "httpbingo_org");
    assert_eq!(fallbacks[1].id, "httpbin_rs");
    assert_eq!(fallbacks[2].id, "httpbun_com");
    assert_eq!(fallbacks[3].id, "httpbin_org");
    assert_eq!(fallbacks[4].id, "httpbin_dev");

    // If excluding httpbingo_org, builtin is included at index 0 (priority 0)
    let fallbacks = pool.fallback_judges("httpbingo_org");
    assert_eq!(fallbacks[0].id, "builtin");
    assert_eq!(fallbacks[1].id, "httpbin_rs");
}

#[test]
fn test_round_robin_strategy() {
    let builtin = JudgeEndpoint::builtin(
        Url::parse("http://127.0.0.1:8080").unwrap(),
        Url::parse("https://127.0.0.1:8080").unwrap(),
        Some("secret"),
    );
    let ep2 = JudgeEndpoint::third_party(
        "j2",
        "Judge 2",
        Url::parse("http://127.0.0.1:8081").unwrap(),
        Url::parse("https://127.0.0.1:8081").unwrap(),
        1,
        true,
    );
    let pool = JudgePool::new(builtin, vec![ep2], JudgeSelectionStrategy::RoundRobin);

    let s1 = pool.select_judge().unwrap();
    let s2 = pool.select_judge().unwrap();
    let s3 = pool.select_judge().unwrap();

    assert_eq!(s1.id, "builtin");
    assert_eq!(s2.id, "j2");
    assert_eq!(s3.id, "builtin");
}

#[test]
fn test_lowest_latency_strategy() {
    let j1 = JudgeEndpoint::third_party(
        "j1_slow",
        "Slow Judge",
        Url::parse("http://127.0.0.1:8081").unwrap(),
        Url::parse("https://127.0.0.1:8081").unwrap(),
        1,
        true,
    );
    let j2 = JudgeEndpoint::third_party(
        "j2_fast",
        "Fast Judge",
        Url::parse("http://127.0.0.1:8082").unwrap(),
        Url::parse("https://127.0.0.1:8082").unwrap(),
        2,
        true,
    );
    let pool = JudgePool::from_endpoints(vec![j1, j2], JudgeSelectionStrategy::LowestLatency);

    // Record probe latency: j1 has 500ms, j2 has 150ms
    pool.record_success("j1_slow", 500);
    pool.record_success("j2_fast", 150);

    // Even though j1 has priority 1, j2 is selected because it has lowest latency (150ms < 500ms)!
    let selected = pool.select_judge().unwrap();
    assert_eq!(selected.id, "j2_fast");

    // Fallback judges should list j1_slow
    let fallbacks = pool.fallback_judges("j2_fast");
    assert_eq!(fallbacks[0].id, "j1_slow");
}

#[tokio::test]
async fn test_disabled_builtin_judge_never_selected() {
    let builtin_disabled = JudgeEndpoint::builtin(
        Url::parse("http://127.0.0.1:8080").unwrap(),
        Url::parse("https://127.0.0.1:8080").unwrap(),
        Some("secret"),
    )
    .with_enabled(false);

    let tp1 = JudgeEndpoint::third_party(
        "tp1",
        "Third Party 1",
        Url::parse("http://127.0.0.1:8081").unwrap(),
        Url::parse("https://127.0.0.1:8081").unwrap(),
        1,
        true,
    );
    let tp2 = JudgeEndpoint::third_party(
        "tp2",
        "Third Party 2",
        Url::parse("http://127.0.0.1:8082").unwrap(),
        Url::parse("https://127.0.0.1:8082").unwrap(),
        2,
        true,
    );

    // Test 1: Priority strategy with all judges Unhealthy
    let pool_priority = JudgePool::new(
        builtin_disabled.clone(),
        vec![tp1.clone(), tp2.clone()],
        JudgeSelectionStrategy::Priority,
    );

    // Mark both third party judges unhealthy
    pool_priority.record_failure("tp1", "down");
    pool_priority.record_failure("tp1", "down");
    pool_priority.record_failure("tp2", "down");
    pool_priority.record_failure("tp2", "down");

    // Even though all third party judges are Unhealthy and builtin has priority 0,
    // builtin MUST NOT be selected because it is disabled! It must fallback to tp1 (first enabled).
    let selected = pool_priority.select_judge().expect("must select enabled judge");
    assert_ne!(selected.id, "builtin", "Disabled builtin judge must NEVER be selected!");
    assert_eq!(selected.id, "tp1");

    // Fallbacks must never include builtin
    let fallbacks = pool_priority.fallback_judges("tp1");
    assert_eq!(fallbacks.len(), 1);
    assert_eq!(fallbacks[0].id, "tp2");

    // Test 2: LowestLatency strategy with all judges Unhealthy
    let pool_latency = JudgePool::new(
        builtin_disabled.clone(),
        vec![tp1.clone(), tp2.clone()],
        JudgeSelectionStrategy::LowestLatency,
    );
    pool_latency.record_failure("tp1", "down");
    pool_latency.record_failure("tp1", "down");
    pool_latency.record_failure("tp2", "down");
    pool_latency.record_failure("tp2", "down");

    let selected = pool_latency.select_judge().expect("must select enabled judge");
    assert_ne!(selected.id, "builtin", "Disabled builtin judge must NEVER be selected!");

    // Test 3: RoundRobin strategy
    let pool_rr = JudgePool::new(
        builtin_disabled.clone(),
        vec![tp1.clone(), tp2.clone()],
        JudgeSelectionStrategy::RoundRobin,
    );
    for _ in 0..10 {
        let s = pool_rr.select_judge().expect("must select enabled judge");
        assert_ne!(s.id, "builtin", "Disabled builtin judge must NEVER appear in RoundRobin!");
    }

    // Test 4: CheckerConfigBuilder with enable_builtin_judge(false)
    let config = hydra_checker::CheckerConfig::builder(
        Url::parse("http://127.0.0.1:8080").unwrap(),
        Url::parse("https://127.0.0.1:8080").unwrap(),
        "token",
    )
    .enable_builtin_judge(false)
    .enable_third_party_judges(false)
    .add_judge(tp1.clone())
    .build()
    .await
    .unwrap();

    let reports = config.judge_pool.get_health_reports();
    let builtin_rep = reports.iter().find(|r| r.id == "builtin").expect("builtin in reports");
    assert!(!builtin_rep.enabled, "Builtin judge report must show enabled: false");

    let s = config.judge_pool.select_judge().expect("judge selected");
    assert_eq!(s.id, "tp1", "Must select third party judge when builtin is disabled");
}
