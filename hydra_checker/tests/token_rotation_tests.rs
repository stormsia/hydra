use std::time::Instant;

use hydra_checker::DailyTokenProvider;
use hydra_checker::token::{current_epoch_day, derive_token};

#[test]
fn test_token_derivation_deterministic() {
    let secret = "hydra_secret_test_key_42";
    let day = current_epoch_day();

    let token1 = derive_token(secret, day);
    let token2 = derive_token(secret, day);

    assert_eq!(token1, token2);
    assert_eq!(token1.len(), 32); // 32 hex chars (128-bit truncated HMAC)

    // Different day produces completely different token
    let token_other_day = derive_token(secret, day + 1);
    assert_ne!(token1, token_other_day);
}

#[test]
fn test_midnight_grace_window() {
    let secret = "hydra_secret_key_rotation";
    let provider = DailyTokenProvider::new(secret);

    let day = current_epoch_day();
    let today_token = derive_token(secret, day);
    let yesterday_token = derive_token(secret, day.saturating_sub(1));
    let tomorrow_token = derive_token(secret, day + 1);

    // Today is valid
    assert!(provider.is_valid_token(&today_token));
    // Yesterday is valid (anti-drift grace window around midnight)
    assert!(provider.is_valid_token(&yesterday_token));
    // Arbitrary / future tokens are rejected
    assert!(!provider.is_valid_token(&tomorrow_token));
    assert!(!provider.is_valid_token("invalid_spoofed_token_12345678"));

    // Body check
    let body_today = format!("REMOTE_ADDR = 1.2.3.4\nHYDRA_TOKEN = {today_token}\n");
    assert!(provider.is_token_in_body(&body_today));

    let body_yesterday = format!("REMOTE_ADDR = 1.2.3.4\nHYDRA_TOKEN = {yesterday_token}\n");
    assert!(provider.is_token_in_body(&body_yesterday));

    let body_bad = "REMOTE_ADDR = 1.2.3.4\nHYDRA_TOKEN = bad_token\n";
    assert!(!provider.is_token_in_body(body_bad));
}

#[test]
fn test_caching_performance_benchmark() {
    let provider = DailyTokenProvider::new("benchmark_secret");
    let iterations = 100_000;

    let start = Instant::now();
    for _ in 0..iterations {
        let _ = provider.current_token();
    }
    let elapsed = start.elapsed();

    // 100,000 reads from memory in debug mode should complete very fast (< 100ms)
    assert!(
        elapsed.as_millis() < 100,
        "100K token cache reads took too long: {elapsed:?}"
    );
}
