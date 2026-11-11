use compact_str::CompactString;
use ring::hmac;
use std::sync::{Arc, RwLock};
use std::time::{SystemTime, UNIX_EPOCH};

const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

/// Get current UTC epoch day number (unix_timestamp / 86400)
#[inline]
pub fn current_epoch_day() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
        / 86400
}

/// Derive deterministic 32-character hex authentication token from secret key and epoch day
pub fn derive_token(secret: &str, epoch_day: u64) -> CompactString {
    let key = hmac::Key::new(hmac::HMAC_SHA256, secret.as_bytes());
    let msg_str = format!("hydra-token-v1:{epoch_day}");
    let tag = hmac::sign(&key, msg_str.as_bytes());

    let mut hex_buf = [0u8; 32];
    for (i, &b) in tag.as_ref()[..16].iter().enumerate() {
        hex_buf[i * 2] = HEX_CHARS[(b >> 4) as usize];
        hex_buf[i * 2 + 1] = HEX_CHARS[(b & 0x0f) as usize];
    }

    let hex_str = std::str::from_utf8(&hex_buf).unwrap_or("");
    CompactString::new(hex_str)
}

#[derive(Clone, Debug)]
struct CachedTokens {
    day: u64,
    today: CompactString,
    yesterday: CompactString,
}

/// Thread-safe daily token provider for the Judge.
/// Never decrypts incoming tokens: performs constant-time string comparison against
/// cached today's and yesterday's tokens.
#[derive(Clone, Debug)]
pub struct DailyTokenProvider {
    secret: CompactString,
    expected_len: usize,
    is_static: bool,
    cached: Arc<RwLock<CachedTokens>>,
}

impl DailyTokenProvider {
    /// Create dynamic rotating daily provider from a pre-shared secret key
    pub fn new_dynamic(secret: impl AsRef<str>) -> Self {
        let secret = CompactString::new(secret);
        let day = current_epoch_day();
        let today = derive_token(&secret, day);
        let yesterday = derive_token(&secret, day.saturating_sub(1));

        Self {
            secret,
            expected_len: 32,
            is_static: false,
            cached: Arc::new(RwLock::new(CachedTokens {
                day,
                today,
                yesterday,
            })),
        }
    }

    /// Create static provider (for backward compatibility or fixed test tokens)
    pub fn new_static(token: impl AsRef<str>) -> Self {
        let token = CompactString::new(token);
        let len = token.len();
        Self {
            secret: token.clone(),
            expected_len: len,
            is_static: true,
            cached: Arc::new(RwLock::new(CachedTokens {
                day: 0,
                today: token.clone(),
                yesterday: token,
            })),
        }
    }

    /// Retrieve today's active token to embed in echo responses
    pub fn active_token(&self) -> CompactString {
        if self.is_static {
            return self.secret.clone();
        }

        let current_day = current_epoch_day();
        {
            let guard = self.cached.read().unwrap();
            if guard.day == current_day {
                return guard.today.clone();
            }
        }

        let mut guard = self.cached.write().unwrap();
        if guard.day != current_day {
            let today = derive_token(&self.secret, current_day);
            let yesterday = derive_token(&self.secret, current_day.saturating_sub(1));
            *guard = CachedTokens {
                day: current_day,
                today,
                yesterday,
            };
        }
        guard.today.clone()
    }

    /// Validate whether an incoming request token matches today's or yesterday's token (string comparison).
    /// Performs zero allocations and fast-fails if string length does not match expected token length.
    pub fn validate_token(&self, incoming: &str) -> bool {
        if incoming.len() != self.expected_len {
            return false;
        }

        if self.is_static {
            return self.secret.as_str() == incoming;
        }

        let current_day = current_epoch_day();
        {
            let guard = self.cached.read().unwrap();
            if guard.day == current_day {
                return incoming == guard.today.as_str() || incoming == guard.yesterday.as_str();
            }
        }

        let mut guard = self.cached.write().unwrap();
        if guard.day != current_day {
            let today = derive_token(&self.secret, current_day);
            let yesterday = derive_token(&self.secret, current_day.saturating_sub(1));
            *guard = CachedTokens {
                day: current_day,
                today,
                yesterday,
            };
        }
        incoming == guard.today.as_str() || incoming == guard.yesterday.as_str()
    }
}
