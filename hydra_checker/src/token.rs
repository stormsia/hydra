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

/// Thread-safe, cached daily token provider with zero per-request hashing overhead
/// and midnight anti-clock-drift tolerance (today + yesterday).
#[derive(Clone, Debug)]
pub struct DailyTokenProvider {
    secret: CompactString,
    cached: Arc<RwLock<CachedTokens>>,
}

impl DailyTokenProvider {
    /// Create a new provider from a pre-shared secret key
    pub fn new(secret: impl AsRef<str>) -> Self {
        let secret = CompactString::new(secret);
        let day = current_epoch_day();
        let today = derive_token(&secret, day);
        let yesterday = derive_token(&secret, day.saturating_sub(1));

        Self {
            secret,
            cached: Arc::new(RwLock::new(CachedTokens {
                day,
                today,
                yesterday,
            })),
        }
    }

    /// Retrieve the active token for today.
    /// Fast-path reads directly from memory with zero hash operations.
    pub fn current_token(&self) -> CompactString {
        let current_day = current_epoch_day();
        {
            let guard = self.cached.read().unwrap();
            if guard.day == current_day {
                return guard.today.clone();
            }
        }

        // Day rolled over (occurs once every 24 hours)
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

    /// Check if a candidate token matches either today's or yesterday's token (zero heap allocation)
    pub fn is_valid_token(&self, token: &str) -> bool {
        if token.len() != 32 {
            return false;
        }
        let current_day = current_epoch_day();
        {
            let guard = self.cached.read().unwrap();
            if guard.day == current_day {
                return token == guard.today.as_str() || token == guard.yesterday.as_str();
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
        token == guard.today.as_str() || token == guard.yesterday.as_str()
    }

    /// Check whether a response body contains today's or yesterday's token without cloning
    pub fn is_token_in_body(&self, body: &str) -> bool {
        let current_day = current_epoch_day();
        {
            let guard = self.cached.read().unwrap();
            if guard.day == current_day {
                return body.contains(guard.today.as_str())
                    || body.contains(guard.yesterday.as_str());
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
        body.contains(guard.today.as_str()) || body.contains(guard.yesterday.as_str())
    }
}
