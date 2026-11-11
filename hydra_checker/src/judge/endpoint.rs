use compact_str::CompactString;
use serde::{Deserialize, Serialize};
use url::Url;

/// Represents an echo endpoint / judge used for validating proxy connectivity and anonymity.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeEndpoint {
    /// Unique identifier (e.g. "builtin", "azenv_net", "proxyjudge_us")
    pub id: CompactString,
    /// Human-readable label
    pub name: CompactString,
    /// HTTP endpoint URL
    pub http_url: Url,
    /// HTTPS endpoint URL
    pub https_url: Url,
    /// Optional expected secret token/marker in response body
    pub expected_token: Option<CompactString>,
    /// Whether this is the local/internal Hydra judge
    pub is_builtin: bool,
    /// Priority order (0 = primary / highest priority, 1, 2, 3... = fallbacks)
    pub priority: u32,
    /// Whether this judge returns headers suitable for anonymity classification
    pub supports_anonymity: bool,
    /// Whether this judge is active in the pool
    pub enabled: bool,
}

impl JudgeEndpoint {
    pub fn builtin(
        http_url: Url,
        https_url: Url,
        token: Option<impl AsRef<str>>,
    ) -> Self {
        Self {
            id: CompactString::new("builtin"),
            name: CompactString::new("Hydra Built-in Judge"),
            http_url,
            https_url,
            expected_token: token.map(|t| CompactString::new(t.as_ref())),
            is_builtin: true,
            priority: 0,
            supports_anonymity: true,
            enabled: true,
        }
    }

    pub fn third_party(
        id: impl AsRef<str>,
        name: impl AsRef<str>,
        http_url: Url,
        https_url: Url,
        priority: u32,
        supports_anonymity: bool,
    ) -> Self {
        Self {
            id: CompactString::new(id.as_ref()),
            name: CompactString::new(name.as_ref()),
            http_url,
            https_url,
            expected_token: None,
            is_builtin: false,
            priority,
            supports_anonymity,
            enabled: true,
        }
    }

    /// Returns the standard curated list of verified, HTTPS-capable echo judges supporting anonymity classification.
    pub fn default_third_party_judges() -> Vec<Self> {
        vec![
            Self::third_party(
                "httpbingo_org",
                "Httpbingo.org",
                Url::parse("http://httpbingo.org/get").expect("valid url"),
                Url::parse("https://httpbingo.org/get").expect("valid url"),
                1,
                true,
            ),
            Self::third_party(
                "httpbin_rs",
                "Httpbin.rs",
                Url::parse("http://httpbin.rs/get").expect("valid url"),
                Url::parse("https://httpbin.rs/get").expect("valid url"),
                2,
                true,
            ),
            Self::third_party(
                "httpbun_com",
                "Httpbun.com",
                Url::parse("http://httpbun.com/get").expect("valid url"),
                Url::parse("https://httpbun.com/get").expect("valid url"),
                3,
                true,
            ),
            Self::third_party(
                "httpbin_org",
                "Httpbin.org",
                Url::parse("http://httpbin.org/get").expect("valid url"),
                Url::parse("https://httpbin.org/get").expect("valid url"),
                4,
                true,
            ),
            Self::third_party(
                "httpbin_dev",
                "Httpbin.dev",
                Url::parse("http://httpbin.dev/get").expect("valid url"),
                Url::parse("https://httpbin.dev/get").expect("valid url"),
                5,
                true,
            ),
        ]
    }
}
