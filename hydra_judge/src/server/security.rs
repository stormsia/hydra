use crate::token::DailyTokenProvider;

/// Validate whether the incoming request contains an authorized token.
///
/// Compares candidate token against active today's and yesterday's derived tokens
/// via string equality (Judge never performs decryption).
pub fn is_authorized(
    path_and_query: &str,
    headers: &[(&str, &str)],
    token_provider: &DailyTokenProvider,
) -> bool {
    // 1. Check Query Parameter (?token=...)
    if let Some((_path, query)) = path_and_query.split_once('?') {
        for pair in query.split('&') {
            if let Some((k, v)) = pair.split_once('=') {
                if k == "token" && token_provider.validate_token(v) {
                    return true;
                }
            }
        }
    }

    // 2. Check Path Segments (e.g. /<token> or /check/<token>)
    let path = path_and_query.split('?').next().unwrap_or(path_and_query);
    for segment in path.split('/') {
        if !segment.is_empty() && token_provider.validate_token(segment) {
            return true;
        }
    }

    // 3. Check Headers (X-Hydra-Token)
    for (name, val) in headers {
        if name.eq_ignore_ascii_case("x-hydra-token") && token_provider.validate_token(val) {
            return true;
        }
    }

    false
}
