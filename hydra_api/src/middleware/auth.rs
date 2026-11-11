use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use crate::app_state::AppState;
use crate::error::ApiError;

pub async fn require_api_key(
    State(state): State<AppState>,
    request: Request,
    next: Next,
) -> Response {
    let path = request.uri().path();
    if path.starts_with("/swagger-ui") || path.starts_with("/api-docs") {
        return next.run(request).await;
    }

    let api_key = request
        .headers()
        .get("X-API-Key")
        .and_then(|v| v.to_str().ok());

    match api_key {
        Some(key) if key == state.config.api_key => next.run(request).await,
        _ => ApiError::unauthorized("Missing or invalid X-API-Key header").into_response(),
    }
}
