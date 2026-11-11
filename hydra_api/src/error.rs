use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

/// Стандартизированный JSON-ответ с ошибкой API
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[schema(example = json!({
    "error": "not_found",
    "message": "Proxy '185.22.14.9:1080' not found"
}))]
pub struct ApiError {
    /// Машинно-читаемый код ошибки (например: bad_request, not_found, unauthorized, internal_error)
    #[schema(example = "not_found", min_length = 1, max_length = 64)]
    pub error: String,

    /// Человеко-читаемое описание возникшей ошибки
    #[schema(example = "Proxy '185.22.14.9:1080' not found", min_length = 1, max_length = 2048)]
    pub message: String,
}

impl ApiError {
    pub fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            error: "bad_request".to_string(),
            message: msg.into(),
        }
    }

    pub fn not_found(msg: impl Into<String>) -> Self {
        Self {
            error: "not_found".to_string(),
            message: msg.into(),
        }
    }

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            error: "unauthorized".to_string(),
            message: msg.into(),
        }
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self {
            error: "internal_error".to_string(),
            message: msg.into(),
        }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let status = match self.error.as_str() {
            "not_found" => StatusCode::NOT_FOUND,
            "bad_request" => StatusCode::BAD_REQUEST,
            "unauthorized" => StatusCode::UNAUTHORIZED,
            "conflict" => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        (status, Json(self)).into_response()
    }
}

impl From<libsql::Error> for ApiError {
    fn from(err: libsql::Error) -> Self {
        tracing::error!("Database error: {:?}", err);
        Self::internal(format!("Database error: {err}"))
    }
}

impl From<serde_json::Error> for ApiError {
    fn from(err: serde_json::Error) -> Self {
        Self::bad_request(format!("Invalid JSON payload: {err}"))
    }
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.error, self.message)
    }
}

impl std::error::Error for ApiError {}
