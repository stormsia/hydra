use axum::Json;
use axum::extract::{Path, State};
use axum::http::StatusCode;

use crate::app_state::AppState;
use crate::db::{delete_source, get_source_stats_by_name, list_source_stats};
use crate::error::ApiError;
use crate::models::SourceStatsItem;

#[utoipa::path(
    get,
    path = "/api/v1/sources",
    tag = "Sources",
    operation_id = "list_sources",
    summary = "List proxy sources with efficiency metrics",
    description = "Calculates aggregated yield statistics for every registered proxy source, including total imported count, active alive proxies, yield percentage, and average latency.",
    responses(
        (status = 200, description = "Array of sources and aggregated performance metrics", body = Vec<SourceStatsItem>),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<SourceStatsItem>>, ApiError> {
    let conn = state.connect_db().await?;
    let stats = list_source_stats(&conn).await?;
    Ok(Json(stats))
}

#[utoipa::path(
    get,
    path = "/api/v1/sources/{name}",
    tag = "Sources",
    operation_id = "get_source_by_name",
    summary = "Get proxy source statistics by name",
    description = "Retrieves aggregated yield metrics, proxy distribution, and status for a specific proxy source by name.",
    params(
        ("name" = String, Path, description = "Unique source name identifier", example = "free_spys_ru")
    ),
    responses(
        (status = 200, description = "Source details and performance metrics", body = SourceStatsItem),
        (status = 400, description = "Validation error: invalid or empty source name", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 404, description = "Source not found in database", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn get_by_name(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<Json<SourceStatsItem>, ApiError> {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return Err(ApiError::bad_request("Source name cannot be empty"));
    }
    let conn = state.connect_db().await?;
    match get_source_stats_by_name(&conn, trimmed).await? {
        Some(item) => Ok(Json(item)),
        None => Err(ApiError::not_found(format!("Source '{trimmed}' not found"))),
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/sources/{name}",
    tag = "Sources",
    operation_id = "delete_source",
    summary = "Delete source and exclusive proxies",
    description = "Deletes a source feed and disassociates its proxies. Proxies exclusively linked to this source are permanently removed.",
    params(
        ("name" = String, Path, description = "Source name identifier", example = "free_spys_ru")
    ),
    responses(
        (status = 204, description = "Source successfully deleted"),
        (status = 400, description = "Validation error: invalid or empty source name", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 404, description = "Source not found in database", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    Path(name): Path<String>,
) -> Result<StatusCode, ApiError> {
    let conn = state.connect_db().await?;
    let deleted = delete_source(&conn, &name).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("Source '{name}' not found")))
    }
}
