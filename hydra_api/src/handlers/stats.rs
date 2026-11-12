use std::sync::atomic::Ordering;
use axum::extract::State;
use axum::Json;

use crate::app_state::AppState;
use crate::db::get_global_stats as db_get_global_stats;
use crate::error::ApiError;
use crate::models::{EngineStatsDto, GlobalStatsResponse};

#[utoipa::path(
    get,
    path = "/api/v1/stats",
    tag = "Stats",
    operation_id = "get_global_stats",
    summary = "Get global telemetry and pool metrics",
    description = "Returns real-time engine throughput (checks/sec, worker pool size, lifetime checks), proxy pool state counts, pool quality & latency metrics, protocol/anonymity/error distributions, and geographic & ASN provider rankings.",
    responses(
        (status = 200, description = "Current global system telemetry and pool statistics", body = GlobalStatsResponse),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn global_stats(
    State(state): State<AppState>,
) -> Result<Json<GlobalStatsResponse>, ApiError> {
    let conn = state.connect_db().await?;
    let (pool, quality, by_protocol, by_anonymity, by_error, top_countries, top_asns) =
        db_get_global_stats(&conn).await?;

    let engine = EngineStatsDto {
        active_workers: state.scheduler_stats.active_workers.load(Ordering::Relaxed),
        checks_per_sec: state.scheduler_stats.get_checks_per_sec(),
        checks_completed: state.scheduler_stats.checks_completed.load(Ordering::Relaxed),
        batch_buffer_size: state.scheduler_stats.batch_buffer_size.load(Ordering::Relaxed),
        judge_healthy: state.scheduler_stats.judge_healthy.load(Ordering::Relaxed),
    };

    Ok(Json(GlobalStatsResponse {
        engine,
        pool,
        quality,
        by_protocol,
        by_anonymity,
        by_error,
        top_countries,
        top_asns,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/stats/engine",
    tag = "Stats",
    operation_id = "get_engine_stats",
    summary = "Get real-time engine throughput and worker stats (in-memory, zero DB queries)",
    description = "Returns real-time in-memory engine throughput metrics and worker statistics without hitting the database.",
    responses(
        (status = 200, description = "Real-time engine throughput metrics", body = EngineStatsDto),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn engine_stats(
    State(state): State<AppState>,
) -> Json<EngineStatsDto> {
    Json(EngineStatsDto {
        active_workers: state.scheduler_stats.active_workers.load(Ordering::Relaxed),
        checks_per_sec: state.scheduler_stats.get_checks_per_sec(),
        checks_completed: state.scheduler_stats.checks_completed.load(Ordering::Relaxed),
        batch_buffer_size: state.scheduler_stats.batch_buffer_size.load(Ordering::Relaxed),
        judge_healthy: state.scheduler_stats.judge_healthy.load(Ordering::Relaxed),
    })
}
