use axum::Json;
use axum::extract::State;
use std::sync::atomic::Ordering;
use std::time::Duration;

use crate::app_state::AppState;
use crate::error::ApiError;
use crate::models::{JudgeHealthCheckResponse, JudgeReportDto};

fn map_report(r: hydra_checker::JudgeHealthReport) -> JudgeReportDto {
    let status_str = match r.status {
        hydra_checker::JudgeHealthStatus::Healthy => "healthy",
        hydra_checker::JudgeHealthStatus::Degraded => "degraded",
        hydra_checker::JudgeHealthStatus::Unhealthy => "unhealthy",
        hydra_checker::JudgeHealthStatus::Unknown => "unknown",
    };

    JudgeReportDto {
        id: r.id.to_string(),
        name: r.name.to_string(),
        http_url: r.http_url.to_string(),
        https_url: r.https_url.to_string(),
        is_builtin: r.is_builtin,
        priority: r.priority,
        supports_anonymity: r.supports_anonymity,
        enabled: r.enabled,
        status: status_str.to_string(),
        latency_ms: r.latency_ms,
        observed_ip: r.observed_ip.map(|ip| ip.to_string()),
        consecutive_failures: r.consecutive_failures,
        consecutive_successes: r.consecutive_successes,
        last_checked_at: r.last_checked_at,
        last_error: r.last_error.map(|s| s.to_string()),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/judges",
    tag = "Judges",
    operation_id = "list_judges",
    summary = "List all judges and live availability telemetry",
    description = "Returns all configured judge endpoints (built-in and third-party fallbacks), their priority order, anonymity classification capability, and real-time health metrics.",
    responses(
        (status = 200, description = "List of all judges and their current status", body = Vec<JudgeReportDto>),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = []))
)]
pub async fn list(State(state): State<AppState>) -> Result<Json<Vec<JudgeReportDto>>, ApiError> {
    let pool = state.engine.judge_pool();
    let reports = pool.get_health_reports();
    let dtos = reports.into_iter().map(map_report).collect();
    Ok(Json(dtos))
}

#[utoipa::path(
    post,
    path = "/api/v1/judges/health-check",
    tag = "Judges",
    operation_id = "trigger_judge_health_check",
    summary = "Trigger immediate judge availability check",
    description = "Concurrently probes all registered judge servers (built-in and external third-party fallbacks), updates health statuses, and returns the verification report.",
    responses(
        (status = 200, description = "Results of the judge availability check", body = JudgeHealthCheckResponse),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 500, description = "Internal server error", body = ApiError),
    ),
    security(("api_key" = []))
)]
pub async fn trigger_health_check(
    State(state): State<AppState>,
) -> Result<Json<JudgeHealthCheckResponse>, ApiError> {
    let pool = state.engine.judge_pool();
    let tls = state.engine.tls_connector();

    let reports = pool
        .check_availability_all(Duration::from_secs(5), tls)
        .await;

    let healthy_count = reports
        .iter()
        .filter(|r| r.enabled && r.status == hydra_checker::JudgeHealthStatus::Healthy)
        .count();

    state
        .scheduler_stats
        .judge_healthy
        .store(healthy_count > 0, Ordering::Relaxed);

    let active_judge = pool.select_judge().map(|j| j.id.to_string());
    let dtos = reports.into_iter().map(map_report).collect::<Vec<_>>();

    Ok(Json(JudgeHealthCheckResponse {
        total_judges: dtos.len(),
        healthy_judges: healthy_count,
        active_judge,
        judges: dtos,
    }))
}
