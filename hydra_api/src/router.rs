use axum::middleware;
use axum::routing::{delete, get, patch, post};
use axum::Router;
use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::{Modify, OpenApi};
use utoipa_swagger_ui::SwaggerUi;

use crate::app_state::AppState;
use crate::error::ApiError;
use crate::handlers;
use crate::middleware::auth::require_api_key;
use crate::models::*;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            components.add_security_scheme(
                "api_key",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-API-Key"))),
            );
        }
    }
}

#[derive(OpenApi)]
#[openapi(
    info(
        title = "Hydra Proxy Checker API",
        version = "1.0.0",
        description = "Hydra is a high-performance distributed proxy verification, scoring, and lifecycle management engine.\n\n### Core Capabilities\n- **Multi-protocol verification**: SOCKS5, SOCKS4, HTTP, HTTPS CONNECT tunneling\n- **GeoIP & ASN enrichment**: MaxMind City & ASN reader with lock-free atomic hot-reloading\n- **Lifecycle State Machine**: `cold_queue` → `alive` ↔ `cooldown` → `dead_permanent`\n- **Batched Persistence**: High-throughput transactional batch writer with WAL mode\n- **Client Feedback**: Real-time failure reporting and priority rechecks\n\n### Authentication\nAll operational endpoints require the `X-API-Key` HTTP header (configured via `API_KEY` in environment).",
        contact(
            name = "Hydra Core Team",
            url = "https://github.com/stormsia/hydra"
        ),
        license(
            name = "MIT"
        )
    ),
    servers(
        (url = "http://127.0.0.1:3000", description = "Local development instance"),
        (url = "http://localhost:3000", description = "Localhost alias")
    ),
    paths(
        handlers::proxies::import,
        handlers::proxies::list,
        handlers::proxies::get_by_id,
        handlers::proxies::patch,
        handlers::proxies::delete,
        handlers::proxies::report_fail,
        handlers::sources::list,
        handlers::sources::get_by_name,
        handlers::sources::delete,
        handlers::stats::global_stats,
        handlers::stats::engine_stats,
        handlers::judges::list,
        handlers::judges::trigger_health_check,
    ),
    components(
        schemas(
            ImportBatchRequest,
            ImportBatchResponse,
            ProxyInputItem,
            ProxyInputObject,
            ReportFailRequest,
            ReportFailResponse,
            PatchProxyRequest,
            ProxyShortItem,
            ProxyFullDetails,
            ProxyMetricsDto,
            ProxyStatsDto,
            ProxyMetaDto,
            ProxySourceMetaDto,
            CheckPolicyDto,
            ProxyState,
            SourceStatsItem,
            GlobalStatsResponse,
            EngineStatsDto,
            PoolCountsDto,
            PoolQualityDto,
            CountryStatsDto,
            AsnStatsDto,
            JudgeReportDto,
            JudgeHealthCheckResponse,
            ApiError,
        )
    ),
    modifiers(&SecurityAddon),
    tags(
        (name = "Proxies", description = "Proxy management, importing, and routing endpoints"),
        (name = "Sources", description = "Proxy source lists & yield performance"),
        (name = "Stats", description = "System metrics and engine statistics"),
        (name = "Judges", description = "Judge pool management, health checks, and fallback status")
    )
)]
pub struct ApiDoc;

pub fn build_router(state: AppState) -> Router {
    let api_routes = Router::new()
        // Proxies
        .route("/api/v1/proxies/import", post(handlers::proxies::import))
        .route("/api/v1/proxies", get(handlers::proxies::list))
        .route("/api/v1/proxies/report-fail", post(handlers::proxies::report_fail))
        .route("/api/v1/proxies/{id}", get(handlers::proxies::get_by_id))
        .route("/api/v1/proxies/{id}", patch(handlers::proxies::patch))
        .route("/api/v1/proxies/{id}", delete(handlers::proxies::delete))
        // Sources
        .route("/api/v1/sources", get(handlers::sources::list))
        .route("/api/v1/sources/{name}", get(handlers::sources::get_by_name))
        .route("/api/v1/sources/{name}", delete(handlers::sources::delete))
        // Judges
        .route("/api/v1/judges", get(handlers::judges::list))
        .route("/api/v1/judges/health-check", post(handlers::judges::trigger_health_check))
        // System
        .route("/api/v1/stats", get(handlers::stats::global_stats))
        .route("/api/v1/stats/engine", get(handlers::stats::engine_stats))
        // Auth layer
        .layer(middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));

    let swagger = SwaggerUi::new("/swagger-ui")
        .url("/api-docs/openapi.json", ApiDoc::openapi());

    Router::new()
        .merge(api_routes)
        .merge(swagger)
        .with_state(state)
}
