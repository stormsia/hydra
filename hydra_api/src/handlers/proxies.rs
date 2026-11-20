use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use chrono::Utc;
use std::collections::HashSet;

use crate::app_state::AppState;
use crate::db::{
    delete_proxy, get_proxy_by_id, get_source_details_for_proxy, get_sources_for_proxy,
    patch_proxy, query_proxies, report_fails_batch, upsert_source,
};
use crate::error::ApiError;
use crate::models::{
    ImportBatchRequest, ImportBatchResponse, PatchProxyRequest, ProxyFilterQuery, ProxyFullDetails,
    ProxyMetaDto, ProxyMetricsDto, ProxyShortItem, ProxyStatsDto, ReportFailRequest,
    ReportFailResponse,
};
use crate::services::parser::parse_input_item;

#[utoipa::path(
    post,
    path = "/api/v1/proxies/import",
    tag = "Proxies",
    operation_id = "import_proxies",
    summary = "Import batch of raw proxies",
    description = "Accepts raw proxy lists in various formats (ip:port, proto://user:pass@ip:port, etc.), parses, validates against bogon IP ranges, deduplicates, associates with a source, and schedules for background verification.",
    request_body(content = ImportBatchRequest, description = "Batch of raw proxy strings and import policy configuration"),
    responses(
        (status = 200, description = "Batch parsed, deduplicated, and scheduled for verification", body = ImportBatchResponse),
        (status = 400, description = "Validation error: invalid request payload or empty source name", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn import(
    State(state): State<AppState>,
    Json(req): Json<ImportBatchRequest>,
) -> Result<Json<ImportBatchResponse>, ApiError> {
    let source_name = req.source.trim();
    if source_name.is_empty() {
        return Err(ApiError::bad_request("Source name cannot be empty"));
    }

    let conn = state.connect_db().await?;
    let now = Utc::now().timestamp();

    conn.execute("BEGIN IMMEDIATE;", ()).await?;

    let source_id = match upsert_source(
        &conn,
        source_name,
        req.source_url.as_deref(),
        req.remark.as_deref(),
        now,
    )
    .await
    {
        Ok(id) => id,
        Err(e) => {
            let _ = conn.execute("ROLLBACK;", ()).await;
            return Err(ApiError::from(e));
        }
    };

    let total_received = req.proxies.len();
    let mut inserted_new = 0;
    let mut updated_existing = 0;
    let mut revived = 0;
    let mut invalid_format = 0;

    let mut seen_in_batch = HashSet::with_capacity(total_received);

    // Prepare statements outside the batch loop to minimize CPU compilation overhead
    // and hold write-locks for as short a time as possible.
    let stmt_insert = match conn
        .prepare(
            "INSERT OR IGNORE INTO proxies (
                id, ip, port, auth_user, auth_pass, state, protocol, supports_https,
                out_ip, country, asn, asn_org, anon,
                rtt_tcp_ms, rtt_handshake_ms, rtt_total_ms,
                connect_timeout_ms, handshake_timeout_ms, rw_timeout_ms,
                recheck_alive_sec, recheck_dead_sec, max_dead_strikes_zero, max_dead_strikes_active,
                stability_window_min, dead_backoff_mult_zero, dead_backoff_mult_active,
                checks_total, checks_success, dead_strikes, last_error, stability_pct, recent_checks, remark,
                first_seen_at, last_checked_at, next_check_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16,
                ?17, ?18, ?19,
                ?20, ?21, ?22, ?23,
                ?24, ?25, ?26,
                ?27, ?28, ?29, ?30, ?31, ?32, ?33,
                ?34, ?35, ?36
             );",
        )
        .await
    {
        Ok(stmt) => stmt,
        Err(e) => {
            let _ = conn.execute("ROLLBACK;", ()).await;
            return Err(ApiError::from(e));
        }
    };

    let stmt_update_ignore = if req.ignore_protocol {
        match conn
            .prepare(
                "UPDATE proxies SET
                    protocol = NULL,
                    state = 0,
                    next_check_at = ?8,
                    auth_user = COALESCE(?1, auth_user),
                    auth_pass = COALESCE(?2, auth_pass),
                    stability_window_min = ?3,
                    dead_backoff_mult_zero = ?4,
                    dead_backoff_mult_active = ?5,
                    max_dead_strikes_zero = ?6,
                    max_dead_strikes_active = ?7
                 WHERE id = ?9;",
            )
            .await
        {
            Ok(stmt) => Some(stmt),
            Err(e) => {
                let _ = conn.execute("ROLLBACK;", ()).await;
                return Err(ApiError::from(e));
            }
        }
    } else {
        None
    };

    let stmt_update = if !req.ignore_protocol {
        match conn
            .prepare(
                "UPDATE proxies SET
                    auth_user = COALESCE(?1, auth_user),
                    auth_pass = COALESCE(?2, auth_pass),
                    protocol = COALESCE(?3, protocol),
                    stability_window_min = ?4,
                    dead_backoff_mult_zero = ?5,
                    dead_backoff_mult_active = ?6,
                    max_dead_strikes_zero = ?7,
                    max_dead_strikes_active = ?8
                 WHERE id = ?9;",
            )
            .await
        {
            Ok(stmt) => Some(stmt),
            Err(e) => {
                let _ = conn.execute("ROLLBACK;", ()).await;
                return Err(ApiError::from(e));
            }
        }
    } else {
        None
    };

    let stmt_revive = if req.revive_dead {
        match conn
            .prepare(
                "UPDATE proxies
                 SET state = 0, dead_strikes = 0, next_check_at = ?2, stability_pct = 0.0, recent_checks = NULL
                 WHERE id = ?1 AND state = 3;",
            )
            .await
        {
            Ok(stmt) => Some(stmt),
            Err(e) => {
                let _ = conn.execute("ROLLBACK;", ()).await;
                return Err(ApiError::from(e));
            }
        }
    } else {
        None
    };

    let stmt_link = match conn
        .prepare(
            "INSERT OR IGNORE INTO proxy_sources (proxy_id, source_id, added_at)
             VALUES (?1, ?2, ?3);",
        )
        .await
    {
        Ok(stmt) => stmt,
        Err(e) => {
            let _ = conn.execute("ROLLBACK;", ()).await;
            return Err(ApiError::from(e));
        }
    };

    for raw in &req.proxies {
        let mut parsed = match parse_input_item(raw) {
            Some(p) => p,
            None => {
                invalid_format += 1;
                continue;
            }
        };

        if req.ignore_protocol {
            parsed.protocol_hint = None;
        }

        if !seen_in_batch.insert(parsed.id.clone()) {
            continue;
        }

        stmt_insert.reset();
        let res = stmt_insert
            .execute(libsql::params![
                parsed.id.as_str(),
                parsed.ip.as_str(),
                parsed.port as i64,
                parsed.auth_user.as_deref(),
                parsed.auth_pass.as_deref(),
                0i64, // ProxyState::ColdQueue
                parsed.protocol_hint.as_deref(),
                0i64, // supports_https = false
                Option::<&str>::None,
                Option::<&str>::None,
                Option::<i64>::None,
                Option::<&str>::None,
                Option::<&str>::None,
                Option::<i64>::None,
                Option::<i64>::None,
                Option::<i64>::None,
                req.policy.connect_timeout_ms as i64,
                req.policy.handshake_timeout_ms as i64,
                req.policy.rw_timeout_ms as i64,
                req.policy.recheck_alive_sec.max(1) as i64,
                req.policy.recheck_dead_sec.max(1) as i64,
                req.policy.max_dead_strikes_zero as i64,
                req.policy.max_dead_strikes_active as i64,
                req.policy.stability_window_min as i64,
                req.policy.dead_backoff_mult_zero as f64,
                req.policy.dead_backoff_mult_active as f64,
                0i64,
                0i64,
                0i64,
                Option::<&str>::None,
                0.0f64,
                Option::<&str>::None,
                Option::<&str>::None,
                now,
                Option::<i64>::None,
                now,
            ])
            .await;
        stmt_insert.reset();

        let affected = match res {
            Ok(n) => n,
            Err(e) => {
                let _ = conn.execute("ROLLBACK;", ()).await;
                return Err(ApiError::from(e));
            }
        };

        if affected > 0 {
            inserted_new += 1;
        } else {
            updated_existing += 1;
            if let Some(ref stmt_upd) = stmt_update_ignore {
                stmt_upd.reset();
                let res = stmt_upd
                    .execute(libsql::params![
                        parsed.auth_user.as_deref(),
                        parsed.auth_pass.as_deref(),
                        req.policy.stability_window_min as i64,
                        req.policy.dead_backoff_mult_zero as f64,
                        req.policy.dead_backoff_mult_active as f64,
                        req.policy.max_dead_strikes_zero as i64,
                        req.policy.max_dead_strikes_active as i64,
                        now,
                        parsed.id.as_str(),
                    ])
                    .await;
                stmt_upd.reset();
                if let Err(e) = res {
                    let _ = conn.execute("ROLLBACK;", ()).await;
                    return Err(ApiError::from(e));
                }
            } else if let Some(ref stmt_upd) = stmt_update {
                stmt_upd.reset();
                let res = stmt_upd
                    .execute(libsql::params![
                        parsed.auth_user.as_deref(),
                        parsed.auth_pass.as_deref(),
                        parsed.protocol_hint.as_deref(),
                        req.policy.stability_window_min as i64,
                        req.policy.dead_backoff_mult_zero as f64,
                        req.policy.dead_backoff_mult_active as f64,
                        req.policy.max_dead_strikes_zero as i64,
                        req.policy.max_dead_strikes_active as i64,
                        parsed.id.as_str(),
                    ])
                    .await;
                stmt_upd.reset();
                if let Err(e) = res {
                    let _ = conn.execute("ROLLBACK;", ()).await;
                    return Err(ApiError::from(e));
                }
            }

            if let Some(ref stmt_rev) = stmt_revive {
                stmt_rev.reset();
                let res = stmt_rev
                    .execute(libsql::params![parsed.id.as_str(), now])
                    .await;
                stmt_rev.reset();
                match res {
                    Ok(n) if n > 0 => {
                        revived += 1;
                    }
                    Ok(_) => {}
                    Err(e) => {
                        let _ = conn.execute("ROLLBACK;", ()).await;
                        return Err(ApiError::from(e));
                    }
                }
            }
        }

        stmt_link.reset();
        let link_res = stmt_link
            .execute(libsql::params![parsed.id.as_str(), source_id, now])
            .await;
        stmt_link.reset();
        if let Err(e) = link_res {
            let _ = conn.execute("ROLLBACK;", ()).await;
            return Err(ApiError::from(e));
        }
    }

    conn.execute("COMMIT;", ()).await?;

    Ok(Json(ImportBatchResponse {
        source_id,
        total_received,
        inserted_new,
        updated_existing,
        revived,
        invalid_format,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/proxies",
    tag = "Proxies",
    operation_id = "list_proxies",
    summary = "Filter and list proxies",
    description = "Retrieves a paginated list of proxies filtered by operational state, protocol, country, anonymity level, uptime percentage, and maximum latency (RTT).",
    params(ProxyFilterQuery),
    responses(
        (status = 200, description = "Array of proxy short items matching the filter criteria", body = Vec<ProxyShortItem>),
        (status = 400, description = "Validation error: invalid query filter parameters", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn list(
    State(state): State<AppState>,
    Query(filter): Query<ProxyFilterQuery>,
) -> Result<Json<Vec<ProxyShortItem>>, ApiError> {
    let conn = state.connect_db().await?;
    let items = query_proxies(&conn, &filter).await?;
    Ok(Json(items))
}

#[utoipa::path(
    get,
    path = "/api/v1/proxies/{id}",
    tag = "Proxies",
    operation_id = "get_proxy_by_id",
    summary = "Retrieve complete proxy details",
    description = "Fetches the full specification and performance metrics for a specific proxy identified by `ip:port` or `ip:port:login:pwd`, including historical latency, uptime percentage, check policy, and source associations.",
    params(
        ("id" = String, Path, description = "Target proxy identifier in `ip:port` or `ip:port:login:pwd` format. Note: When transmitting in HTTP request URLs, the ID MUST be URL-encoded (percent-encoded, e.g. encodeURIComponent in JS / quote in Python), particularly if credentials contain characters such as '/', '?', '#', '@', or '%'. Example: '185.220.101.5:1080:myuser:p%40ss%2Fword' or IPv6 '[2001:db8::1]:8080'.", example = "185.220.101.5:1080:myuser:mypassword")
    ),
    responses(
        (status = 200, description = "Full proxy details and operational metrics", body = ProxyFullDetails),
        (status = 400, description = "Validation error: invalid proxy ID format", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 404, description = "Proxy not found in database", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn get_by_id(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<Json<ProxyFullDetails>, ApiError> {
    let conn = state.connect_db().await?;
    let row = match get_proxy_by_id(&conn, &id).await? {
        Some(r) => r,
        None => return Err(ApiError::not_found(format!("Proxy '{id}' not found"))),
    };

    let sources = get_sources_for_proxy(&conn, &id).await?;
    let source_details = get_source_details_for_proxy(&conn, &id).await?;
    let proto = row.protocol.clone().unwrap_or_else(|| "http".to_string());
    let host_port = match row.ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(v6)) => format!("[{}]:{}", v6, row.port),
        _ => format!("{}:{}", row.ip, row.port),
    };
    let has_auth = row.auth_user.is_some();
    let url = match (&row.auth_user, &row.auth_pass) {
        (Some(u), Some(p)) if !p.is_empty() => format!("{proto}://{u}:{p}@{host_port}"),
        (Some(u), _) => format!("{proto}://{u}@{host_port}"),
        _ => format!("{proto}://{host_port}"),
    };

    let uptime_pct = if row.checks_total > 0 {
        (row.checks_success as f32 / row.checks_total as f32) * 100.0
    } else {
        0.0
    };

    let now = Utc::now().timestamp();
    let effective_stability = if let Some(last_chk) = row.last_checked_at {
        let window_sec = (row.stability_window_min.max(1) as i64) * 60;
        if last_chk < now - window_sec {
            0.0
        } else {
            row.stability_pct
        }
    } else {
        0.0
    };

    Ok(Json(ProxyFullDetails {
        id: row.id,
        ip: row.ip,
        port: row.port,
        url,
        has_auth,
        auth_user: row.auth_user,
        auth_pass: row.auth_pass,
        state: row.state,
        protocol: if row.state == crate::models::ProxyState::Alive && row.protocol.is_none() {
            Some("http".to_string())
        } else {
            row.protocol
        },
        supports_https: row.supports_https,
        out_ip: row.out_ip,
        country: row.country,
        asn: row.asn,
        asn_org: row.asn_org,
        anon: row.anon,
        metrics: ProxyMetricsDto {
            rtt_tcp_ms: row.rtt_tcp_ms,
            rtt_handshake_ms: row.rtt_handshake_ms,
            rtt_total_ms: row.rtt_total_ms,
        },
        policy: crate::models::CheckPolicyDto {
            connect_timeout_ms: row.connect_timeout_ms,
            handshake_timeout_ms: row.handshake_timeout_ms,
            rw_timeout_ms: row.rw_timeout_ms,
            recheck_alive_sec: row.recheck_alive_sec,
            recheck_dead_sec: row.recheck_dead_sec,
            max_dead_strikes_zero: row.max_dead_strikes_zero,
            max_dead_strikes_active: row.max_dead_strikes_active,
            stability_window_min: row.stability_window_min,
            dead_backoff_mult_zero: row.dead_backoff_mult_zero,
            dead_backoff_mult_active: row.dead_backoff_mult_active,
        },
        stats: ProxyStatsDto {
            checks_total: row.checks_total,
            checks_success: row.checks_success,
            uptime_pct,
            stability_pct: effective_stability,
            dead_strikes: row.dead_strikes,
            last_error: row.last_error,
            first_seen_at: row.first_seen_at,
            last_checked_at: row.last_checked_at,
            next_check_at: row.next_check_at,
        },
        meta: ProxyMetaDto {
            remark: row.remark,
            sources,
            source_details,
        },
    }))
}

#[utoipa::path(
    patch,
    path = "/api/v1/proxies/{id}",
    tag = "Proxies",
    operation_id = "patch_proxy",
    summary = "Update proxy configuration",
    description = "Modifies proxy metadata (user remark), credentials, overrides verification policy (timeouts, strike limits), and optionally schedules an immediate recheck or resets protocol to auto-detect.",
    params(
        ("id" = String, Path, description = "Target proxy identifier in `ip:port` or `ip:port:login:pwd` format. Note: When transmitting in HTTP request URLs, the ID MUST be URL-encoded (percent-encoded). Example: '185.220.101.5:1080:myuser:p%40ss%2Fword' or IPv6 '[2001:db8::1]:8080'.", example = "185.220.101.5:1080:myuser:mypassword")
    ),
    request_body(content = PatchProxyRequest, description = "Fields to modify and optional recheck trigger"),
    responses(
        (status = 200, description = "Proxy updated successfully"),
        (status = 400, description = "Validation error: invalid request payload or policy settings", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 404, description = "Proxy not found in database", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn patch(
    State(state): State<AppState>,
    Path(id): Path<String>,
    Json(req): Json<PatchProxyRequest>,
) -> Result<StatusCode, ApiError> {
    let conn = state.connect_db().await?;
    let now = Utc::now().timestamp();

    let updated = patch_proxy(&conn, &id, &req, now).await?;
    if updated {
        Ok(StatusCode::OK)
    } else {
        Err(ApiError::not_found(format!("Proxy '{id}' not found")))
    }
}

#[utoipa::path(
    delete,
    path = "/api/v1/proxies/{id}",
    tag = "Proxies",
    operation_id = "delete_proxy",
    summary = "Permanently delete proxy",
    description = "Removes a proxy and its source associations permanently from the database and active verification queues.",
    params(
        ("id" = String, Path, description = "Target proxy identifier in `ip:port` or `ip:port:login:pwd` format. Note: When transmitting in HTTP request URLs, the ID MUST be URL-encoded (percent-encoded). Example: '185.220.101.5:1080:myuser:p%40ss%2Fword' or IPv6 '[2001:db8::1]:8080'.", example = "185.220.101.5:1080:myuser:mypassword")
    ),
    responses(
        (status = 204, description = "Proxy successfully deleted"),
        (status = 400, description = "Validation error: invalid proxy ID format", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 404, description = "Proxy not found in database", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn delete(
    State(state): State<AppState>,
    Path(id): Path<String>,
) -> Result<StatusCode, ApiError> {
    let conn = state.connect_db().await?;
    let deleted = delete_proxy(&conn, &id).await?;
    if deleted {
        Ok(StatusCode::NO_CONTENT)
    } else {
        Err(ApiError::not_found(format!("Proxy '{id}' not found")))
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/proxies/report-fail",
    tag = "Proxies",
    operation_id = "report_proxy_failure",
    summary = "Report client-side proxy failure (single or batch)",
    description = "Enables client workers and proxy gateways to immediately signal unexpected failures (connection drops, target bans, timeouts) for one or multiple active proxies. Increments strike counts and schedules urgent verification checks. Accepts either single 'id' or batch 'ids'.",
    request_body(content = ReportFailRequest, description = "Proxy failure payload (single 'id' or batch 'ids' with failure reason)"),
    responses(
        (status = 200, description = "Failures logged and proxies scheduled for immediate recheck", body = ReportFailResponse),
        (status = 400, description = "Validation error: missing proxy ID(s) or reason", body = ApiError),
        (status = 401, description = "Missing or invalid API key", body = ApiError),
        (status = 404, description = "None of the specified proxies found in alive state", body = ApiError),
        (status = 500, description = "Internal database or server error", body = ApiError)
    ),
    security(("api_key" = []))
)]
pub async fn report_fail(
    State(state): State<AppState>,
    Json(req): Json<ReportFailRequest>,
) -> Result<Json<ReportFailResponse>, ApiError> {
    let conn = state.connect_db().await?;
    let now = Utc::now().timestamp();

    let mut target_ids = Vec::new();
    if let Some(ref single_id) = req.id {
        let trimmed = single_id.trim();
        if !trimmed.is_empty() {
            target_ids.push(trimmed.to_string());
        }
    }
    if let Some(ref batch_ids) = req.ids {
        for id in batch_ids {
            let trimmed = id.trim();
            if !trimmed.is_empty() && !target_ids.iter().any(|existing| existing == trimmed) {
                target_ids.push(trimmed.to_string());
            }
        }
    }

    if target_ids.is_empty() {
        return Err(ApiError::bad_request(
            "Missing proxy 'id' or 'ids' in request payload",
        ));
    }

    let affected_ids = report_fails_batch(&conn, &target_ids, &req.reason, now).await?;
    if affected_ids.is_empty() {
        return Err(ApiError::not_found(
            "None of the specified proxies were found in alive state",
        ));
    }

    Ok(Json(ReportFailResponse {
        status: "reported".to_string(),
        affected_count: affected_ids.len(),
        proxy_id: affected_ids.first().cloned(),
        reported_ids: affected_ids,
    }))
}
