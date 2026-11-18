use libsql::Connection;
use std::collections::HashMap;

use crate::models::{
    AsnStatsDto, CountryStatsDto, PatchProxyRequest, PoolCountsDto, PoolQualityDto,
    ProxyFilterQuery, ProxyRow, ProxyShortItem, ProxyState,
};

pub async fn insert_proxy_if_not_exists(
    conn: &Connection,
    row: &ProxyRow,
    ignore_protocol: bool,
) -> Result<bool, libsql::Error> {
    let affected = conn
        .execute(
            "INSERT OR IGNORE INTO proxies (
                id, ip, port, auth_user, auth_pass, state, protocol, supports_https,
                out_ip, country, asn, asn_org, anon,
                rtt_tcp_ms, rtt_handshake_ms, rtt_total_ms,
                connect_timeout_ms, handshake_timeout_ms, rw_timeout_ms,
                recheck_alive_sec, recheck_dead_sec, max_dead_strikes, stability_window_min, dead_backoff_mult,
                checks_total, checks_success, dead_strikes, last_error, stability_pct, recent_checks, remark,
                first_seen_at, last_checked_at, next_check_at
             ) VALUES (
                ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8,
                ?9, ?10, ?11, ?12, ?13,
                ?14, ?15, ?16,
                ?17, ?18, ?19,
                ?20, ?21, ?22, ?23, ?24,
                ?25, ?26, ?27, ?28, ?29, ?30, ?31,
                ?32, ?33, ?34
             );",
            libsql::params![
                row.id.as_str(),
                row.ip.as_str(),
                row.port as i64,
                row.auth_user.as_deref(),
                row.auth_pass.as_deref(),
                row.state.to_i64(),
                row.protocol.as_deref(),
                if row.supports_https { 1i64 } else { 0i64 },
                row.out_ip.as_deref(),
                row.country.as_deref(),
                row.asn.map(|v| v as i64),
                row.asn_org.as_deref(),
                row.anon.as_deref(),
                row.rtt_tcp_ms.map(|v| v as i64),
                row.rtt_handshake_ms.map(|v| v as i64),
                row.rtt_total_ms.map(|v| v as i64),
                row.connect_timeout_ms as i64,
                row.handshake_timeout_ms as i64,
                row.rw_timeout_ms as i64,
                row.recheck_alive_sec as i64,
                row.recheck_dead_sec as i64,
                row.max_dead_strikes as i64,
                row.stability_window_min as i64,
                row.dead_backoff_mult as f64,
                row.checks_total as i64,
                row.checks_success as i64,
                row.dead_strikes as i64,
                row.last_error.as_deref(),
                row.stability_pct as f64,
                row.recent_checks.as_deref(),
                row.remark.as_deref(),
                row.first_seen_at,
                row.last_checked_at,
                row.next_check_at,
            ],
        )
        .await?;

    let inserted = affected > 0;
    if !inserted {
        if ignore_protocol {
            conn.execute(
                "UPDATE proxies SET
                    protocol = NULL,
                    auth_user = COALESCE(?1, auth_user),
                    auth_pass = COALESCE(?2, auth_pass)
                 WHERE id = ?3;",
                libsql::params![
                    row.auth_user.as_deref(),
                    row.auth_pass.as_deref(),
                    row.id.as_str()
                ],
            )
            .await?;
        } else if row.auth_user.is_some() || row.protocol.is_some() {
            conn.execute(
                "UPDATE proxies SET
                    auth_user = COALESCE(?1, auth_user),
                    auth_pass = COALESCE(?2, auth_pass),
                    protocol = COALESCE(?3, protocol)
                 WHERE id = ?4;",
                libsql::params![
                    row.auth_user.as_deref(),
                    row.auth_pass.as_deref(),
                    row.protocol.as_deref(),
                    row.id.as_str()
                ],
            )
            .await?;
        }
    }

    Ok(inserted)
}

pub async fn revive_if_dead(conn: &Connection, id: &str, now: i64) -> Result<bool, libsql::Error> {
    let affected = conn
        .execute(
            "UPDATE proxies
             SET state = 0, dead_strikes = 0, next_check_at = ?2, stability_pct = 0.0, recent_checks = NULL
             WHERE id = ?1 AND state = 3;",
            libsql::params![id, now],
        )
        .await?;

    Ok(affected > 0)
}

fn map_proxy_row(row: &libsql::Row) -> Result<ProxyRow, libsql::Error> {
    let state_num: i64 = row.get(5)?;
    let supports_https_num: i64 = row.get(7)?;
    let rtt_tcp: Option<i64> = row.get(13)?;
    let rtt_handshake: Option<i64> = row.get(14)?;
    let rtt_total: Option<i64> = row.get(15)?;
    let connect_timeout: i64 = row.get(16)?;
    let handshake_timeout: i64 = row.get(17)?;
    let rw_timeout: i64 = row.get(18)?;
    let recheck_alive: i64 = row.get(19)?;
    let recheck_dead: i64 = row.get(20)?;
    let max_strikes: i64 = row.get(21)?;
    let stability_window: i64 = row.get(22)?;
    let dead_backoff: f64 = row.get(23)?;
    let checks_total: i64 = row.get(24)?;
    let checks_success: i64 = row.get(25)?;
    let dead_strikes: i64 = row.get(26)?;
    let asn_val: Option<i64> = row.get(10)?;
    let port_num: i64 = row.get(2)?;
    let stability_pct_val: f64 = row.get(28)?;

    Ok(ProxyRow {
        id: row.get(0)?,
        ip: row.get(1)?,
        port: port_num as u16,
        auth_user: row.get(3)?,
        auth_pass: row.get(4)?,
        state: ProxyState::from_i64(state_num),
        protocol: row.get(6)?,
        supports_https: supports_https_num != 0,
        out_ip: row.get(8)?,
        country: row.get(9)?,
        asn: asn_val.map(|v| v as u32),
        asn_org: row.get(11)?,
        anon: row.get(12)?,
        rtt_tcp_ms: rtt_tcp.map(|v| v as u32),
        rtt_handshake_ms: rtt_handshake.map(|v| v as u32),
        rtt_total_ms: rtt_total.map(|v| v as u32),
        connect_timeout_ms: connect_timeout as u32,
        handshake_timeout_ms: handshake_timeout as u32,
        rw_timeout_ms: rw_timeout as u32,
        recheck_alive_sec: recheck_alive as u32,
        recheck_dead_sec: recheck_dead as u32,
        max_dead_strikes: max_strikes as u32,
        stability_window_min: stability_window as u32,
        dead_backoff_mult: dead_backoff as f32,
        checks_total: checks_total as u64,
        checks_success: checks_success as u64,
        dead_strikes: dead_strikes as u32,
        last_error: row.get(27)?,
        stability_pct: stability_pct_val as f32,
        recent_checks: row.get(29)?,
        remark: row.get(30)?,
        first_seen_at: row.get(31)?,
        last_checked_at: row.get(32)?,
        next_check_at: row.get(33)?,
    })
}

pub async fn get_proxy_by_id(
    conn: &Connection,
    id: &str,
) -> Result<Option<ProxyRow>, libsql::Error> {
    let sql = "SELECT id, ip, port, auth_user, auth_pass, state, protocol, supports_https,
                      out_ip, country, asn, asn_org, anon, rtt_tcp_ms, rtt_handshake_ms, rtt_total_ms,
                      connect_timeout_ms, handshake_timeout_ms, rw_timeout_ms,
                      recheck_alive_sec, recheck_dead_sec, max_dead_strikes, stability_window_min, dead_backoff_mult,
                      checks_total, checks_success, dead_strikes, last_error, stability_pct, recent_checks, remark,
                      first_seen_at, last_checked_at, next_check_at
               FROM proxies WHERE id = ?1;";

    let mut rows = conn.query(sql, libsql::params![id]).await?;
    if let Some(row) = rows.next().await? {
        Ok(Some(map_proxy_row(&row)?))
    } else {
        Ok(None)
    }
}

pub async fn query_proxies(
    conn: &Connection,
    filter: &ProxyFilterQuery,
) -> Result<Vec<ProxyShortItem>, libsql::Error> {
    let target_state = filter.state.unwrap_or(ProxyState::Alive).to_i64();
    let limit = filter.limit.unwrap_or(100).min(10_000) as i64;
    let offset = filter.offset.unwrap_or(0) as i64;

    let mut query = String::from(
        "SELECT p.id, p.protocol, p.supports_https, p.out_ip, p.country, p.asn, p.asn_org,
                p.anon, p.rtt_tcp_ms, p.rtt_handshake_ms, p.rtt_total_ms,
                p.checks_total, p.checks_success, p.last_checked_at, p.auth_user, p.auth_pass, p.ip, p.port,
                p.state, p.dead_strikes, p.last_error, p.first_seen_at, p.next_check_at, p.remark,
                p.stability_pct, p.stability_window_min
         FROM proxies p
         WHERE p.state = ?1 "
    );

    let mut params: Vec<libsql::Value> = vec![target_state.into()];

    if let Some(ref countries) = filter.country {
        let country_list: Vec<&str> = countries
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !country_list.is_empty() {
            query.push_str("AND p.country IN (");
            for (idx, c) in country_list.iter().enumerate() {
                if idx > 0 {
                    query.push_str(", ");
                }
                params.push((*c).to_string().into());
                query.push_str(&format!("?{}", params.len()));
            }
            query.push_str(") ");
        }
    }

    if let Some(ref countries) = filter.exclude_country {
        let country_list: Vec<&str> = countries
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
            .collect();
        if !country_list.is_empty() {
            query.push_str("AND (p.country IS NULL OR p.country NOT IN (");
            for (idx, c) in country_list.iter().enumerate() {
                if idx > 0 {
                    query.push_str(", ");
                }
                params.push((*c).to_string().into());
                query.push_str(&format!("?{}", params.len()));
            }
            query.push_str(")) ");
        }
    }

    if let Some(ref proto) = filter.protocol {
        params.push(proto.clone().into());
        query.push_str(&format!("AND p.protocol = ?{} ", params.len()));
    }

    if let Some(ref anon) = filter.anon {
        params.push(anon.clone().into());
        query.push_str(&format!("AND p.anon = ?{} ", params.len()));
    }

    if let Some(https) = filter.supports_https {
        params.push(if https { 1i64.into() } else { 0i64.into() });
        query.push_str(&format!("AND p.supports_https = ?{} ", params.len()));
    }

    if let Some(has_auth) = filter.has_auth {
        if has_auth {
            query.push_str("AND p.auth_user IS NOT NULL ");
        } else {
            query.push_str("AND p.auth_user IS NULL ");
        }
    }

    if let Some(max_rtt) = filter.max_rtt {
        params.push((max_rtt as i64).into());
        query.push_str(&format!("AND p.rtt_total_ms <= ?{} ", params.len()));
    }

    if let Some(min_uptime) = filter.min_uptime {
        params.push((min_uptime as f64).into());
        query.push_str(&format!(
            "AND (CAST(p.checks_success AS REAL) / MAX(p.checks_total, 1) * 100) >= ?{} ",
            params.len()
        ));
    }

    if let Some(min_stab) = filter.min_stability {
        let now = chrono::Utc::now().timestamp();
        params.push((min_stab as f64).into());
        if min_stab > 0.0 {
            params.push(now.into());
            query.push_str(&format!(
                "AND p.stability_pct >= ?{} AND (p.last_checked_at IS NOT NULL AND p.last_checked_at >= (?{} - (p.stability_window_min * 60))) ",
                params.len() - 1,
                params.len()
            ));
        } else {
            query.push_str(&format!("AND p.stability_pct >= ?{} ", params.len()));
        }
    }

    if let Some(win_min) = filter.stability_window_min {
        params.push((win_min as i64).into());
        query.push_str(&format!("AND p.stability_window_min = ?{} ", params.len()));
    }

    if let Some(ref source) = filter.source {
        params.push(source.clone().into());
        query.push_str(&format!(
            "AND EXISTS (
                SELECT 1 FROM proxy_sources ps
                JOIN sources s ON s.id = ps.source_id
                WHERE ps.proxy_id = p.id AND s.name = ?{}
            ) ",
            params.len()
        ));
    }

    query.push_str("ORDER BY p.rtt_total_ms ASC NULLS LAST ");

    if limit > 0 {
        params.push(limit.into());
        query.push_str(&format!("LIMIT ?{} ", params.len()));

        if offset > 0 {
            params.push(offset.into());
            query.push_str(&format!("OFFSET ?{} ", params.len()));
        }
    } else if offset > 0 {
        params.push(offset.into());
        query.push_str(&format!("LIMIT -1 OFFSET ?{} ", params.len()));
    }

    let mut rows = conn.query(&query, params).await?;
    let mut items = Vec::new();

    while let Some(row) = rows.next().await? {
        let id: String = row.get(0)?;
        let protocol: Option<String> = row.get(1)?;
        let supports_https_num: i64 = row.get(2)?;
        let out_ip: Option<String> = row.get(3)?;
        let country: Option<String> = row.get(4)?;
        let asn: Option<i64> = row.get(5)?;
        let asn_org: Option<String> = row.get(6)?;
        let anon: Option<String> = row.get(7)?;
        let rtt_tcp_ms: Option<i64> = row.get(8)?;
        let rtt_handshake_ms: Option<i64> = row.get(9)?;
        let rtt_total_ms: Option<i64> = row.get(10)?;
        let checks_total: i64 = row.get(11)?;
        let checks_success: i64 = row.get(12)?;
        let last_checked_at: Option<i64> = row.get(13)?;
        let auth_user: Option<String> = row.get(14)?;
        let auth_pass: Option<String> = row.get(15)?;

        let ip_val: String = row.get(16)?;
        let port_val: i64 = row.get(17)?;

        let state_val: i64 = row.get(18)?;
        let dead_strikes: i64 = row.get(19)?;
        let last_error: Option<String> = row.get(20)?;
        let first_seen_at: i64 = row.get(21)?;
        let next_check_at: i64 = row.get(22)?;
        let remark: Option<String> = row.get(23)?;
        let stability_pct_db: f64 = row.get(24)?;
        let stability_window_min_val: i64 = row.get(25)?;

        let host_port = match ip_val.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V6(v6)) => format!("[{v6}]:{port_val}"),
            _ => format!("{ip_val}:{port_val}"),
        };

        let proto_str = protocol.clone().unwrap_or_else(|| "http".to_string());
        let has_auth = auth_user.is_some();
        let url = match (&auth_user, &auth_pass) {
            (Some(u), Some(p)) if !p.is_empty() => format!("{proto_str}://{u}:{p}@{host_port}"),
            (Some(u), _) => format!("{proto_str}://{u}@{host_port}"),
            _ => format!("{proto_str}://{host_port}"),
        };

        let uptime_pct = if checks_total > 0 {
            (checks_success as f32 / checks_total as f32) * 100.0
        } else {
            0.0
        };

        let now = chrono::Utc::now().timestamp();
        let stability_window_min = stability_window_min_val as u32;
        let effective_stability = if let Some(last_chk) = last_checked_at {
            let window_sec = (stability_window_min.max(1) as i64) * 60;
            if last_chk < now - window_sec {
                0.0
            } else {
                stability_pct_db as f32
            }
        } else {
            0.0
        };

        items.push(ProxyShortItem {
            id,
            ip: ip_val,
            port: port_val as u16,
            url,
            protocol,
            has_auth,
            auth_user,
            auth_pass,
            state: ProxyState::from_i64(state_val),
            supports_https: supports_https_num != 0,
            out_ip,
            country,
            asn: asn.map(|v| v as u32),
            asn_org,
            anon,
            rtt_tcp_ms: rtt_tcp_ms.map(|v| v as u32),
            rtt_handshake_ms: rtt_handshake_ms.map(|v| v as u32),
            rtt_total_ms: rtt_total_ms.map(|v| v as u32),
            uptime_pct,
            stability_pct: effective_stability,
            stability_window_min,
            checks_total: checks_total.max(0) as u64,
            checks_success: checks_success.max(0) as u64,
            dead_strikes: dead_strikes.max(0) as u32,
            last_error,
            remark,
            first_seen_at,
            last_checked_at,
            next_check_at,
        });
    }

    Ok(items)
}

pub async fn patch_proxy(
    conn: &Connection,
    id: &str,
    req: &PatchProxyRequest,
    now: i64,
) -> Result<bool, libsql::Error> {
    let mut sets = Vec::new();
    let mut params: Vec<libsql::Value> = Vec::new();

    if let Some(ref remark) = req.remark {
        params.push(remark.clone().into());
        sets.push(format!("remark = ?{}", params.len()));
    }

    if let Some(ref user) = req.auth_user {
        params.push(user.clone().into());
        sets.push(format!("auth_user = ?{}", params.len()));
    }

    if let Some(ref pass) = req.auth_pass {
        params.push(pass.clone().into());
        sets.push(format!("auth_pass = ?{}", params.len()));
    }

    if req.ignore_protocol.unwrap_or(false) {
        sets.push("protocol = NULL".to_string());
    }

    if let Some(ref policy) = req.policy {
        params.push((policy.connect_timeout_ms as i64).into());
        sets.push(format!("connect_timeout_ms = ?{}", params.len()));

        params.push((policy.handshake_timeout_ms as i64).into());
        sets.push(format!("handshake_timeout_ms = ?{}", params.len()));

        params.push((policy.rw_timeout_ms as i64).into());
        sets.push(format!("rw_timeout_ms = ?{}", params.len()));

        params.push((policy.recheck_alive_sec as i64).into());
        sets.push(format!("recheck_alive_sec = ?{}", params.len()));

        params.push((policy.recheck_dead_sec as i64).into());
        sets.push(format!("recheck_dead_sec = ?{}", params.len()));

        params.push((policy.max_dead_strikes as i64).into());
        sets.push(format!("max_dead_strikes = ?{}", params.len()));

        params.push((policy.stability_window_min as i64).into());
        sets.push(format!("stability_window_min = ?{}", params.len()));

        params.push((policy.dead_backoff_mult as f64).into());
        sets.push(format!("dead_backoff_mult = ?{}", params.len()));
    }

    if req.force_recheck.unwrap_or(false) {
        params.push(now.into());
        sets.push(format!("next_check_at = ?{}", params.len()));
        sets.push("state = CASE WHEN state = 3 THEN 0 ELSE state END".to_string());
        sets.push("dead_strikes = CASE WHEN state = 3 THEN 0 ELSE dead_strikes END".to_string());
    }

    if sets.is_empty() {
        return Ok(true);
    }

    params.push(id.to_string().into());
    let id_param_idx = params.len();

    let sql = format!(
        "UPDATE proxies SET {} WHERE id = ?{}",
        sets.join(", "),
        id_param_idx
    );
    let affected = conn.execute(&sql, params).await?;

    Ok(affected > 0)
}

pub async fn delete_proxy(conn: &Connection, id: &str) -> Result<bool, libsql::Error> {
    let affected = conn
        .execute("DELETE FROM proxies WHERE id = ?1;", libsql::params![id])
        .await?;
    Ok(affected > 0)
}

pub async fn report_fail(
    conn: &Connection,
    id: &str,
    reason: &str,
    now: i64,
) -> Result<bool, libsql::Error> {
    let affected = conn
        .execute(
            "UPDATE proxies
             SET state = 2,
                 dead_strikes = dead_strikes + 1,
                 last_error = ?2,
                 next_check_at = ?3
             WHERE id = ?1 AND state = 1;",
            libsql::params![id, reason, now],
        )
        .await?;

    Ok(affected > 0)
}

pub async fn report_fails_batch(
    conn: &Connection,
    ids: &[String],
    reason: &str,
    now: i64,
) -> Result<Vec<String>, libsql::Error> {
    if ids.is_empty() {
        return Ok(Vec::new());
    }
    conn.execute("BEGIN IMMEDIATE;", ()).await?;
    let mut affected_ids = Vec::with_capacity(ids.len());

    for id in ids {
        let res = conn
            .execute(
                "UPDATE proxies
                 SET state = 2,
                     dead_strikes = dead_strikes + 1,
                     last_error = ?2,
                     next_check_at = ?3
                 WHERE id = ?1 AND state = 1;",
                libsql::params![id.as_str(), reason, now],
            )
            .await;

        match res {
            Ok(n) if n > 0 => {
                affected_ids.push(id.clone());
            }
            Ok(_) => {}
            Err(e) => {
                let _ = conn.execute("ROLLBACK;", ()).await;
                return Err(e);
            }
        }
    }

    conn.execute("COMMIT;", ()).await?;
    Ok(affected_ids)
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MaintenanceStats {
    pub purged_dead_proxies: usize,
    pub purged_orphaned_sources: usize,
}

pub async fn run_db_maintenance(
    conn: &Connection,
    retention_days: u32,
) -> Result<MaintenanceStats, libsql::Error> {
    let now = chrono::Utc::now().timestamp();
    let cutoff = now - (retention_days as i64 * 86400);

    conn.execute("BEGIN IMMEDIATE;", ()).await?;

    let purged_dead = match conn
        .execute(
            "DELETE FROM proxy_sources
             WHERE proxy_id IN (
                 SELECT id FROM proxies
                 WHERE state = 3 AND last_checked_at IS NOT NULL AND last_checked_at < ?1
             );",
            libsql::params![cutoff],
        )
        .await
    {
        Ok(_) => {
            let res = conn
                .execute(
                    "DELETE FROM proxies
                     WHERE state = 3 AND last_checked_at IS NOT NULL AND last_checked_at < ?1;",
                    libsql::params![cutoff],
                )
                .await;
            match res {
                Ok(n) => n as usize,
                Err(e) => {
                    let _ = conn.execute("ROLLBACK;", ()).await;
                    return Err(e);
                }
            }
        }
        Err(e) => {
            let _ = conn.execute("ROLLBACK;", ()).await;
            return Err(e);
        }
    };

    let purged_orphaned = match conn
        .execute(
            "DELETE FROM proxy_sources
             WHERE proxy_id NOT IN (SELECT id FROM proxies);",
            (),
        )
        .await
    {
        Ok(n) => n as usize,
        Err(e) => {
            let _ = conn.execute("ROLLBACK;", ()).await;
            return Err(e);
        }
    };

    conn.execute("COMMIT;", ()).await?;

    // Non-blocking SQLite / libSQL WAL maintenance
    let _ = conn.execute("PRAGMA wal_checkpoint(PASSIVE);", ()).await;
    let _ = conn.execute("PRAGMA incremental_vacuum;", ()).await;
    let _ = conn.execute("PRAGMA optimize;", ()).await;

    Ok(MaintenanceStats {
        purged_dead_proxies: purged_dead,
        purged_orphaned_sources: purged_orphaned,
    })
}

pub async fn fetch_due_proxies(
    conn: &Connection,
    now: i64,
    limit: usize,
) -> Result<Vec<ProxyRow>, libsql::Error> {
    let sql = "
        SELECT id, ip, port, auth_user, auth_pass, state, protocol, supports_https,
               out_ip, country, asn, asn_org, anon, rtt_tcp_ms, rtt_handshake_ms, rtt_total_ms,
               connect_timeout_ms, handshake_timeout_ms, rw_timeout_ms,
               recheck_alive_sec, recheck_dead_sec, max_dead_strikes, stability_window_min, dead_backoff_mult,
               checks_total, checks_success, dead_strikes, last_error, stability_pct, recent_checks, remark,
               first_seen_at, last_checked_at, next_check_at
        FROM proxies
        WHERE state IN (0, 1, 2) AND next_check_at <= ?1
        ORDER BY
          CASE state WHEN 1 THEN 0 WHEN 0 THEN 1 ELSE 2 END,
          next_check_at ASC
        LIMIT ?2;
    ";

    let mut rows = conn.query(sql, libsql::params![now, limit as i64]).await?;

    let mut results = Vec::new();
    while let Some(row) = rows.next().await? {
        results.push(map_proxy_row(&row)?);
    }
    Ok(results)
}

pub async fn get_global_stats(
    conn: &Connection,
) -> Result<
    (
        PoolCountsDto,
        PoolQualityDto,
        HashMap<String, u64>,
        HashMap<String, u64>,
        HashMap<String, u64>,
        Vec<CountryStatsDto>,
        Vec<AsnStatsDto>,
    ),
    libsql::Error,
> {
    // 1. Pool counts and quality aggregation in a single query
    let mut pool_rows = conn
        .query(
            "SELECT
              COUNT(*) AS total,
              COALESCE(SUM(CASE WHEN state = 1 THEN 1 ELSE 0 END), 0) AS alive,
              COALESCE(SUM(CASE WHEN state = 0 THEN 1 ELSE 0 END), 0) AS cold_queue,
              COALESCE(SUM(CASE WHEN state = 2 THEN 1 ELSE 0 END), 0) AS cooldown,
              COALESCE(SUM(CASE WHEN state = 3 THEN 1 ELSE 0 END), 0) AS dead_permanent,
              COALESCE(SUM(checks_total), 0) AS total_checks,
              COALESCE(SUM(checks_success), 0) AS total_checks_success,
              CAST(AVG(CASE WHEN state = 1 THEN rtt_total_ms END) AS INTEGER) AS avg_rtt_total,
              CAST(AVG(CASE WHEN state = 1 THEN rtt_tcp_ms END) AS INTEGER) AS avg_rtt_tcp,
              CAST(AVG(CASE WHEN state = 1 THEN rtt_handshake_ms END) AS INTEGER) AS avg_rtt_handshake,
              COALESCE(SUM(CASE WHEN state = 1 AND supports_https = 1 THEN 1 ELSE 0 END), 0) AS supports_https_count,
              COALESCE(SUM(CASE WHEN state = 1 AND auth_user IS NOT NULL THEN 1 ELSE 0 END), 0) AS with_auth_count,
              COALESCE(SUM(CASE WHEN state = 1 AND auth_user IS NULL THEN 1 ELSE 0 END), 0) AS no_auth_count
             FROM proxies;",
            (),
        )
        .await?;

    let (pool, mut quality) = if let Some(row) = pool_rows.next().await? {
        let total: i64 = row.get(0)?;
        let alive: i64 = row.get(1)?;
        let cold: i64 = row.get(2)?;
        let cool: i64 = row.get(3)?;
        let dead: i64 = row.get(4)?;
        let total_checks: i64 = row.get(5)?;
        let total_success: i64 = row.get(6)?;
        let avg_rtt: Option<i64> = row.get(7)?;
        let avg_tcp: Option<i64> = row.get(8)?;
        let avg_hs: Option<i64> = row.get(9)?;
        let https_count: i64 = row.get(10)?;
        let with_auth: i64 = row.get(11)?;
        let no_auth: i64 = row.get(12)?;

        let uptime_pct = if total_checks > 0 {
            (total_success as f32 / total_checks as f32) * 100.0
        } else {
            0.0
        };

        (
            PoolCountsDto {
                total: total.max(0) as u64,
                alive: alive.max(0) as u64,
                cold_queue: cold.max(0) as u64,
                cooldown: cool.max(0) as u64,
                dead_permanent: dead.max(0) as u64,
            },
            PoolQualityDto {
                total_checks: total_checks.max(0) as u64,
                total_checks_success: total_success.max(0) as u64,
                uptime_pct,
                avg_rtt_ms: avg_rtt.map(|v| v.max(0) as u32),
                avg_rtt_tcp_ms: avg_tcp.map(|v| v.max(0) as u32),
                avg_rtt_handshake_ms: avg_hs.map(|v| v.max(0) as u32),
                supports_https_count: https_count.max(0) as u64,
                with_auth_count: with_auth.max(0) as u64,
                no_auth_count: no_auth.max(0) as u64,
                total_sources: 0,
            },
        )
    } else {
        (
            PoolCountsDto {
                total: 0,
                alive: 0,
                cold_queue: 0,
                cooldown: 0,
                dead_permanent: 0,
            },
            PoolQualityDto {
                total_checks: 0,
                total_checks_success: 0,
                uptime_pct: 0.0,
                avg_rtt_ms: None,
                avg_rtt_tcp_ms: None,
                avg_rtt_handshake_ms: None,
                supports_https_count: 0,
                with_auth_count: 0,
                no_auth_count: 0,
                total_sources: 0,
            },
        )
    };

    // 2. Count total sources
    let mut sources_rows = conn.query("SELECT COUNT(*) FROM sources;", ()).await?;
    if let Some(row) = sources_rows.next().await? {
        let sc: i64 = row.get(0)?;
        quality.total_sources = sc.max(0) as u64;
    }

    // 3. By protocol (alive only)
    let mut proto_rows = conn
        .query(
            "SELECT protocol, COUNT(*) AS cnt
             FROM proxies WHERE state = 1 AND protocol IS NOT NULL
             GROUP BY protocol;",
            (),
        )
        .await?;

    let mut by_protocol = HashMap::new();
    while let Some(row) = proto_rows.next().await? {
        let proto: String = row.get(0)?;
        let cnt: i64 = row.get(1)?;
        by_protocol.insert(proto, cnt.max(0) as u64);
    }

    // 4. By anonymity (alive only)
    let mut anon_rows = conn
        .query(
            "SELECT anon, COUNT(*) AS cnt
             FROM proxies WHERE state = 1 AND anon IS NOT NULL
             GROUP BY anon;",
            (),
        )
        .await?;

    let mut by_anonymity = HashMap::new();
    while let Some(row) = anon_rows.next().await? {
        let anon: String = row.get(0)?;
        let cnt: i64 = row.get(1)?;
        by_anonymity.insert(anon, cnt.max(0) as u64);
    }

    // 5. By error (all errors recorded on proxies)
    let mut error_rows = conn
        .query(
            "SELECT last_error, COUNT(*) AS cnt
             FROM proxies WHERE last_error IS NOT NULL
             GROUP BY last_error
             ORDER BY cnt DESC
             LIMIT 20;",
            (),
        )
        .await?;

    let mut by_error = HashMap::new();
    while let Some(row) = error_rows.next().await? {
        let err_reason: String = row.get(0)?;
        let cnt: i64 = row.get(1)?;
        by_error.insert(err_reason, cnt.max(0) as u64);
    }

    // 6. Top countries (alive only)
    let mut country_rows = conn
        .query(
            "SELECT country, COUNT(*) AS alive_count,
                    COALESCE(CAST(AVG(rtt_total_ms) AS INTEGER), 0) AS avg_rtt_ms
             FROM proxies WHERE state = 1 AND country IS NOT NULL
             GROUP BY country
             ORDER BY alive_count DESC
             LIMIT 20;",
            (),
        )
        .await?;

    let mut top_countries = Vec::new();
    while let Some(row) = country_rows.next().await? {
        let country: String = row.get(0)?;
        let alive_count: i64 = row.get(1)?;
        let avg_rtt_ms: i64 = row.get(2)?;
        top_countries.push(CountryStatsDto {
            country,
            alive_count: alive_count.max(0) as u64,
            avg_rtt_ms: avg_rtt_ms.max(0) as u32,
        });
    }

    // 7. Top ASNs (alive only)
    let mut asn_rows = conn
        .query(
            "SELECT asn, asn_org, COUNT(*) AS alive_count,
                    COALESCE(CAST(AVG(rtt_total_ms) AS INTEGER), 0) AS avg_rtt_ms
             FROM proxies WHERE state = 1 AND asn IS NOT NULL
             GROUP BY asn, asn_org
             ORDER BY alive_count DESC
             LIMIT 20;",
            (),
        )
        .await?;

    let mut top_asns = Vec::new();
    while let Some(row) = asn_rows.next().await? {
        let asn_val: i64 = row.get(0)?;
        let asn_org: Option<String> = row.get(1)?;
        let alive_count: i64 = row.get(2)?;
        let avg_rtt_ms: i64 = row.get(3)?;
        top_asns.push(AsnStatsDto {
            asn: asn_val as u32,
            asn_org,
            alive_count: alive_count.max(0) as u64,
            avg_rtt_ms: avg_rtt_ms.max(0) as u32,
        });
    }

    Ok((
        pool,
        quality,
        by_protocol,
        by_anonymity,
        by_error,
        top_countries,
        top_asns,
    ))
}
