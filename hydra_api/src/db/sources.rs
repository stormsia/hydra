use crate::models::{SourceRow, SourceStatsItem};
use libsql::Connection;

pub async fn upsert_source(
    conn: &Connection,
    name: &str,
    url: Option<&str>,
    remark: Option<&str>,
    now: i64,
) -> Result<i64, libsql::Error> {
    let mut rows = conn
        .query(
            "INSERT INTO sources (name, url, remark, created_at)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(name) DO UPDATE SET
                url = COALESCE(excluded.url, sources.url),
                remark = COALESCE(excluded.remark, sources.remark)
             RETURNING id;",
            libsql::params![name, url, remark, now],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        let id: i64 = row.get(0)?;
        Ok(id)
    } else {
        Err(libsql::Error::QueryReturnedNoRows)
    }
}

pub async fn get_source_by_name(
    conn: &Connection,
    name: &str,
) -> Result<Option<SourceRow>, libsql::Error> {
    let mut rows = conn
        .query(
            "SELECT id, name, url, remark, created_at FROM sources WHERE name = ?1;",
            libsql::params![name],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        Ok(Some(SourceRow {
            id: row.get(0)?,
            name: row.get(1)?,
            url: row.get(2)?,
            remark: row.get(3)?,
            created_at: row.get(4)?,
        }))
    } else {
        Ok(None)
    }
}

pub async fn list_source_stats(conn: &Connection) -> Result<Vec<SourceStatsItem>, libsql::Error> {
    let sql = "
        SELECT s.id, s.name, s.url, s.remark,
            COUNT(ps.proxy_id) AS total_proxies,
            COALESCE(SUM(CASE WHEN p.state = 1 THEN 1 ELSE 0 END), 0) AS alive_proxies,
            COALESCE(SUM(CASE WHEN p.state = 0 THEN 1 ELSE 0 END), 0) AS cold_queue_proxies,
            COALESCE(SUM(CASE WHEN p.state = 2 THEN 1 ELSE 0 END), 0) AS cooldown_proxies,
            COALESCE(SUM(CASE WHEN p.state = 3 THEN 1 ELSE 0 END), 0) AS dead_proxies,
            COALESCE(ROUND(
              CAST(SUM(CASE WHEN p.state = 1 THEN 1 ELSE 0 END) AS REAL) /
              NULLIF(SUM(CASE WHEN p.state != 0 THEN 1 ELSE 0 END), 0) * 100,
              1
            ), 0.0) AS yield_pct,
            CAST(AVG(CASE WHEN p.state = 1 THEN p.rtt_total_ms END) AS INTEGER) AS avg_rtt_ms,
            s.created_at,
            MAX(ps.added_at) AS last_added_at,
            MAX(p.last_checked_at) AS last_checked_at
        FROM sources s
        LEFT JOIN proxy_sources ps ON ps.source_id = s.id
        LEFT JOIN proxies p ON p.id = ps.proxy_id
        GROUP BY s.id
        ORDER BY alive_proxies DESC;
    ";

    let mut rows = conn.query(sql, ()).await?;
    let mut results = Vec::new();

    while let Some(row) = rows.next().await? {
        let id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        let url: Option<String> = row.get(2)?;
        let remark: Option<String> = row.get(3)?;
        let total_proxies: i64 = row.get(4)?;
        let alive_proxies: i64 = row.get(5)?;
        let cold_queue_proxies: i64 = row.get(6)?;
        let cooldown_proxies: i64 = row.get(7)?;
        let dead_proxies: i64 = row.get(8)?;
        let yield_pct_val: f64 = row.get(9).unwrap_or(0.0);
        let avg_rtt_ms: Option<i64> = row.get(10)?;
        let created_at: i64 = row.get(11)?;
        let last_added_at: Option<i64> = row.get(12)?;
        let last_checked_at: Option<i64> = row.get(13)?;

        results.push(SourceStatsItem {
            id,
            name,
            url,
            remark,
            total_proxies: total_proxies.max(0) as u64,
            alive_proxies: alive_proxies.max(0) as u64,
            cold_queue_proxies: cold_queue_proxies.max(0) as u64,
            cooldown_proxies: cooldown_proxies.max(0) as u64,
            dead_proxies: dead_proxies.max(0) as u64,
            yield_pct: yield_pct_val as f32,
            avg_rtt_ms: avg_rtt_ms.map(|v| v as u32),
            created_at,
            last_added_at,
            last_checked_at,
        });
    }

    Ok(results)
}

pub async fn get_source_stats_by_name(
    conn: &Connection,
    name: &str,
) -> Result<Option<SourceStatsItem>, libsql::Error> {
    let sql = "
        SELECT s.id, s.name, s.url, s.remark,
            COUNT(ps.proxy_id) AS total_proxies,
            COALESCE(SUM(CASE WHEN p.state = 1 THEN 1 ELSE 0 END), 0) AS alive_proxies,
            COALESCE(SUM(CASE WHEN p.state = 0 THEN 1 ELSE 0 END), 0) AS cold_queue_proxies,
            COALESCE(SUM(CASE WHEN p.state = 2 THEN 1 ELSE 0 END), 0) AS cooldown_proxies,
            COALESCE(SUM(CASE WHEN p.state = 3 THEN 1 ELSE 0 END), 0) AS dead_proxies,
            COALESCE(ROUND(
              CAST(SUM(CASE WHEN p.state = 1 THEN 1 ELSE 0 END) AS REAL) /
              NULLIF(SUM(CASE WHEN p.state != 0 THEN 1 ELSE 0 END), 0) * 100,
              1
            ), 0.0) AS yield_pct,
            CAST(AVG(CASE WHEN p.state = 1 THEN p.rtt_total_ms END) AS INTEGER) AS avg_rtt_ms,
            s.created_at,
            MAX(ps.added_at) AS last_added_at,
            MAX(p.last_checked_at) AS last_checked_at
        FROM sources s
        LEFT JOIN proxy_sources ps ON ps.source_id = s.id
        LEFT JOIN proxies p ON p.id = ps.proxy_id
        WHERE s.name = ?1
        GROUP BY s.id;
    ";

    let mut rows = conn.query(sql, libsql::params![name]).await?;
    if let Some(row) = rows.next().await? {
        let id: i64 = row.get(0)?;
        let name: String = row.get(1)?;
        let url: Option<String> = row.get(2)?;
        let remark: Option<String> = row.get(3)?;
        let total_proxies: i64 = row.get(4)?;
        let alive_proxies: i64 = row.get(5)?;
        let cold_queue_proxies: i64 = row.get(6)?;
        let cooldown_proxies: i64 = row.get(7)?;
        let dead_proxies: i64 = row.get(8)?;
        let yield_pct_val: f64 = row.get(9).unwrap_or(0.0);
        let avg_rtt_ms: Option<i64> = row.get(10)?;
        let created_at: i64 = row.get(11)?;
        let last_added_at: Option<i64> = row.get(12)?;
        let last_checked_at: Option<i64> = row.get(13)?;

        Ok(Some(SourceStatsItem {
            id,
            name,
            url,
            remark,
            total_proxies: total_proxies.max(0) as u64,
            alive_proxies: alive_proxies.max(0) as u64,
            cold_queue_proxies: cold_queue_proxies.max(0) as u64,
            cooldown_proxies: cooldown_proxies.max(0) as u64,
            dead_proxies: dead_proxies.max(0) as u64,
            yield_pct: yield_pct_val as f32,
            avg_rtt_ms: avg_rtt_ms.map(|v| v as u32),
            created_at,
            last_added_at,
            last_checked_at,
        }))
    } else {
        Ok(None)
    }
}

pub async fn delete_source(conn: &Connection, name: &str) -> Result<bool, libsql::Error> {
    let affected = conn
        .execute(
            "DELETE FROM sources WHERE name = ?1;",
            libsql::params![name],
        )
        .await?;

    if affected > 0 {
        // Clean up orphan proxies if no sources reference them
        let _ = conn.execute(
            "DELETE FROM proxies WHERE id NOT IN (SELECT DISTINCT proxy_id FROM proxy_sources);",
            (),
        ).await;
        Ok(true)
    } else {
        Ok(false)
    }
}
