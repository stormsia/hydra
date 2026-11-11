use libsql::Connection;
use crate::models::ProxySourceMetaDto;

pub async fn link_proxy_to_source(
    conn: &Connection,
    proxy_id: &str,
    source_id: i64,
    now: i64,
) -> Result<bool, libsql::Error> {
    let affected = conn
        .execute(
            "INSERT OR IGNORE INTO proxy_sources (proxy_id, source_id, added_at)
             VALUES (?1, ?2, ?3);",
            libsql::params![proxy_id, source_id, now],
        )
        .await?;

    Ok(affected > 0)
}

pub async fn get_sources_for_proxy(
    conn: &Connection,
    proxy_id: &str,
) -> Result<Vec<String>, libsql::Error> {
    let mut rows = conn
        .query(
            "SELECT s.name
             FROM sources s
             JOIN proxy_sources ps ON ps.source_id = s.id
             WHERE ps.proxy_id = ?1
             ORDER BY s.name ASC;",
            libsql::params![proxy_id],
        )
        .await?;

    let mut names = Vec::new();
    while let Some(row) = rows.next().await? {
        names.push(row.get::<String>(0)?);
    }
    Ok(names)
}

pub async fn get_source_details_for_proxy(
    conn: &Connection,
    proxy_id: &str,
) -> Result<Vec<ProxySourceMetaDto>, libsql::Error> {
    let mut rows = conn
        .query(
            "SELECT s.name, ps.added_at
             FROM sources s
             JOIN proxy_sources ps ON ps.source_id = s.id
             WHERE ps.proxy_id = ?1
             ORDER BY s.name ASC;",
            libsql::params![proxy_id],
        )
        .await?;

    let mut details = Vec::new();
    while let Some(row) = rows.next().await? {
        let name: String = row.get(0)?;
        let added_at: i64 = row.get(1)?;
        details.push(ProxySourceMetaDto { name, added_at });
    }
    Ok(details)
}
