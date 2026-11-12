use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};
use libsql::{Builder, Connection, Database};

static DB_COUNTER: AtomicU64 = AtomicU64::new(1);

/// Centralized connection configuration for SQLite / libSQL.
/// Configures busy timeout, enables foreign keys (per-connection!), sets cache, memory temp store,
/// memory-mapped I/O, and NORMAL synchronous mode for high-throughput WAL operations.
pub async fn configure_conn(conn: &Connection) -> Result<(), libsql::Error> {
    let _ = conn.busy_timeout(Duration::from_millis(5000));
    let _ = conn.query("PRAGMA busy_timeout = 5000;", ()).await;
    conn.execute("PRAGMA foreign_keys = ON;", ()).await?;
    conn.execute("PRAGMA cache_size = -64000;", ()).await?;
    conn.execute("PRAGMA temp_store = MEMORY;", ()).await?;
    let _ = conn.query("PRAGMA mmap_size = 268435456;", ()).await;
    conn.execute("PRAGMA synchronous = NORMAL;", ()).await?;
    Ok(())
}

pub async fn init_db(db_path: &str) -> Result<Database, libsql::Error> {
    let resolved_path = if db_path == ":memory:" {
        let counter = DB_COUNTER.fetch_add(1, Ordering::Relaxed);
        let now_nanos = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let temp_file = std::env::temp_dir().join(format!(
            "hydra_test_{}_{}_{}.db",
            std::process::id(),
            now_nanos,
            counter
        ));
        temp_file.to_string_lossy().to_string()
    } else {
        db_path.to_string()
    };

    if let Some(parent) = Path::new(&resolved_path).parent()
        && !parent.as_os_str().is_empty() {
            let _ = std::fs::create_dir_all(parent);
        }

    let db = Builder::new_local(&resolved_path).build().await?;
    run_migrations(&db).await?;
    Ok(db)
}

pub async fn run_migrations(db: &Database) -> Result<(), libsql::Error> {
    let conn = db.connect()?;
    configure_conn(&conn).await?;

    // auto_vacuum MUST be set before tables are created and before WAL mode transition
    conn.execute("PRAGMA auto_vacuum = INCREMENTAL;", ()).await?;
    let _ = conn.query("PRAGMA journal_mode = WAL;", ()).await;

    // Safe incremental migration for existing databases created with older schema:
    // We add missing columns BEFORE running execute_batch(schema_sql) so that any
    // indexes referencing these new columns (such as idx_alive_stability) do not fail with
    // "no such column: stability_pct" when table `proxies` already existed.
    let _ = conn
        .execute(
            "ALTER TABLE proxies ADD COLUMN stability_window_min INTEGER NOT NULL DEFAULT 5;",
            (),
        )
        .await;
    let _ = conn
        .execute(
            "ALTER TABLE proxies ADD COLUMN dead_backoff_mult REAL NOT NULL DEFAULT 1.5;",
            (),
        )
        .await;
    let _ = conn
        .execute(
            "ALTER TABLE proxies ADD COLUMN stability_pct REAL NOT NULL DEFAULT 0.0;",
            (),
        )
        .await;
    let _ = conn
        .execute("ALTER TABLE proxies ADD COLUMN recent_checks TEXT;", ())
        .await;

    let schema_sql = include_str!("../../migrations/001_initial.sql");
    conn.execute_batch(schema_sql).await?;

    Ok(())
}
