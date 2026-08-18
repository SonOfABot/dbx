use anyhow::Context;
use rusqlite::{params, Connection};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS credentials (
    id         INTEGER PRIMARY KEY,
    protocol   TEXT NOT NULL,
    host       TEXT NOT NULL,
    port       INTEGER NOT NULL,
    username   TEXT NOT NULL,
    password   TEXT NOT NULL,
    privileged INTEGER NOT NULL DEFAULT 0,
    first_seen TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen  TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (protocol, host, port, username, password)
);
CREATE TABLE IF NOT EXISTS databases (
    id      INTEGER PRIMARY KEY,
    cred_id INTEGER NOT NULL REFERENCES credentials(id),
    name    TEXT NOT NULL,
    UNIQUE (cred_id, name)
);
-- created now so the module system needs no migration later:
CREATE TABLE IF NOT EXISTS verified_primitives (
    id         INTEGER PRIMARY KEY,
    cred_id    INTEGER NOT NULL REFERENCES credentials(id),
    module     TEXT NOT NULL,
    detail     TEXT,
    checked_at TEXT NOT NULL DEFAULT (datetime('now')),
    UNIQUE (cred_id, module)
);
CREATE TABLE IF NOT EXISTS module_runs (
    id      INTEGER PRIMARY KEY,
    cred_id INTEGER NOT NULL REFERENCES credentials(id),
    module  TEXT NOT NULL,
    options TEXT,
    output  TEXT,
    ran_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
";

/// Cloneable handle; internally one connection behind a mutex.
/// Writes are tiny and infrequent (only on hits) — contention is a non-issue.
#[derive(Clone)]
pub struct Loot {
    conn: Arc<Mutex<Connection>>,
}

pub struct CredRow {
    pub protocol: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub privileged: bool,
}

impl Loot {
    pub fn open(path: &Path) -> anyhow::Result<Self> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).ok();
        }
        let conn = Connection::open(path)
            .with_context(|| format!("opening loot db at {}", path.display()))?;
        conn.execute_batch(SCHEMA)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)) })
    }

    pub fn default_path() -> PathBuf {
        let home = dirs::home_dir().unwrap_or_else(|| PathBuf::from("."));
        home.join(".dbx").join("loot.db")
    }

    /// Upsert a valid credential; upgrades the privileged flag if we learn
    /// more later, refreshes last_seen. Returns the credential row id.
    pub fn record_credential(
        &self,
        protocol: &str,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
        privileged: bool,
    ) -> anyhow::Result<i64> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO credentials (protocol, host, port, username, password, privileged)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT (protocol, host, port, username, password)
             DO UPDATE SET privileged = MAX(privileged, excluded.privileged),
                           last_seen  = datetime('now')",
            params![protocol, host, port, username, password, privileged as i64],
        )?;
        let id = conn.query_row(
            "SELECT id FROM credentials
             WHERE protocol=?1 AND host=?2 AND port=?3 AND username=?4 AND password=?5",
            params![protocol, host, port, username, password],
            |r| r.get(0),
        )?;
        Ok(id)
    }

    pub fn record_database(&self, cred_id: i64, name: &str) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT OR IGNORE INTO databases (cred_id, name) VALUES (?1, ?2)",
            params![cred_id, name],
        )?;
        Ok(())
    }

    pub fn credentials(&self, protocol: Option<&str>) -> anyhow::Result<Vec<CredRow>> {
        let conn = self.conn.lock().unwrap();
        let map_row = |r: &rusqlite::Row| -> rusqlite::Result<CredRow> {
            Ok(CredRow {
                protocol: r.get(0)?,
                host: r.get(1)?,
                port: r.get::<_, i64>(2)? as u16,
                username: r.get(3)?,
                password: r.get(4)?,
                privileged: r.get::<_, i64>(5)? != 0,
            })
        };
        let rows: Vec<CredRow> = match protocol {
            Some(p) => conn
                .prepare(
                    "SELECT protocol,host,port,username,password,privileged
                     FROM credentials WHERE protocol=?1 ORDER BY host,port",
                )?
                .query_map(params![p], map_row)?
                .collect::<rusqlite::Result<_>>()?,
            None => conn
                .prepare(
                    "SELECT protocol,host,port,username,password,privileged
                     FROM credentials ORDER BY protocol,host,port",
                )?
                .query_map([], map_row)?
                .collect::<rusqlite::Result<_>>()?,
        };
        Ok(rows)
    }

    pub fn record_verified_primitive(
        &self,
        cred_id: i64,
        module: &str,
        detail: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO verified_primitives (cred_id, module, detail) VALUES (?1, ?2, ?3)
             ON CONFLICT (cred_id, module)
             DO UPDATE SET detail = excluded.detail, checked_at = datetime('now')",
            params![cred_id, module, detail],
        )?;
        Ok(())
    }

    pub fn record_module_run(
        &self,
        cred_id: i64,
        module: &str,
        options: &str,
        output: &str,
    ) -> anyhow::Result<()> {
        let conn = self.conn.lock().unwrap();
        conn.execute(
            "INSERT INTO module_runs (cred_id, module, options, output) VALUES (?1, ?2, ?3, ?4)",
            params![cred_id, module, options, output],
        )?;
        Ok(())
    }
}
