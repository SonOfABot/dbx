//! dbx-mysql — MySQL / MariaDB protocol driver for dbx.
//!
//! Native wire protocol via mysql_async. No TLS backend is compiled in
//! (droppable-binary rule: no OpenSSL anywhere); MySQL 8's default
//! caching_sha2_password still works over plaintext through the server's
//! RSA public-key exchange. MariaDB's mysql_native_password works;
//! ed25519 auth is NOT supported by the driver and surfaces as a
//! protocol error.

mod modules;

use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use dbx_core::*;
use mysql_async::prelude::Queryable;
use mysql_async::{Conn, OptsBuilder, Row, Value};
use tokio::sync::Mutex;

/// `Conn` is neither `Clone` nor usable without `&mut`, so the whole
/// driver shares one connection behind a mutex — same pattern as the
/// MSSQL driver.
pub(crate) type MyConn = Arc<Mutex<Conn>>;

const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Map wire/server errors onto spray-friendly auth semantics.
///
/// 1045 = access denied. 1044 = creds ARE valid but carry no rights on
/// the requested schema — counted as a spray miss for --db runs; without
/// --db the same creds succeed.
pub(crate) fn classify(e: &mysql_async::Error) -> AuthError {
    match e {
        mysql_async::Error::Server(se) => match se.code {
            // 1045 ER_ACCESS_DENIED_ERROR / 1044 ER_DBACCESS_DENIED_ERROR
            1045 | 1044 => AuthError::InvalidCredentials,
            // 1040 too many connections / 1203 user has too many connections
            1040 | 1203 => AuthError::Blocked("connection limit".into()),
            // 1129 host blocked (max_connect_errors) / 1130 host not allowed
            1129 | 1130 => AuthError::Blocked(format!("host blocked: {}", se.message)),
            _ => AuthError::Protocol(format!(
                "mysql error {} ({}): {}",
                se.code, se.state, se.message
            )),
        },
        mysql_async::Error::Io(_) => AuthError::Network(e.to_string()),
        other => AuthError::Protocol(other.to_string()),
    }
}

/// Stringify one cell. Bytes are lossy-decoded (BLOBs may look odd in
/// thief CSVs — acceptable for loot triage).
fn cell_to_string(v: &Value) -> String {
    match v {
        Value::NULL => "NULL".to_string(),
        Value::Bytes(b) => String::from_utf8_lossy(b).into_owned(),
        Value::Int(i) => i.to_string(),
        Value::UInt(u) => u.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Double(d) => d.to_string(),
        Value::Date(y, mo, d, h, mi, s, _us) => {
            format!("{y:04}-{mo:02}-{d:02} {h:02}:{mi:02}:{s:02}")
        }
        Value::Time(neg, days, h, m, s, _us) => {
            let sign = if *neg { "-" } else { "" };
            format!("{sign}{}:{m:02}:{s:02}", days * 24 + u32::from(*h))
        }
    }
}

/// Run a text query, every cell stringified — the workhorse for sessions
/// and modules alike.
pub(crate) async fn query_text(
    conn: &MyConn,
    sql: &str,
) -> Result<Vec<Vec<String>>, AuthError> {
    let mut guard = conn.lock().await;
    let rows: Vec<Row> = guard.query(sql).await.map_err(|e| classify(&e))?;
    Ok(rows
        .iter()
        .map(|r| {
            (0..r.len())
                .map(|i| cell_to_string(r.as_ref(i).unwrap_or(&Value::NULL)))
                .collect()
        })
        .collect())
}

/// Escape a single-quoted string literal (backslash mode on or off).
pub(crate) fn escape_str(s: &str) -> String {
    s.replace('\\', "\\\\").replace('\'', "''")
}

/// Backtick-quote an identifier.
pub(crate) fn quote_ident(s: &str) -> String {
    format!("`{}`", s.replace('`', "``"))
}

/// SHOW GRANTS for the current session user, one line per grant.
pub(crate) async fn grants(conn: &MyConn) -> Result<Vec<String>, AuthError> {
    let rows = query_text(conn, "SHOW GRANTS").await?;
    Ok(rows.into_iter().map(|r| r.join(" ")).collect())
}

/// Case-insensitive substring match across the grant list.
pub(crate) fn has_priv(grant_lines: &[String], needle: &str) -> bool {
    let needle = needle.to_uppercase();
    grant_lines.iter().any(|g| g.to_uppercase().contains(&needle))
}

/// Open one authenticated connection. mysql_async has no connect-timeout
/// option, so the whole handshake is wrapped in tokio's timeout.
async fn connect_db(
    target: &Target,
    cred: &Credential,
    dbname: Option<&str>,
) -> Result<MyConn, AuthError> {
    let builder = OptsBuilder::default()
        .ip_or_hostname(target.host.clone())
        .tcp_port(target.port)
        .user(Some(cred.username.clone()))
        .pass(Some(cred.password.clone()))
        .db_name(dbname.map(|d| d.to_string()));
    match tokio::time::timeout(CONNECT_TIMEOUT, Conn::new(builder)).await {
        Ok(Ok(c)) => Ok(Arc::new(Mutex::new(c))),
        Ok(Err(e)) => Err(classify(&e)),
        Err(_) => Err(AuthError::Network(format!(
            "connect timed out after {}s",
            CONNECT_TIMEOUT.as_secs()
        ))),
    }
}

pub struct MysqlProtocol;

#[async_trait]
impl Protocol for MysqlProtocol {
    fn name(&self) -> &'static str {
        "MYSQL"
    }

    fn default_port(&self) -> u16 {
        3306
    }

    /// MySQL reveals almost nothing pre-auth — a provoked 1045 confirms it.
    async fn fingerprint(&self, target: &Target) -> Result<Fingerprint, AuthError> {
        let bogus = Credential {
            username: "dbx_probe".into(),
            password: "dbx_probe".into(),
        };
        match connect_db(target, &bogus, None).await {
            Err(AuthError::InvalidCredentials) => Ok(Fingerprint {
                version: "MySQL (pre-auth)".into(),
                detail: None,
            }),
            Err(AuthError::Blocked(r)) => Ok(Fingerprint {
                version: "MySQL (pre-auth)".into(),
                detail: Some(r),
            }),
            Err(e) => Err(e),
            Ok(_) => Ok(Fingerprint {
                version: "MySQL".into(),
                detail: Some("probe user exists?!".into()),
            }),
        }
    }

    /// MySQL sessions need no default schema; --db selects one.
    async fn authenticate(&self, target: &Target, cred: &Credential) -> AuthResult {
        match connect_db(target, cred, None).await {
            Ok(conn) => AuthResult::Success(Box::new(MysqlSession {
                target: target.clone(),
                cred: cred.clone(),
                dbname: None,
                conn,
            })),
            Err(e) => AuthResult::Failed(e),
        }
    }

    async fn authenticate_db(&self, target: &Target, cred: &Credential, db: &str) -> AuthResult {
        match connect_db(target, cred, Some(db)).await {
            Ok(conn) => AuthResult::Success(Box::new(MysqlSession {
                target: target.clone(),
                cred: cred.clone(),
                dbname: Some(db.to_string()),
                conn,
            })),
            Err(e) => AuthResult::Failed(e),
        }
    }

    fn module_catalog(&self) -> Vec<ModuleMeta> {
        modules::catalog()
    }
}

struct MysqlSession {
    target: Target,
    cred: Credential,
    dbname: Option<String>,
    conn: MyConn,
}

impl MysqlSession {
    fn require_db(&self) -> Result<&str, AuthError> {
        self.dbname
            .as_deref()
            .filter(|d| !d.is_empty())
            .ok_or_else(|| {
                AuthError::Protocol("no database selected — re-run with --db <name>".into())
            })
    }
}

#[async_trait]
impl Session for MysqlSession {
    /// Admin = ALL PRIVILEGES, GRANT OPTION, or SUPER in SHOW GRANTS.
    /// MySQL 8 dynamic privileges (SYSTEM_VARIABLES_ADMIN etc.) do not
    /// flip this bit on their own — modules check those individually.
    async fn privilege(&self) -> Result<Privilege, AuthError> {
        let g = grants(&self.conn).await?;
        Ok(
            if has_priv(&g, "ALL PRIVILEGES") || has_priv(&g, "GRANT OPTION") || has_priv(&g, "SUPER")
            {
                Privilege::Admin
            } else {
                Privilege::User
            },
        )
    }

    async fn enum_databases(&self) -> Result<Vec<String>, AuthError> {
        let rows = query_text(
            &self.conn,
            "SELECT schema_name FROM information_schema.schemata ORDER BY schema_name",
        )
        .await?;
        Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect())
    }

    async fn query_rows(&self, sql: &str) -> Result<Vec<Vec<String>>, AuthError> {
        query_text(&self.conn, sql).await
    }

    fn db_name(&self) -> Option<String> {
        self.dbname.clone()
    }

    async fn enum_tables(&self) -> Result<Vec<String>, AuthError> {
        let db = self.require_db()?;
        let rows = query_text(
            &self.conn,
            &format!(
                "SELECT table_name FROM information_schema.tables
                 WHERE table_schema = '{}' AND table_type = 'BASE TABLE' ORDER BY table_name",
                escape_str(db)
            ),
        )
        .await?;
        Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect())
    }

    async fn dump_table(&self, table: &str, limit: Option<u64>) -> Result<Dump, AuthError> {
        let db = self.require_db()?.to_string();
        let qualified = format!("{}.{}", quote_ident(&db), quote_ident(table));
        let sql = match limit {
            Some(n) => format!("SELECT * FROM {qualified} LIMIT {n}"),
            None => format!("SELECT * FROM {qualified}"),
        };
        let (mut columns, rows) = {
            let mut guard = self.conn.lock().await;
            let rows: Vec<Row> = guard.query(sql).await.map_err(|e| classify(&e))?;
            let columns: Vec<String> = match rows.first() {
                Some(r) => r
                    .columns_ref()
                    .iter()
                    .map(|c| String::from_utf8_lossy(c.name_ref()).into_owned())
                    .collect(),
                None => Vec::new(),
            };
            (columns, rows)
        };
        if columns.is_empty() {
            // Empty table: column names come from the catalog instead.
            let col_rows = query_text(
                &self.conn,
                &format!(
                    "SELECT column_name FROM information_schema.columns
                     WHERE table_schema = '{}' AND table_name = '{}' ORDER BY ordinal_position",
                    escape_str(&db),
                    escape_str(table)
                ),
            )
            .await?;
            columns = col_rows
                .into_iter()
                .filter_map(|r| r.into_iter().next())
                .collect();
        }
        let rows = rows
            .iter()
            .map(|r| {
                (0..r.len())
                    .map(|i| cell_to_string(r.as_ref(i).unwrap_or(&Value::NULL)))
                    .collect()
            })
            .collect();
        Ok(Dump { columns, rows })
    }

    async fn session_for_db(&self, db: &str) -> Result<Box<dyn Session>, AuthError> {
        let conn = connect_db(&self.target, &self.cred, Some(db)).await?;
        Ok(Box::new(MysqlSession {
            target: self.target.clone(),
            cred: self.cred.clone(),
            dbname: Some(db.to_string()),
            conn,
        }))
    }

    fn module(&self, name: &str) -> Result<Box<dyn Module>, AuthError> {
        modules::instantiate(name, self.conn.clone())
    }
}
