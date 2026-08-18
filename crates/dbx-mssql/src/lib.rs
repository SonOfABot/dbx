mod modules;

use async_trait::async_trait;
use dbx_core::*;
use futures_util::TryStreamExt;
use std::sync::Arc;
use tiberius::{AuthMethod, Client, Config, QueryItem, Row};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_util::compat::{Compat, TokioAsyncWriteCompatExt};

/// tiberius queries need &mut Client — sessions share one via Mutex.
type Conn = Arc<Mutex<Client<Compat<TcpStream>>>>;

pub struct MssqlProtocol;

/// SQL Server error numbers do the classification work:
/// 18456 = login failed (bad creds), 18470 = locked, 18486/18487 = lockout
/// policy / password must change.
pub(crate) fn classify(e: &tiberius::error::Error) -> AuthError {
    match e {
        tiberius::error::Error::Server(se) => match se.code() {
            18456 => AuthError::InvalidCredentials,
            18470 => AuthError::Blocked("account is locked".into()),
            18486 => AuthError::Blocked("locked by lockout policy".into()),
            18487 => AuthError::Blocked("password expired, must change".into()),
            code => AuthError::Protocol(format!("{code}: {}", se.message())),
        },
        _ => AuthError::Network(e.to_string()),
    }
}

async fn connect_db(target: &Target, cred: &Credential, db: &str) -> Result<Conn, AuthError> {
    let mut config = Config::new();
    config.host(&target.host);
    config.port(target.port);
    config.database(db);
    config.authentication(AuthMethod::sql_server(&cred.username, &cred.password));
    config.trust_cert(); // lab + most internal servers use self-signed certs

    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .map_err(|e| AuthError::Network(e.to_string()))?;
    let _ = tcp.set_nodelay(true);

    let client = Client::connect(config, tcp.compat_write())
        .await
        .map_err(|e| classify(&e))?;
    Ok(Arc::new(Mutex::new(client)))
}

/// Generic text conversion for any cell. NULL renders as "NULL";
/// exotic types (datetime, decimal) fall through to <unsupported> for now.
pub(crate) fn cell_to_string(row: &Row, i: usize) -> String {
    macro_rules! try_ty {
        ($t:ty, $fmt:expr) => {
            if let Ok(v) = row.try_get::<$t, _>(i) {
                return match v {
                    Some(x) => $fmt(x),
                    None => "NULL".to_string(),
                };
            }
        };
    }
    try_ty!(&str, |s: &str| s.to_string());
    try_ty!(bool, |v: bool| v.to_string());
    try_ty!(u8, |v: u8| v.to_string());
    try_ty!(i16, |v: i16| v.to_string());
    try_ty!(i32, |v: i32| v.to_string());
    try_ty!(i64, |v: i64| v.to_string());
    try_ty!(f32, |v: f32| v.to_string());
    try_ty!(f64, |v: f64| v.to_string());
    "<unsupported>".to_string()
}

pub(crate) async fn query_text(conn: &Conn, sql: &str) -> Result<Vec<Vec<String>>, AuthError> {
    let mut c = conn.lock().await;
    let mut stream = c.simple_query(sql).await.map_err(|e| classify(&e))?;
    let mut out = Vec::new();
    while let Ok(Some(item)) = stream.try_next().await {
        if let QueryItem::Row(row) = item {
            out.push((0..row.len()).map(|i| cell_to_string(&row, i)).collect());
        }
    }
    Ok(out)
}

#[async_trait]
impl Protocol for MssqlProtocol {
    fn name(&self) -> &'static str {
        "MSSQL"
    }
    fn default_port(&self) -> u16 {
        1433
    }

    /// Bogus-login probe: a 18456 back proves a live SQL Server.
    /// (The TDS pre-login response carries the real version token; tiberius
    /// hides it — version comes post-auth via @@VERSION, M3 polish.)
    async fn fingerprint(&self, target: &Target) -> Result<Fingerprint, AuthError> {
        let bogus = Credential {
            username: "dbx_probe".into(),
            password: "dbx_probe".into(),
        };
        match connect_db(target, &bogus, "master").await {
            Err(AuthError::InvalidCredentials) => Ok(Fingerprint {
                version: "Microsoft SQL Server (pre-auth)".into(),
                detail: None,
            }),
            Err(AuthError::Blocked(r)) => Ok(Fingerprint {
                version: "Microsoft SQL Server (pre-auth)".into(),
                detail: Some(r),
            }),
            Err(e) => Err(e),
            Ok(_) => Ok(Fingerprint {
                version: "Microsoft SQL Server".into(),
                detail: Some("probe login exists?!".into()),
            }),
        }
    }

    async fn authenticate(&self, target: &Target, cred: &Credential) -> AuthResult {
        self.authenticate_db(target, cred, "master").await
    }

    async fn authenticate_db(&self, target: &Target, cred: &Credential, db: &str) -> AuthResult {
        match connect_db(target, cred, db).await {
            Ok(conn) => AuthResult::Success(Box::new(MssqlSession {
                target: target.clone(),
                cred: cred.clone(),
                dbname: db.to_string(),
                client: conn,
            })),
            Err(e) => AuthResult::Failed(e),
        }
    }

    fn module_catalog(&self) -> Vec<ModuleMeta> {
        modules::catalog()
    }
}

struct MssqlSession {
    target: Target,
    cred: Credential,
    dbname: String,
    client: Conn,
}

/// "dbo.Users" -> [dbo].[Users] — identifier injection guard.
fn quote_bracket(name: &str) -> String {
    name.split('.')
        .map(|part| format!("[{}]", part.replace(']', "]]")))
        .collect::<Vec<_>>()
        .join(".")
}

#[async_trait]
impl Session for MssqlSession {
    async fn privilege(&self) -> Result<Privilege, AuthError> {
        let rows = query_text(&self.client, "SELECT IS_SRVROLEMEMBER('sysadmin')").await?;
        let is_admin = rows
            .first()
            .and_then(|r| r.first())
            .map(|s| s == "1")
            .unwrap_or(false);
        Ok(if is_admin {
            Privilege::Admin
        } else {
            Privilege::User
        })
    }

    async fn enum_databases(&self) -> Result<Vec<String>, AuthError> {
        let rows = query_text(&self.client, "SELECT name FROM sys.databases ORDER BY name").await?;
        Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect())
    }

    async fn query_rows(&self, sql: &str) -> Result<Vec<Vec<String>>, AuthError> {
        query_text(&self.client, sql).await
    }

    fn db_name(&self) -> Option<String> {
        Some(self.dbname.clone())
    }

    async fn enum_tables(&self) -> Result<Vec<String>, AuthError> {
        let rows = query_text(
            &self.client,
            "SELECT TABLE_SCHEMA + '.' + TABLE_NAME FROM INFORMATION_SCHEMA.TABLES
             WHERE TABLE_TYPE = 'BASE TABLE' ORDER BY 1",
        )
        .await?;
        Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect())
    }

    async fn dump_table(&self, table: &str, limit: Option<u64>) -> Result<Dump, AuthError> {
        let q = quote_bracket(table);
        let sql = match limit {
            Some(n) => format!("SELECT TOP {n} * FROM {q}"),
            None => format!("SELECT * FROM {q}"),
        };
        let mut c = self.client.lock().await;
        let mut stream = c.query(&sql, &[]).await.map_err(|e| classify(&e))?;
        let columns = stream
            .columns()
            .await
            .map_err(|e| classify(&e))?
            .map(|cols| cols.iter().map(|c| c.name().to_string()).collect::<Vec<_>>())
            .unwrap_or_default();
        let mut rows = Vec::new();
        while let Ok(Some(item)) = stream.try_next().await {
            if let QueryItem::Row(row) = item {
                rows.push((0..row.len()).map(|i| cell_to_string(&row, i)).collect());
            }
        }
        Ok(Dump { columns, rows })
    }

    async fn session_for_db(&self, db: &str) -> Result<Box<dyn Session>, AuthError> {
        let conn = connect_db(&self.target, &self.cred, db).await?;
        Ok(Box::new(MssqlSession {
            target: self.target.clone(),
            cred: self.cred.clone(),
            dbname: db.to_string(),
            client: conn,
        }))
    }

    fn module(&self, name: &str) -> Result<Box<dyn Module>, AuthError> {
        modules::instantiate(name, self.client.clone())
    }
}
