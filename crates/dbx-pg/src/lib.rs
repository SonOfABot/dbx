mod modules;

use std::sync::Arc;
use async_trait::async_trait;
use dbx_core::*;
use std::time::Duration;
use tokio_postgres::{Client, NoTls};

pub struct PgProtocol;

/// Map driver errors onto our auth semantics. SQLSTATE codes do the work:
/// 28P01 = wrong password, 28000 = auth not allowed (e.g. pg_hba reject).
pub(crate) fn classify(e: &tokio_postgres::Error) -> AuthError {
    if let Some(db) = e.as_db_error() {
        match db.code().code() {
            "28P01" | "28000" => AuthError::InvalidCredentials,
            "53300" => AuthError::Blocked("too many connections".into()),
            code => AuthError::Protocol(format!("{code}: {}", db.message())),
        }
    } else {
        AuthError::Network(e.to_string())
    }
}

/// simple_query returns every value as text — perfect for generic dumping.
pub(crate) async fn query_text(c: &Client, sql: &str) -> Result<Vec<Vec<String>>, AuthError> {
    let msgs = c.simple_query(sql).await.map_err(|e| classify(&e))?;
    Ok(msgs
        .iter()
        .filter_map(|m| match m {
            tokio_postgres::SimpleQueryMessage::Row(r) => Some(
                (0..r.len())
                    .map(|i| r.get(i).unwrap_or("NULL").to_string())
                    .collect(),
            ),
            _ => None,
        })
        .collect())
}

async fn connect(target: &Target, cred: &Credential, dbname: &str) -> Result<Client, AuthError> {
    let mut cfg = tokio_postgres::Config::new();
    cfg.host(&target.host)
        .port(target.port)
        .user(&cred.username)
        .password(&cred.password)
        .dbname(dbname)
        .connect_timeout(Duration::from_secs(5));
    let (client, connection) = cfg.connect(NoTls).await.map_err(|e| classify(&e))?;
    tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::debug!("pg connection closed: {e}");
        }
    });
    Ok(client)
}

#[async_trait]
impl Protocol for PgProtocol {
    fn name(&self) -> &'static str {
        "PGSQL"
    }
    fn default_port(&self) -> u16 {
        5432
    }

    /// Postgres reveals almost nothing pre-auth. We confirm it's PG by
    /// provoking an auth error; version comes post-auth in the session.
    async fn fingerprint(&self, target: &Target) -> Result<Fingerprint, AuthError> {
        let bogus = Credential {
            username: "dbx_probe".into(),
            password: "dbx_probe".into(),
        };
        match connect(target, &bogus, "postgres").await {
            Err(AuthError::InvalidCredentials) => Ok(Fingerprint {
                version: "PostgreSQL (pre-auth)".into(),
                detail: None,
            }),
            Err(AuthError::Blocked(r)) => Ok(Fingerprint {
                version: "PostgreSQL (pre-auth)".into(),
                detail: Some(r),
            }),
            Err(e) => Err(e),
            Ok(_) => Ok(Fingerprint {
                version: "PostgreSQL".into(),
                detail: Some("probe user exists?!".into()),
            }),
        }
    }

    async fn authenticate(&self, target: &Target, cred: &Credential) -> AuthResult {
        self.authenticate_db(target, cred, "postgres").await
    }

    async fn authenticate_db(&self, target: &Target, cred: &Credential, db: &str) -> AuthResult {
        match connect(target, cred, db).await {
            Ok(client) => AuthResult::Success(Box::new(PgSession {
                target: target.clone(),
                cred: cred.clone(),
                dbname: db.to_string(),
                client: Arc::new(client),
            })),
            Err(e) => AuthResult::Failed(e),
        }
    }

    fn module_catalog(&self) -> Vec<ModuleMeta> {
        modules::catalog()
    }
}

struct PgSession {
    target: Target,
    cred: Credential,
    dbname: String,
    client: Arc<Client>,
}

/// "public.users" -> "public"."users" — identifier injection guard.
fn quote_qualified(name: &str) -> String {
    name.split('.')
        .map(|part| format!("\"{}\"", part.replace('"', "\"\"")))
        .collect::<Vec<_>>()
        .join(".")
}

#[async_trait]
impl Session for PgSession {
    async fn privilege(&self) -> Result<Privilege, AuthError> {
        let row = self
            .client
            .query_one(
                "SELECT usesuper FROM pg_user WHERE usename = current_user",
                &[],
            )
            .await
            .map_err(|e| classify(&e))?;
        let is_super: bool = row.get(0);
        Ok(if is_super {
            Privilege::Admin
        } else {
            Privilege::User
        })
    }

    async fn enum_databases(&self) -> Result<Vec<String>, AuthError> {
        let rows = self
            .client
            .query(
                "SELECT datname FROM pg_database WHERE datistemplate = false",
                &[],
            )
            .await
            .map_err(|e| classify(&e))?;
        Ok(rows.iter().map(|r| r.get(0)).collect())
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
            "SELECT schemaname || '.' || tablename FROM pg_tables
             WHERE schemaname NOT IN ('pg_catalog', 'information_schema')
             ORDER BY 1",
        )
        .await?;
        Ok(rows.into_iter().filter_map(|r| r.into_iter().next()).collect())
    }

    async fn dump_table(&self, table: &str, limit: Option<u64>) -> Result<Dump, AuthError> {
        let q = quote_qualified(table);
        // column names via a zero-row prepared statement (typed path)
        let stmt = self
            .client
            .prepare(&format!("SELECT * FROM {q} LIMIT 0"))
            .await
            .map_err(|e| classify(&e))?;
        let columns = stmt.columns().iter().map(|c| c.name().to_string()).collect();
        // values via simple_query (everything comes back as text)
        let sql = match limit {
            Some(n) => format!("SELECT * FROM {q} LIMIT {n}"),
            None => format!("SELECT * FROM {q}"),
        };
        let rows = query_text(&self.client, &sql).await?;
        Ok(Dump { columns, rows })
    }

    async fn session_for_db(&self, db: &str) -> Result<Box<dyn Session>, AuthError> {
        let client = connect(&self.target, &self.cred, db).await?;
        Ok(Box::new(PgSession {
            target: self.target.clone(),
            cred: self.cred.clone(),
            dbname: db.to_string(),
            client: Arc::new(client),
        }))
    }

    fn module(&self, name: &str) -> Result<Box<dyn Module>, AuthError> {
        modules::instantiate(name, self.client.clone())
    }
}
