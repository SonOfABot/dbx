use async_trait::async_trait;
use std::collections::HashMap;

#[derive(Debug, Clone)]
pub struct Target {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub struct Credential {
    pub username: String,
    pub password: String,
}

#[derive(Debug, Clone)]
pub struct Fingerprint {
    pub version: String,
    pub detail: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Privilege {
    User,
    Admin, // -> (Pwn3d!)
}

/// Failure type drives spray strategy (design doc §3.3) — never flatten these.
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("invalid credentials")]
    InvalidCredentials,
    #[error("authentication blocked: {0}")]
    Blocked(String),
    #[error("network error: {0}")]
    Network(String),
    #[error("protocol error: {0}")]
    Protocol(String),
}

pub enum AuthResult {
    Success(Box<dyn Session>),
    Failed(AuthError),
}

// ---------- modules (design doc §3.2, §6) ----------

/// Module options: normalized UPPER_SNAKE keys, e.g. --atk-ip => ATK_IP
pub type ModuleOptions = HashMap<String, String>;

/// Green = read-only. Amber = executes / temp state, cleaned up.
/// Red = persistent artifacts — requires --force.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Opsec {
    Green,
    Amber,
    Red,
}

pub struct ModuleOpt {
    pub name: &'static str, // canonical form, e.g. "ATK_IP" (user types --atk-ip)
    pub description: &'static str,
    pub required: bool,
}

pub struct ModuleMeta {
    pub name: &'static str,
    pub description: &'static str,
    pub opsec: Opsec,
    pub options: &'static [ModuleOpt],
}

pub struct CheckResult {
    pub possible: bool,
    pub detail: String,
}

pub struct ModuleResult {
    pub lines: Vec<String>,
}

/// The verify-then-execute contract. check() must NEVER mutate state.
#[async_trait]
pub trait Module: Send + Sync {
    fn meta(&self) -> ModuleMeta;
    async fn check(&self) -> Result<CheckResult, AuthError>;
    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError>;
}

// ---------- data exfil (--thief) ----------

pub struct Dump {
    pub columns: Vec<String>,
    pub rows: Vec<Vec<String>>,
}

// ---------- traits ----------

#[async_trait]
pub trait Protocol: Send + Sync {
    fn name(&self) -> &'static str;
    fn default_port(&self) -> u16;
    async fn fingerprint(&self, target: &Target) -> Result<Fingerprint, AuthError>;
    async fn authenticate(&self, target: &Target, cred: &Credential) -> AuthResult;

    /// Auth into a specific database. Default: ignore and use the normal path.
    async fn authenticate_db(&self, target: &Target, cred: &Credential, db: &str) -> AuthResult {
        let _ = db;
        self.authenticate(target, cred).await
    }

    /// Static module catalog for -L (no session needed).
    fn module_catalog(&self) -> Vec<ModuleMeta> {
        vec![]
    }
}

#[async_trait]
pub trait Session: Send + Sync {
    async fn privilege(&self) -> Result<Privilege, AuthError>;
    async fn enum_databases(&self) -> Result<Vec<String>, AuthError>;
    async fn query_rows(&self, sql: &str) -> Result<Vec<Vec<String>>, AuthError>;

    /// Name of the database this session is connected to (for loot paths).
    fn db_name(&self) -> Option<String> {
        None
    }

    async fn enum_tables(&self) -> Result<Vec<String>, AuthError> {
        Err(AuthError::Protocol("table enumeration not supported".into()))
    }

    async fn dump_table(&self, table: &str, limit: Option<u64>) -> Result<Dump, AuthError> {
        let _ = (table, limit);
        Err(AuthError::Protocol("table dump not supported".into()))
    }

    /// Open a sibling session against another database on the same server
    /// (same creds). Powers --thief-all.
    async fn session_for_db(&self, db: &str) -> Result<Box<dyn Session>, AuthError> {
        let _ = db;
        Err(AuthError::Protocol("database hopping not supported".into()))
    }

    /// Instantiate a protocol module bound to this session.
    fn module(&self, name: &str) -> Result<Box<dyn Module>, AuthError> {
        let _ = name;
        Err(AuthError::Protocol("this protocol has no modules".into()))
    }
}
