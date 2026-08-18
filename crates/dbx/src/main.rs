mod engine;
mod input;
mod loot;
mod output;

use clap::{Args, Parser, Subcommand};
use colored::Colorize;
use dbx_core::{Credential, ModuleOptions, Opsec, Protocol};
use dbx_mysql::MysqlProtocol;
use std::path::PathBuf;
use std::sync::Arc;

const BANNER: &str = r#"     _ _
  __| | |____  __
 / _` | '_ \ \/ /
| (_| | |_) |>  <
 \__,_|_.__//_/\_\
"#;

const HELP_TEMPLATE: &str = "\
{before-help}
{usage-heading} {usage}

{about}

{all-args}
{after-help}";

// clap doesn't style after_help, so ANSI codes are embedded by hand.
const FOOTER: &str = concat!(
    "\x1b[1;32mBuilt by 0xS0B\x1b[0m\n",
    "\x1b[33mCodename:\x1b[0m \x1b[1;33mFirst Contact\x1b[0m\n",
    "\x1b[36mProtocols under active development:\x1b[0m \x1b[1mredis\x1b[0m",
);

/// Flags dbx itself owns. Any other --flag is treated as a module option:
///   --atk-ip 10.0.0.5  =>  -o ATK_IP=10.0.0.5
///   --xp-reconfig      =>  -o RECONFIG=true      (bare flag => boolean)
const KNOWN_FLAGS: &[&str] = &[
    "--threads", "--timeout", "--jitter",
    "--only-success", "--only-pwned", "--quiet", "--verbose",
    "--no-progress", "--log", "--loot-db",
    "--username", "--password", "--dbs", "--db", "--tables", "--skip-system",
    "--verify", "--list-modules", "--module", "--module-opt", "--check", "--force",
    "--thief", "--thief-all", "--thief-limit",
    "--help", "--version",
];

/// Rewrite unknown --flags into -o KEY=VALUE so modules get nxc-style
/// custom flags without clap knowing them ahead of time.
/// Caveat: a typo'd dbx flag (--verbse) becomes a module option silently.
fn preprocess_module_flags(argv: Vec<String>) -> Vec<String> {
    let mut out = Vec::with_capacity(argv.len() + 4);
    let mut i = 0;
    while i < argv.len() {
        let tok = &argv[i];
        if tok.starts_with("--") && !KNOWN_FLAGS.contains(&tok.as_str()) {
            let key = tok.trim_start_matches('-').to_uppercase().replace('-', "_");
            if i + 1 < argv.len() && !argv[i + 1].starts_with('-') {
                out.push("-o".to_string());
                out.push(format!("{}={}", key, argv[i + 1]));
                i += 2;
            } else {
                // bare flag => boolean module option
                out.push("-o".to_string());
                out.push(format!("{key}=true"));
                i += 1;
            }
        } else {
            out.push(tok.clone());
            i += 1;
        }
    }
    out
}

/// Parse --jitter "MIN-MAX" (ms). A bare number means a fixed delay.
fn parse_jitter(s: &str) -> anyhow::Result<(u64, u64)> {
    let (lo, hi) = match s.split_once('-') {
        Some((a, b)) => (a.trim().parse::<u64>(), b.trim().parse::<u64>()),
        None => {
            let v = s.trim().parse::<u64>();
            (v.clone(), v)
        }
    };
    let (lo, hi) = match (lo, hi) {
        (Ok(lo), Ok(hi)) => (lo, hi),
        _ => anyhow::bail!("bad --jitter '{s}' (use MIN-MAX in ms, e.g. 200-1500)"),
    };
    if lo > hi {
        anyhow::bail!("bad --jitter '{s}' (MIN must be <= MAX)");
    }
    Ok((lo, hi))
}

#[derive(Parser)]
#[command(
    name = "dbx",
    version,
    before_help = BANNER,
    about = "The database execution tool — credential spraying, enumeration and verified post-exploitation for database engines.",
    after_help = FOOTER,
    help_template = HELP_TEMPLATE,
    arg_required_else_help = true,
)]
struct Cli {
    #[command(subcommand)]
    command: Command,

    #[command(flatten)]
    global: GlobalOpts,
}

/// Global options — usable before OR after the subcommand (like nxc).
#[derive(Args, Clone)]
struct GlobalOpts {
    /// Concurrent authentications
    #[arg(short = 't', long, default_value_t = 100, global = true, help_heading = "Generic Options")]
    threads: usize,

    /// Hard timeout in seconds per authentication attempt
    #[arg(long, default_value_t = 10, global = true, help_heading = "Generic Options")]
    timeout: u64,

    /// Random delay in ms between auths against the same target (e.g. 200-1500)
    #[arg(long, value_name = "MIN-MAX", global = true, help_heading = "Generic Options")]
    jitter: Option<String>,

    /// Hide [-] failures; show fingerprints, hits and the tally
    #[arg(long, global = true, help_heading = "Output Options")]
    only_success: bool,

    /// Print only privileged (Pwn3d!) hits
    #[arg(long, global = true, help_heading = "Output Options")]
    only_pwned: bool,

    /// Successes only, nothing else — pure grep output
    #[arg(short = 'q', long, global = true, help_heading = "Output Options")]
    quiet: bool,

    /// Verbose: error codes, retries, backoff notices
    #[arg(short = 'v', long, global = true, help_heading = "Output Options")]
    verbose: bool,

    /// Do not display the progress bar during sprays
    #[arg(long, global = true, help_heading = "Output Options")]
    no_progress: bool,

    /// Export results to a log file
    #[arg(long, value_name = "FILE", global = true, help_heading = "Output Options")]
    log: Option<PathBuf>,

    /// Loot database location [default: ~/.dbx/loot.db]
    #[arg(long, value_name = "PATH", global = true, help_heading = "Output Options")]
    loot_db: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Command {
    /// Own stuff using PostgreSQL
    #[command(visible_alias = "postgres")]
    Pg(Common),

    /// Own stuff using MSSQL
    Mssql(Common),

    /// Own stuff using Mysql
    #[command(alias = "mariadb")]
    Mysql(Common),

    /// Review captured loot
    Loot(LootArgs),
}

#[derive(Args)]
struct LootArgs {
    /// What to show
    #[arg(value_parser = ["creds"])]
    what: String,

    /// Filter by protocol (e.g. pgsql)
    #[arg(long)]
    protocol: Option<String>,
}

#[derive(Args)]
struct Common {
    /// Targets: IPs, CIDRs, ranges (10.0.0.1-50), host:port, or files of targets
    #[arg(required_unless_present = "list_modules", value_name = "TARGET")]
    targets: Vec<String>,

    /// Username(s) or file(s) of usernames
    #[arg(short = 'u', long, required_unless_present = "list_modules", value_name = "USER|FILE")]
    username: Vec<String>,

    /// Password(s) or file(s) of passwords — default: try empty password
    #[arg(short = 'p', long, value_name = "PASS|FILE")]
    password: Vec<String>,

    /// Authenticate into this database instead of the default
    #[arg(long, value_name = "DB")]
    db: Option<String>,

    /// List databases on every successful auth
    #[arg(long)]
    dbs: bool,

    /// List tables — of --db if given, otherwise of every database
    #[arg(long)]
    tables: bool,

    /// Skip system databases in --dbs/--tables walks and --thief-all
    #[arg(long)]
    skip_system: bool,

    /// Fingerprint each target before spraying; skip targets that don't
    /// answer like this protocol (sends one bogus-auth probe per target)
    #[arg(long)]
    verify: bool,

    /// List available modules for this protocol
    #[arg(short = 'L', long)]
    list_modules: bool,

    /// Module to run on successful auth (see -L)
    #[arg(short = 'M', long, value_name = "NAME")]
    module: Option<String>,

    /// Module option, KEY=VALUE (repeatable). Custom --flags work too:
    /// --atk-ip 1.2.3.4  |  --xp-reconfig on  |  --bare-flag (=true)
    #[arg(short = 'o', long = "module-opt", value_name = "KEY=VALUE")]
    module_opts: Vec<String>,

    /// Verify the module's primitive only — never execute
    #[arg(long)]
    check: bool,

    /// Skip safety gates (required for RED opsec modules)
    #[arg(long)]
    force: bool,

    /// Dump table(s) to CSV on this machine (comma-separated or repeatable)
    #[arg(long, value_name = "TABLE")]
    thief: Vec<String>,

    /// Dump every table of every database to CSV
    #[arg(long)]
    thief_all: bool,

    /// Max rows per table for --thief (0 = unlimited)
    #[arg(long, default_value_t = 10000)]
    thief_limit: u64,
}

fn print_module_catalog(proto: &dyn Protocol) {
    for m in proto.module_catalog() {
        let opsec = match m.opsec {
            Opsec::Green => "GREEN".green(),
            Opsec::Amber => "AMBER".yellow(),
            Opsec::Red => "RED".red().bold(),
        };
        println!("  {} [{}]", m.name.bold(), opsec);
        println!("      {}", m.description);
        for o in m.options {
            let reqd = if o.required { " (required)" } else { "" };
            println!(
                "        --{} {reqd} — {}",
                o.name.to_lowercase().replace('_', "-"),
                o.description
            );
        }
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let argv: Vec<String> = std::env::args().collect();
    let cli = Cli::parse_from(preprocess_module_flags(argv));

    // tiberius logs token errors (failed logins!) at ERROR — we classify
    // those ourselves, so mute the library unless -v is on.
    let filter = if cli.global.verbose {
        "debug"
    } else {
        "warn,tiberius=off"
    };
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::new(filter))
        .init();

    let loot_path = cli
        .global
        .loot_db
        .clone()
        .unwrap_or_else(loot::Loot::default_path);

    // ---- loot review mode: no engine, just the store ----
    if let Command::Loot(largs) = &cli.command {
        let store = loot::Loot::open(&loot_path)?;
        let proto_filter = largs.protocol.as_ref().map(|p| p.to_uppercase());
        let creds = store.credentials(proto_filter.as_deref())?;
        if creds.is_empty() {
            println!("No loot yet — go get some.");
            return Ok(());
        }
        for c in &creds {
            output::success(
                &c.protocol,
                &c.host,
                c.port,
                &format!("{}:{}", c.username, c.password),
                c.privileged,
            );
        }
        println!("{} credential(s) in loot", creds.len());
        return Ok(());
    }

    let (proto, args): (Arc<dyn Protocol>, &Common) = match &cli.command {
        Command::Pg(c) => (Arc::new(dbx_pg::PgProtocol), c),
        Command::Mssql(c) => (Arc::new(dbx_mssql::MssqlProtocol), c),
        Command::Mysql(c) => (Arc::new(MysqlProtocol), c),
        Command::Loot(_) => unreachable!(),
    };

    // ---- -L: static catalog, no targets needed ----
    if args.list_modules {
        println!("{} modules:", proto.name());
        print_module_catalog(&*proto);
        return Ok(());
    }

    // ---- --jitter: parse once, fail fast on a bad range ----
    let jitter: Option<(u64, u64)> = match &cli.global.jitter {
        Some(s) => Some(parse_jitter(s)?),
        None => None,
    };

    // ---- expand inputs: existing file => line list, else literal ----
    let users = input::expand_values(&args.username)?;
    let passwords = if args.password.is_empty() {
        vec![String::new()]
    } else {
        input::expand_values(&args.password)?
    };

    // cross-product pairing (nxc default; --no-bruteforce comes later)
    let mut creds = Vec::with_capacity(users.len() * passwords.len());
    for u in &users {
        for p in &passwords {
            creds.push(Credential {
                username: u.clone(),
                password: p.clone(),
            });
        }
    }

    let raw_targets = input::expand_targets(&args.targets)?;
    let mut targets = Vec::with_capacity(raw_targets.len());
    for t in raw_targets {
        match t.rsplit_once(':') {
            Some((h, p)) => match p.parse::<u16>() {
                Ok(port) => targets.push((h.to_string(), port)),
                Err(_) => targets.push((t.clone(), proto.default_port())),
            },
            None => targets.push((t, proto.default_port())),
        }
    }

    // module options: -o KEY=VALUE (keys normalized to UPPER_SNAKE)
    let mut module_opts = ModuleOptions::new();
    for kv in &args.module_opts {
        match kv.split_once('=') {
            Some((k, v)) => {
                module_opts.insert(k.to_uppercase().replace('-', "_"), v.to_string());
            }
            None => anyhow::bail!("bad module option '{kv}' (expected KEY=VALUE)"),
        }
    }
    if args.module.is_none() && !module_opts.is_empty() {
        eprintln!("[!] module options given but no -M module selected — ignoring them");
    }

    // --thief accepts comma-separated and repeatable
    let thief: Vec<String> = args
        .thief
        .iter()
        .flat_map(|t| t.split(','))
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    eprintln!(
        "[*] {} target(s) x {} credential(s) = {} auth attempt(s) planned",
        targets.len(),
        creds.len(),
        targets.len() * creds.len()
    );

    let store = loot::Loot::open(&loot_path)?;
    let loot_dir = loot_path
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|| PathBuf::from("."));

    engine::run(
        proto,
        targets,
        creds,
        engine::EngineOpts {
            threads: cli.global.threads,
            no_progress: cli.global.no_progress || cli.global.quiet,
            verify: args.verify,
            timeout: cli.global.timeout,
            jitter,
            dbs: args.dbs,
            tables: args.tables,
            skip_system: args.skip_system,
            show_failures: !cli.global.only_success
                && !cli.global.only_pwned
                && !cli.global.quiet,
            only_pwned: cli.global.only_pwned,
            loot: Some(store),
            db: args.db.clone(),
            module: args.module.clone(),
            module_opts,
            check_only: args.check,
            force: args.force,
            thief,
            thief_all: args.thief_all,
            thief_limit: if args.thief_limit == 0 { None } else { Some(args.thief_limit) },
            loot_dir,
        },
    )
    .await
}
