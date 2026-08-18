use colored::Colorize;

fn prefix(proto: &str, host: &str, port: u16) -> String {
    format!("{:<9} {:<16} {:<6}", proto.bold(), host, port)
}

/// [+] valid credential — (Pwn3d!) highlighted when privileged
pub fn success(proto: &str, host: &str, port: u16, creds: &str, pwned: bool) {
    let tag = "[+]".green().bold();
    if pwned {
        println!(
            "{}{} {} {}",
            prefix(proto, host, port),
            tag,
            creds.green().bold(),
            "(Pwn3d!)".black().on_yellow().bold()
        );
    } else {
        println!("{}{} {}", prefix(proto, host, port), tag, creds.green());
    }
}

/// [-] failed auth (suppressed by --only-success / --only-pwned / -q)
pub fn failure(proto: &str, host: &str, port: u16, creds: &str, reason: &str) {
    println!(
        "{}{} {} {}",
        prefix(proto, host, port),
        "[-]".red(),
        creds.red(),
        format!("({reason})").dimmed()
    );
}

/// [*] fingerprints, enumerated dbs, general info
pub fn info(proto: &str, host: &str, port: u16, msg: &str) {
    println!("{}{} {}", prefix(proto, host, port), "[*]".cyan(), msg);
}

/// [M] module output (check/run results)
pub fn module(proto: &str, host: &str, port: u16, name: &str, msg: &str) {
    println!(
        "{}{} {}",
        prefix(proto, host, port),
        "[M]".magenta().bold(),
        format!("{name}: {msg}")
    );
}
