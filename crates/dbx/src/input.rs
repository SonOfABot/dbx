use anyhow::Context;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::path::Path;

/// Usernames/passwords: literal or file of lines.
pub fn expand_values(inputs: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for input in inputs {
        let path = Path::new(input);
        if path.is_file() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading {input}"))?;
            let content = String::from_utf8_lossy(&bytes);
            out.extend(
                content
                    .lines()
                    .map(|l| l.trim_end_matches('\r'))
                    .filter(|l| !l.is_empty())
                    .map(str::to_string),
            );
        } else {
            out.push(input.clone());
        }
    }
    Ok(dedup(out))
}

/// Targets: literal, file of targets, CIDR, or range.
pub fn expand_targets(inputs: &[String]) -> anyhow::Result<Vec<String>> {
    let mut out = Vec::new();
    for input in inputs {
        let path = Path::new(input);
        if path.is_file() {
            let bytes = std::fs::read(path)
                .with_context(|| format!("reading {input}"))?;
            let content = String::from_utf8_lossy(&bytes);
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                out.extend(expand_one_target(line)?);
            }
        } else {
            out.extend(expand_one_target(input)?);
        }
    }
    Ok(dedup(out))
}

fn expand_one_target(s: &str) -> anyhow::Result<Vec<String>> {
    // CIDR with explicit port: 10.0.0.0/24:5433
    if let Some((host_part, port)) = s.rsplit_once(':') {
        if host_part.contains('/') {
            let nets = expand_cidr(host_part)?;
            return Ok(nets.into_iter().map(|h| format!("{h}:{port}")).collect());
        }
    }
    if s.contains('/') {
        expand_cidr(s)
    } else if s.contains('-') && !s.starts_with('-') {
        expand_range(s)
    } else {
        Ok(vec![s.to_string()])
    }
}

fn expand_cidr(s: &str) -> anyhow::Result<Vec<String>> {
    let net: ipnet::Ipv4Net = s.parse().with_context(|| format!("bad CIDR: {s}"))?;
    let hosts: Vec<String> = net.hosts().map(|ip| ip.to_string()).collect();
    // /32 and /31 yield no "hosts" — keep the address itself
    if hosts.is_empty() {
        Ok(vec![net.addr().to_string()])
    } else {
        Ok(hosts)
    }
}

/// 10.0.0.10-20  or  10.0.0.10-10.0.0.20
fn expand_range(s: &str) -> anyhow::Result<Vec<String>> {
    let (start, end) = s.split_once('-').unwrap();
    let start: Ipv4Addr = start.parse().with_context(|| format!("bad range start: {s}"))?;
    let end: Ipv4Addr = if end.contains('.') {
        end.parse().with_context(|| format!("bad range end: {s}"))?
    } else {
        let last: u8 = end.parse().with_context(|| format!("bad range end: {s}"))?;
        let mut o = start.octets();
        o[3] = last;
        Ipv4Addr::from(o)
    };
    let (a, b) = (u32::from(start), u32::from(end));
    anyhow::ensure!(b >= a, "range end before start: {s}");
    anyhow::ensure!(b - a <= 1 << 16, "range too large (max 65536 hosts): {s}");
    Ok((a..=b).map(Ipv4Addr::from).map(|ip| ip.to_string()).collect())
}

fn dedup(items: Vec<String>) -> Vec<String> {
    let mut seen = HashSet::new();
    let mut out = Vec::with_capacity(items.len());
    for i in items {
        if seen.insert(i.clone()) {
            out.push(i);
        }
    }
    out
}
