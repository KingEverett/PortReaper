use std::sync::LazyLock;
use regex::Regex;
use anyhow::Result;
use crate::models;

/// Matches "Nmap scan report for hostname (ip)" or "Nmap scan report for ip"
static HOST_HEADER: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Nmap scan report for (?:(\S+) \()?(\d+\.\d+\.\d+\.\d+)\)?").unwrap()
});

/// Matches port lines: "22/tcp   open  ssh      OpenSSH 8.9p1"
static PORT_LINE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^(\d+)/(\w+)\s+(open|filtered|closed)\s+(\S+)(?:\s+(.+))?$").unwrap()
});

/// Parse nmap default text output into a normalized ScanResult.
pub fn parse_text(content: &str, source: &str) -> Result<models::ScanResult> {
    let mut hosts: Vec<models::Host> = Vec::new();

    // Split by host headers
    let mut current_ip: Option<String> = None;
    let mut current_hostname: Option<String> = None;
    let mut current_ports: Vec<models::Port> = Vec::new();

    for line in content.lines() {
        let line = line.trim();

        if let Some(caps) = HOST_HEADER.captures(line) {
            // Save previous host if any
            if let Some(ip) = current_ip.take() {
                hosts.push(build_host(ip, current_hostname.take(), current_ports.drain(..).collect()));
            }
            // group 1 = optional hostname, group 2 = IP
            current_hostname = caps.get(1).map(|m| m.as_str().to_string());
            current_ip = Some(caps[2].to_string());
            current_ports.clear();
            continue;
        }

        if current_ip.is_none() {
            continue;
        }

        if let Some(caps) = PORT_LINE.captures(line) {
            let port_id: u16 = caps[1].parse().unwrap_or(0);
            let protocol = caps[2].to_string();
            let state = caps[3].to_string();
            let svc_name = caps[4].to_string();
            let version_str = caps.get(5).map(|m| m.as_str().trim().to_string());

            let service = Some(models::Service {
                name: svc_name,
                // Text format stores version info as a combined string in product
                product: version_str.filter(|v| !v.is_empty()),
                version: None,
                extra_info: None,
                tunnel: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec![],
            });

            current_ports.push(models::Port {
                port_id,
                protocol,
                state,
                service,
                vulnerabilities: vec![],
            });
        }
        // Non-matching lines are silently skipped (lenient parsing per locked decision)
    }

    // Save last host
    if let Some(ip) = current_ip.take() {
        hosts.push(build_host(ip, current_hostname.take(), current_ports.drain(..).collect()));
    }

    Ok(models::ScanResult {
        source: source.to_string(),
        hosts,
    })
}

fn build_host(ip: String, hostname: Option<String>, ports: Vec<models::Port>) -> models::Host {
    let hostnames = hostname.into_iter().collect();
    let ip_addr = ip.clone();
    models::Host {
        ip: ip_addr,
        hostnames,
        status: "up".to_string(),
        addresses: vec![models::Address {
            addr: ip,
            addr_type: "ipv4".to_string(),
        }],
        ports,
        os_matches: vec![],
    }
}
