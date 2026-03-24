use std::sync::LazyLock;
use std::collections::HashMap;
use regex::Regex;
use anyhow::Result;
use crate::models;

/// Matches "Host: IP (hostname)" lines
static HOST_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Host:\s+(\S+)\s+\(([^)]*)\)").unwrap()
});

/// Matches individual port entries in the Ports field
/// portnum/state/protocol//service//version/
static PORTS_RE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"(\d+)/(open|filtered|closed)/(\w+)//([^/]*)//([^/,]*)").unwrap()
});

/// Parse nmap greppable (-oG) output into a normalized ScanResult.
pub fn parse_greppable(content: &str, source: &str) -> Result<models::ScanResult> {
    // Collect data per IP: (hostname, ports)
    let mut host_map: HashMap<String, (String, Vec<models::Port>)> = HashMap::new();

    for line in content.lines() {
        let line = line.trim();

        // Skip comments
        if line.starts_with('#') {
            continue;
        }

        // Extract IP and hostname from this line
        let ip_and_hostname = HOST_RE.captures(line).map(|caps| {
            let ip = caps[1].to_string();
            let hostname = caps[2].to_string();
            (ip, hostname)
        });

        let (ip, hostname) = match ip_and_hostname {
            Some(v) => v,
            None => continue,
        };

        // Parse ports if present in this line
        let ports = if line.contains("Ports:") {
            extract_ports(line)
        } else {
            vec![]
        };

        // Merge into host map
        let entry = host_map.entry(ip.clone()).or_insert_with(|| (hostname.clone(), vec![]));
        // Update hostname if current entry has empty hostname
        if entry.0.is_empty() && !hostname.is_empty() {
            entry.0 = hostname;
        }
        // Add ports (union by port_id + protocol)
        for port in ports {
            if !entry.1.iter().any(|p: &models::Port| p.port_id == port.port_id && p.protocol == port.protocol) {
                entry.1.push(port);
            }
        }
    }

    let hosts: Vec<models::Host> = host_map
        .into_iter()
        .map(|(ip, (hostname, ports))| {
            let hostnames = if hostname.is_empty() {
                vec![]
            } else {
                vec![hostname]
            };
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
        })
        .collect();

    Ok(models::ScanResult {
        source: source.to_string(),
        hosts,
    })
}

fn extract_ports(line: &str) -> Vec<models::Port> {
    // Find the "Ports: " section (between "Ports: " and next tab or end of line)
    let ports_section = match line.find("Ports:") {
        Some(idx) => {
            let after = &line[idx + "Ports:".len()..];
            let end = after.find('\t').unwrap_or(after.len());
            after[..end].trim()
        }
        None => return vec![],
    };

    PORTS_RE
        .captures_iter(ports_section)
        .map(|caps| {
            let port_id: u16 = caps[1].parse().unwrap_or(0);
            let state = caps[2].to_string();
            let protocol = caps[3].to_string();
            let svc_name = caps[4].trim().to_string();
            let version_str = caps[5].trim().to_string();

            let service = if !svc_name.is_empty() {
                Some(models::Service {
                    name: svc_name,
                    // Greppable format has version as combined string; store in product
                    product: if version_str.is_empty() { None } else { Some(version_str) },
                    version: None,
                    extra_info: None,
                    tunnel: None,
                    hostname: None,
                    os_type: None,
                    device_type: None,
                    cpe: vec![],
                })
            } else {
                None
            };

            models::Port {
                port_id,
                protocol,
                state,
                service,
                vulnerabilities: vec![],
                exploits: vec![],
            }
        })
        .collect()
}
