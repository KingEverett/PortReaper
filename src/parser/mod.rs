pub mod greppable;
pub mod text;
pub mod xml;

use crate::models::{Address, Host, Port, ScanResult};
use anyhow::{anyhow, Result};

#[derive(Debug, PartialEq)]
pub enum NmapFormat {
    Xml,
    Greppable,
    Text,
}

/// Detect nmap output format by content sniffing the first ~64 bytes.
/// Per locked decision: `<?xml` or `<nmaprun` = XML, `# Nmap` or `Host:` = greppable, else text.
pub fn detect_format(content: &str) -> NmapFormat {
    let head = &content[..content.len().min(64)];
    let trimmed = head.trim_start();
    if trimmed.starts_with("<?xml") || trimmed.starts_with("<nmaprun") {
        NmapFormat::Xml
    } else if trimmed.starts_with("# Nmap") || trimmed.starts_with("Host:") {
        NmapFormat::Greppable
    } else {
        NmapFormat::Text
    }
}

/// Parse a single nmap output string, auto-detecting format.
/// Returns error for non-nmap content (clear, actionable message per locked decision).
pub fn parse(content: &str, source: &str) -> Result<ScanResult> {
    let format = detect_format(content);
    let result = match format {
        NmapFormat::Xml => xml::parse_xml(content, source)?,
        NmapFormat::Greppable => greppable::parse_greppable(content, source)?,
        NmapFormat::Text => text::parse_text(content, source)?,
    };

    // If no hosts found for text/greppable, warn (XML would have already errored on invalid XML)
    if result.hosts.is_empty() {
        eprintln!(
            "warning: no hosts found in {} -- is this a valid nmap output file?",
            source
        );
    }

    Ok(result)
}

/// Merge multiple ScanResults into one, combining hosts by IP address.
/// Per locked decision: merge duplicate hosts by IP across multiple files -- union of all discovered ports/services.
pub fn parse_and_merge(inputs: Vec<(String, String)>) -> Result<ScanResult> {
    use std::collections::HashMap;

    let mut host_map: HashMap<String, Host> = HashMap::new();
    let mut sources: Vec<String> = Vec::new();

    for (source, content) in &inputs {
        sources.push(source.clone());
        match parse(content, source) {
            Ok(result) => {
                for host in result.hosts {
                    host_map
                        .entry(host.ip.clone())
                        .and_modify(|existing| merge_host(existing, &host))
                        .or_insert(host);
                }
            }
            Err(e) => {
                eprintln!("warning: failed to parse {}: {}", source, e);
            }
        }
    }

    let combined_source = sources.join(", ");
    Ok(ScanResult {
        source: combined_source,
        hosts: host_map.into_values().collect(),
    })
}

/// Merge ports from `other` into `existing`, avoiding duplicate port_id+protocol combos.
fn merge_host(existing: &mut Host, other: &Host) {
    // Union of hostnames
    for hn in &other.hostnames {
        if !existing.hostnames.contains(hn) {
            existing.hostnames.push(hn.clone());
        }
    }
    // Union of addresses
    for addr in &other.addresses {
        if !existing
            .addresses
            .iter()
            .any(|a| a.addr == addr.addr && a.addr_type == addr.addr_type)
        {
            existing.addresses.push(addr.clone());
        }
    }
    // Union of ports (by port_id + protocol)
    for port in &other.ports {
        if !existing
            .ports
            .iter()
            .any(|p| p.port_id == port.port_id && p.protocol == port.protocol)
        {
            existing.ports.push(port.clone());
        }
    }
    // Union of OS matches
    for os in &other.os_matches {
        if !existing.os_matches.contains(os) {
            existing.os_matches.push(os.clone());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models;

    // --- detect_format tests ---

    #[test]
    fn detect_xml_from_xml_declaration() {
        assert_eq!(detect_format("<?xml version=\"1.0\"?><nmaprun>"), NmapFormat::Xml);
    }

    #[test]
    fn detect_xml_from_nmaprun_tag() {
        assert_eq!(detect_format("<nmaprun scanner=\"nmap\">"), NmapFormat::Xml);
    }

    #[test]
    fn detect_greppable_from_hash_nmap() {
        assert_eq!(
            detect_format("# Nmap 7.94 scan initiated ..."),
            NmapFormat::Greppable
        );
    }

    #[test]
    fn detect_greppable_from_host_prefix() {
        assert_eq!(detect_format("Host: 192.168.1.1 ()\tStatus: Up"), NmapFormat::Greppable);
    }

    #[test]
    fn detect_text_from_starting_nmap() {
        assert_eq!(
            detect_format("Starting Nmap 7.94 ( https://nmap.org ) at 2024-03-10"),
            NmapFormat::Text
        );
    }

    #[test]
    fn detect_text_as_default_for_unknown_content() {
        assert_eq!(detect_format("random content not nmap"), NmapFormat::Text);
    }

    // --- parse dispatch tests ---

    #[test]
    fn parse_dispatches_xml_format() {
        let xml_content = include_str!("../../tests/fixtures/scan_basic.xml");
        let result = parse(xml_content, "scan_basic.xml").expect("parse failed");
        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ip, "192.168.1.1");
    }

    #[test]
    fn parse_dispatches_greppable_format() {
        let grep_content = include_str!("../../tests/fixtures/scan_basic.grep");
        let result = parse(grep_content, "scan_basic.grep").expect("parse failed");
        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ip, "192.168.1.1");
    }

    #[test]
    fn parse_dispatches_text_format() {
        let txt_content = include_str!("../../tests/fixtures/scan_basic.txt");
        let result = parse(txt_content, "scan_basic.txt").expect("parse failed");
        assert_eq!(result.hosts.len(), 1);
        assert_eq!(result.hosts[0].ip, "192.168.1.1");
    }

    #[test]
    fn parse_non_nmap_returns_ok_with_warning() {
        // Non-nmap content won't fail -- it just produces 0 hosts with warning to stderr
        let result = parse("This is just random text.\nNo nmap here.", "not_nmap.txt");
        assert!(result.is_ok());
        let r = result.unwrap();
        assert_eq!(r.hosts.len(), 0);
    }

    // --- merge tests ---

    fn make_host(ip: &str, port_ids: &[u16]) -> models::Host {
        models::Host {
            ip: ip.to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![models::Address {
                addr: ip.to_string(),
                addr_type: "ipv4".to_string(),
            }],
            ports: port_ids
                .iter()
                .map(|&id| models::Port {
                    port_id: id,
                    protocol: "tcp".to_string(),
                    state: "open".to_string(),
                    service: None,
                    vulnerabilities: vec![],
                    exploits: vec![],
                })
                .collect(),
            os_matches: vec![],
        }
    }

    #[test]
    fn merge_same_ip_produces_union_of_ports() {
        let host_a = make_host("192.168.1.1", &[22, 80]);
        let host_b = make_host("192.168.1.1", &[80, 443]);

        let xml_a = include_str!("../../tests/fixtures/scan_basic.xml");
        let xml_b = include_str!("../../tests/fixtures/scan_multi_host.xml");

        // Use parse_and_merge with two XML files that share 192.168.1.1
        let result = parse_and_merge(vec![
            ("scan_basic.xml".to_string(), xml_a.to_string()),
            ("scan_multi_host.xml".to_string(), xml_b.to_string()),
        ])
        .expect("merge failed");

        // 192.168.1.1 appears in both files -- should be merged (not duplicated)
        let count_191 = result.hosts.iter().filter(|h| h.ip == "192.168.1.1").count();
        assert_eq!(count_191, 1, "expected 1 merged entry for 192.168.1.1, got {}", count_191);

        let host = result.hosts.iter().find(|h| h.ip == "192.168.1.1").unwrap();
        // scan_basic.xml has ports 22, 80, 443; scan_multi_host.xml has port 22 for .1
        // All should be present (union)
        let port_ids: Vec<u16> = host.ports.iter().map(|p| p.port_id).collect();
        assert!(port_ids.contains(&22), "port 22 missing after merge");
        assert!(port_ids.contains(&80), "port 80 missing after merge");
        assert!(port_ids.contains(&443), "port 443 missing after merge");
    }

    #[test]
    fn merge_different_ips_stay_separate() {
        let xml_multi = include_str!("../../tests/fixtures/scan_multi_host.xml");
        let result = parse_and_merge(vec![
            ("scan_multi_host.xml".to_string(), xml_multi.to_string()),
        ])
        .expect("merge failed");

        // scan_multi_host.xml has 3 distinct IPs
        assert_eq!(result.hosts.len(), 3);
    }
}
