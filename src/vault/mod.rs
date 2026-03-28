pub mod frontmatter;
pub mod graph_config;
pub mod merge;
pub mod templates;
pub mod writer;

use std::collections::HashMap;
use std::path::Path;

use crate::models::{Port, ScanResult, Severity, Vulnerability};
use crate::util::filename::sanitize_filename;

use frontmatter::{CveFrontmatter, HostFrontmatter, ServiceFrontmatter, TechFrontmatter};

/// Errors that can occur during vault generation.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("failed to write vault file {path}: {source}")]
    WriteError { path: String, source: std::io::Error },
    #[error("failed to create vault directory {path}: {source}")]
    DirError { path: String, source: std::io::Error },
    #[error("YAML serialization failed: {0}")]
    YamlError(String),
}

/// Statistics from vault generation for reporting.
pub struct VaultStats {
    pub hosts: usize,
    pub services: usize,
    pub cves: usize,
    pub technologies: usize,
}

/// Derive a scan label from the source filename.
/// Format: `{YYYY-MM-DD}_{sanitized_source}` per D-03 fallback.
/// ScanResult currently lacks nmap metadata fields so date + filename is the correct path.
pub fn derive_scan_label(source: &str) -> String {
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    let sanitized = sanitize_filename(source);
    format!("{date}_{sanitized}")
}

// ============================================================
// Accumulators for Pass 1
// ============================================================

/// Accumulates data for a shared CVE note across all services.
struct CveAccumulator {
    cve_id: String,
    score: Option<f32>,
    severity: Severity,
    cvss_version: Option<String>,
    sources: Vec<String>,
    description: Option<String>,
    affected_services: Vec<String>, // pre-built service wikilinks
    affected_hosts: Vec<String>,    // pre-built host wikilinks
}

/// Accumulates data for a technology note across all services.
struct TechAccumulator {
    product: String,
    versions_seen: Vec<String>,                    // deduplicated
    instances: Vec<(String, u16, Option<String>)>, // (ip, port, version)
    cve_ids: Vec<String>,                          // deduplicated
}

// ============================================================
// Helpers
// ============================================================

fn highest_severity(vulns: &[Vulnerability]) -> Severity {
    vulns
        .iter()
        .filter_map(|v| v.cvss.as_ref())
        .map(|c| &c.severity)
        .max_by_key(|s| match s {
            Severity::Critical => 4,
            Severity::High => 3,
            Severity::Medium => 2,
            Severity::Low => 1,
            Severity::None => 0,
        })
        .cloned()
        .unwrap_or(Severity::None)
}

fn today_string() -> String {
    chrono::Local::now().format("%Y-%m-%d").to_string()
}

fn severity_cmp(s: &Severity) -> u8 {
    match s {
        Severity::Critical => 4,
        Severity::High => 3,
        Severity::Medium => 2,
        Severity::Low => 1,
        Severity::None => 0,
    }
}

// ============================================================
// Two-pass generate_vault
// ============================================================

/// Generate the vault structure from a scan result.
/// Two-pass: collect CVE/tech maps (pass 1), then write all files (pass 2).
pub fn generate_vault(
    scan: &ScanResult,
    vault_path: &Path,
    scan_label: &str,
) -> Result<VaultStats, VaultError> {
    let today = today_string();

    // ===== PASS 1: Collect global state =====
    let mut cve_map: HashMap<String, CveAccumulator> = HashMap::new();
    let mut tech_map: HashMap<String, TechAccumulator> = HashMap::new();

    for host in &scan.hosts {
        for port in &host.ports {
            let svc_name = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
            let product = port.service.as_ref().and_then(|s| s.product.as_deref());
            let version = port.service.as_ref().and_then(|s| s.version.as_deref());

            // Build service wikilink for CVE affected_services
            let svc_wikilink = templates::service_wikilink(
                &host.ip,
                port.port_id,
                &port.protocol,
                svc_name,
                product,
            );

            // Upsert CVEs
            for vuln in &port.vulnerabilities {
                let acc = cve_map
                    .entry(vuln.cve_id.clone())
                    .or_insert_with(|| CveAccumulator {
                        cve_id: vuln.cve_id.clone(),
                        score: vuln.cvss.as_ref().map(|c| c.score),
                        severity: vuln
                            .cvss
                            .as_ref()
                            .map(|c| c.severity.clone())
                            .unwrap_or(Severity::None),
                        cvss_version: vuln.cvss.as_ref().map(|c| c.version.clone()),
                        sources: vec![],
                        description: vuln.description.clone(),
                        affected_services: vec![],
                        affected_hosts: vec![],
                    });

                // Keep highest CVSS score
                if let Some(cvss) = &vuln.cvss {
                    let incoming = severity_cmp(&cvss.severity);
                    let current = severity_cmp(&acc.severity);
                    if incoming > current {
                        acc.score = Some(cvss.score);
                        acc.severity = cvss.severity.clone();
                        acc.cvss_version = Some(cvss.version.clone());
                    } else if acc.score.is_none() {
                        acc.score = Some(cvss.score);
                    }
                    // Prefer the description with more info
                    if acc.description.is_none() {
                        acc.description = vuln.description.clone();
                    }
                }

                // Collect unique sources
                if !acc.sources.contains(&vuln.source) {
                    acc.sources.push(vuln.source.clone());
                }

                // Add service wikilink (deduplicated)
                if !acc.affected_services.contains(&svc_wikilink) {
                    acc.affected_services.push(svc_wikilink.clone());
                }

                // Add host wikilink (deduplicated)
                let host_wl = templates::host_wikilink(&host.ip);
                if !acc.affected_hosts.contains(&host_wl) {
                    acc.affected_hosts.push(host_wl);
                }
            }

            // Upsert tech (only if product present)
            if let Some(prod) = product {
                let port_cve_ids: Vec<String> =
                    port.vulnerabilities.iter().map(|v| v.cve_id.clone()).collect();

                let acc = tech_map
                    .entry(prod.to_string())
                    .or_insert_with(|| TechAccumulator {
                        product: prod.to_string(),
                        versions_seen: vec![],
                        instances: vec![],
                        cve_ids: vec![],
                    });

                // Add version (deduplicated)
                if let Some(ver) = version {
                    if !acc.versions_seen.contains(&ver.to_string()) {
                        acc.versions_seen.push(ver.to_string());
                    }
                }

                // Add instance
                acc.instances.push((
                    host.ip.clone(),
                    port.port_id,
                    version.map(|v| v.to_string()),
                ));

                // Merge CVE IDs (deduplicated)
                for cve_id in &port_cve_ids {
                    if !acc.cve_ids.contains(cve_id) {
                        acc.cve_ids.push(cve_id.clone());
                    }
                }
            }
        }
    }

    // ===== PASS 2: Write all files =====

    // Collect pre-existing service file paths for stale detection (D-02)
    let scan_services_dir = vault_path.join("scans").join(scan_label).join("services");
    let pre_existing_services: Vec<String> = if scan_services_dir.exists() {
        std::fs::read_dir(&scan_services_dir)
            .ok()
            .map(|entries| {
                entries.flatten()
                    .filter_map(|e| {
                        let name = e.file_name().to_string_lossy().to_string();
                        if name.ends_with(".md") {
                            Some(format!("scans/{}/services/{}", scan_label, name))
                        } else {
                            None
                        }
                    })
                    .collect()
            })
            .unwrap_or_default()
    } else {
        vec![]
    };

    // Track which service paths are regenerated this run (for stale tag detection)
    let mut regenerated_service_paths: Vec<String> = vec![];

    // 1. Write .obsidian/graph.json
    let graph_json = graph_config::generate_graph_json();
    writer::write_note(vault_path, ".obsidian/graph.json", &graph_json)?;

    // 2. Write assets/severity-colors.css
    let css = graph_config::generate_css_snippet();
    writer::write_note(vault_path, "assets/severity-colors.css", &css)?;

    // 3. Write host notes
    let mut host_count = 0usize;
    let mut service_count = 0usize;

    for host in &scan.hosts {
        host_count += 1;

        // Collect all vulns across all ports for host-level severity
        let all_vulns: Vec<Vulnerability> = host
            .ports
            .iter()
            .flat_map(|p| p.vulnerabilities.iter().cloned())
            .collect();
        let host_severity = highest_severity(&all_vulns);

        let fm = HostFrontmatter {
            ip: host.ip.clone(),
            hostnames: host.hostnames.clone(),
            os: host.os_matches.first().cloned(),
            highest_severity: host_severity.obsidian_tag().to_string(),
            tags: vec!["host".to_string(), host_severity.obsidian_tag().to_string()],
            scan_label: scan_label.to_string(),
        };

        let body = templates::render_host_body(host, scan_label);
        let note_content = frontmatter::render_note(&fm, &body)?;
        let path = format!(
            "scans/{}/hosts/{}.md",
            scan_label,
            sanitize_filename(&host.ip)
        );
        merge::merge_write_note(vault_path, &path, &note_content)?;

        // 4. Write service notes
        for port in &host.ports {
            service_count += 1;

            let svc_name = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
            let product = port.service.as_ref().and_then(|s| s.product.as_deref());
            let version = port.service.as_ref().and_then(|s| s.version.as_deref());

            let port_severity = highest_severity(&port.vulnerabilities);

            let fm = ServiceFrontmatter {
                host: host.ip.clone(),
                port: port.port_id,
                protocol: port.protocol.clone(),
                service: svc_name.to_string(),
                product: product.map(|s| s.to_string()),
                version: version.map(|s| s.to_string()),
                highest_severity: port_severity.obsidian_tag().to_string(),
                tags: vec![
                    "service".to_string(),
                    svc_name.to_string(),
                    port_severity.obsidian_tag().to_string(),
                ],
                scan_label: scan_label.to_string(),
            };

            // Build vulns table data
            let vulns_for_table: Vec<(String, Option<f32>, String, String)> = port
                .vulnerabilities
                .iter()
                .map(|v| {
                    let score = v.cvss.as_ref().map(|c| c.score);
                    let severity = v
                        .cvss
                        .as_ref()
                        .map(|c| c.severity.obsidian_tag().to_string())
                        .unwrap_or_else(|| "none".to_string());
                    let desc = v.description.as_deref().unwrap_or("").to_string();
                    (v.cve_id.clone(), score, severity, desc)
                })
                .collect();

            let body = templates::render_service_body(&host.ip, port, &vulns_for_table, &port.exploits);
            let note_content = frontmatter::render_note(&fm, &body)?;
            let path = format!(
                "scans/{}/services/{}_{}.md",
                scan_label,
                sanitize_filename(&host.ip),
                format!("{}_{}", port.port_id, sanitize_filename(&port.protocol))
            );
            merge::merge_write_note(vault_path, &path, &note_content)?;
            regenerated_service_paths.push(path);
        }
    }

    // 5. Write CVE notes (with Score History tracking)
    let cve_count = cve_map.len();
    for (_, acc) in &cve_map {
        let fm = CveFrontmatter {
            cve_id: acc.cve_id.clone(),
            cvss_score: acc.score,
            severity: acc.severity.obsidian_tag().to_string(),
            cvss_version: acc.cvss_version.clone(),
            sources: acc.sources.clone(),
            tags: vec!["cve".to_string(), acc.severity.obsidian_tag().to_string()],
            first_seen: today.clone(),
        };

        let body = templates::render_cve_body(
            &acc.cve_id,
            acc.score,
            acc.severity.obsidian_tag(),
            acc.cvss_version.as_deref(),
            &acc.sources,
            acc.description.as_deref(),
            &acc.affected_services,
            &acc.affected_hosts,
        );
        let note_content = frontmatter::render_note(&fm, &body)?;
        let path = format!("cves/{}.md", sanitize_filename(&acc.cve_id));
        merge::merge_write_cve_note(
            vault_path,
            &path,
            &note_content,
            acc.score,
            acc.severity.obsidian_tag(),
            acc.cvss_version.as_deref(),
            &today,
        )?;
    }

    // 6. Write technology notes
    let tech_count = tech_map.len();
    for (_, acc) in &tech_map {
        let fm = TechFrontmatter {
            product: acc.product.clone(),
            versions_seen: acc.versions_seen.clone(),
            tags: vec!["technology".to_string(), sanitize_filename(&acc.product)],
            first_seen: today.clone(),
        };

        let body = templates::render_tech_body(&acc.product, &acc.instances, &acc.cve_ids);
        let note_content = frontmatter::render_note(&fm, &body)?;
        let path = format!("technologies/{}.md", sanitize_filename(&acc.product));
        merge::merge_write_note(vault_path, &path, &note_content)?;
    }

    // Apply stale tags to service notes not seen in current scan (D-02)
    if !pre_existing_services.is_empty() {
        merge::apply_stale_tags(vault_path, &pre_existing_services, &regenerated_service_paths)?;
    }

    // 7. Write index pages

    // Compute severity breakdown from CVE map
    let mut severity_counts: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    for (_, acc) in &cve_map {
        let tag = acc.severity.obsidian_tag().to_string();
        *severity_counts.entry(tag).or_insert(0) += 1;
    }
    // Sort by severity descending: critical, high, medium, low, none
    let severity_order = ["critical", "high", "medium", "low", "none"];
    let severity_breakdown: Vec<(String, usize)> = severity_order
        .iter()
        .filter_map(|&s| severity_counts.get(s).map(|&c| (s.to_string(), c)))
        .collect();

    // Compute critical findings: CVEs with critical severity
    let mut critical_findings: Vec<(String, Vec<String>)> = cve_map
        .values()
        .filter(|acc| acc.severity == Severity::Critical)
        .map(|acc| (acc.cve_id.clone(), acc.affected_services.clone()))
        .collect();
    critical_findings.sort_by(|a, b| a.0.cmp(&b.0));

    // Compute host entries: (ip, highest_severity)
    let host_entries: Vec<(String, String)> = scan.hosts
        .iter()
        .map(|host| {
            let all_vulns: Vec<Vulnerability> = host
                .ports
                .iter()
                .flat_map(|p| p.vulnerabilities.iter().cloned())
                .collect();
            let severity = highest_severity(&all_vulns);
            (host.ip.clone(), severity.obsidian_tag().to_string())
        })
        .collect();

    // Write global _index.md at vault root
    let global_index_body = templates::render_global_index_body(
        scan_label,
        host_count,
        service_count,
        cve_count,
        &severity_breakdown,
        &critical_findings,
        &host_entries,
    );
    writer::write_note(vault_path, "_index.md", &global_index_body)?;

    // Write per-scan _index.md
    let scan_index_body = templates::render_scan_index_body(
        scan_label,
        &scan.source,
        host_count,
        service_count,
        cve_count,
        &severity_breakdown,
        &host_entries,
    );
    let scan_index_path = format!("scans/{}/_index.md", scan_label);
    writer::write_note(vault_path, &scan_index_path, &scan_index_body)?;

    // Write overview.md for this scan
    // Build top_cves: collect all CVEs, sort by score descending (None last), take top 10
    let mut top_cves_raw: Vec<(String, Option<f32>, String, String)> = cve_map
        .values()
        .map(|acc| {
            let desc = acc.description.as_deref().unwrap_or("").to_string();
            let truncated = templates::truncate_description(&desc);
            (
                acc.cve_id.clone(),
                acc.score,
                acc.severity.obsidian_tag().to_string(),
                truncated,
            )
        })
        .collect();
    top_cves_raw.sort_by(|a, b| {
        match (a.1, b.1) {
            (Some(sa), Some(sb)) => sb.partial_cmp(&sa).unwrap_or(std::cmp::Ordering::Equal),
            (Some(_), None) => std::cmp::Ordering::Less,
            (None, Some(_)) => std::cmp::Ordering::Greater,
            (None, None) => std::cmp::Ordering::Equal,
        }
    });
    top_cves_raw.truncate(10);

    // Build service_entries from all scan hosts
    let service_entries: Vec<(String, u16, String, String, Option<String>)> = scan.hosts
        .iter()
        .flat_map(|host| {
            host.ports.iter().map(move |port| {
                let svc_name = port.service.as_ref().map(|s| s.name.clone()).unwrap_or_else(|| "unknown".to_string());
                let product = port.service.as_ref().and_then(|s| s.product.clone());
                (host.ip.clone(), port.port_id, port.protocol.clone(), svc_name, product)
            })
        })
        .collect();

    let overview_body = templates::render_scan_overview_body(
        scan_label,
        host_count,
        service_count,
        cve_count,
        &severity_breakdown,
        &top_cves_raw,
        &host_entries,
        &service_entries,
    );
    writer::write_note(vault_path, &format!("scans/{}/overview.md", scan_label), &overview_body)?;

    Ok(VaultStats {
        hosts: host_count,
        services: service_count,
        cves: cve_count,
        technologies: tech_count,
    })
}

// ============================================================
// Merge target detection (for main.rs use)
// ============================================================

/// Find existing scan folder with IP overlap for merge. Returns scan label or None.
/// Called by main.rs before derive_scan_label to detect existing scan subfolders for merge.
pub fn find_merge_target(vault_path: &Path, scan: &ScanResult) -> Option<String> {
    let ips: Vec<String> = scan.hosts.iter().map(|h| h.ip.clone()).collect();
    merge::find_existing_scan_folder(vault_path, &ips)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Address, CvssScore, Host, Port, Service, ScanResult, Vulnerability};
    use std::fs;
    use std::path::PathBuf;

    fn make_test_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "portreaper_vault_test_{}_{}",
            suffix,
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create test vault dir");
        dir
    }

    fn make_scan(label: &str) -> (ScanResult, PathBuf) {
        let vuln1 = Vulnerability {
            cve_id: "CVE-2021-41773".to_string(),
            source: "NVD".to_string(),
            cvss: Some(CvssScore {
                score: 9.8,
                severity: Severity::Critical,
                version: "3.1".to_string(),
            }),
            description: Some("Path traversal and RCE in Apache".to_string()),
        };

        let service_ssh = Service {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("8.9p1".to_string()),
            extra_info: None,
            tunnel: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openbsd:openssh:8.9p1".to_string()],
        };

        let port_ssh = Port {
            port_id: 22,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(service_ssh),
            vulnerabilities: vec![],
            exploits: vec![],
        };

        let service_http = Service {
            name: "http".to_string(),
            product: Some("Apache".to_string()),
            version: Some("2.4.49".to_string()),
            extra_info: None,
            tunnel: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec![],
        };

        let port_http = Port {
            port_id: 80,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(service_http),
            vulnerabilities: vec![vuln1],
            exploits: vec![],
        };

        let host = Host {
            ip: "192.168.1.1".to_string(),
            hostnames: vec!["target.local".to_string()],
            status: "up".to_string(),
            addresses: vec![Address {
                addr: "192.168.1.1".to_string(),
                addr_type: "ipv4".to_string(),
            }],
            os_matches: vec!["Linux 5.15".to_string()],
            ports: vec![port_ssh, port_http],
        };

        let scan = ScanResult {
            source: "test.xml".to_string(),
            hosts: vec![host],
        };

        let dir = make_test_dir(label);
        (scan, dir)
    }

    #[test]
    fn generate_vault_creates_host_note() {
        let (scan, dir) = make_scan("host_note");
        generate_vault(&scan, &dir, "test-2026-03-24").expect("generate_vault");
        let path = dir.join("scans/test-2026-03-24/hosts/192.168.1.1.md");
        assert!(path.exists(), "host note should exist at {:?}", path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_creates_service_notes_for_each_port() {
        let (scan, dir) = make_scan("service_notes");
        generate_vault(&scan, &dir, "test-label").expect("generate_vault");
        let ssh = dir.join("scans/test-label/services/192.168.1.1_22_tcp.md");
        let http = dir.join("scans/test-label/services/192.168.1.1_80_tcp.md");
        assert!(ssh.exists(), "ssh service note should exist");
        assert!(http.exists(), "http service note should exist");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_creates_cve_note() {
        let (scan, dir) = make_scan("cve_note");
        generate_vault(&scan, &dir, "test-label").expect("generate_vault");
        let path = dir.join("cves/CVE-2021-41773.md");
        assert!(path.exists(), "CVE note should exist at {:?}", path);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_creates_technology_note() {
        let (scan, dir) = make_scan("tech_note");
        generate_vault(&scan, &dir, "test-label").expect("generate_vault");
        // Apache has a CVE; OpenSSH has no CVE — both should get notes
        let apache = dir.join("technologies/Apache.md");
        let openssh = dir.join("technologies/OpenSSH.md");
        assert!(apache.exists(), "Apache tech note should exist");
        assert!(openssh.exists(), "OpenSSH tech note should exist");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_creates_graph_json() {
        let (scan, dir) = make_scan("graph_json");
        generate_vault(&scan, &dir, "label").expect("generate_vault");
        let path = dir.join(".obsidian/graph.json");
        assert!(path.exists(), ".obsidian/graph.json should exist");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_creates_css_snippet() {
        let (scan, dir) = make_scan("css_snippet");
        generate_vault(&scan, &dir, "label").expect("generate_vault");
        let path = dir.join("assets/severity-colors.css");
        assert!(path.exists(), "assets/severity-colors.css should exist");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_vault_stats_counts_match() {
        let (scan, dir) = make_scan("stats_count");
        let stats = generate_vault(&scan, &dir, "label").expect("generate_vault");
        assert_eq!(stats.hosts, 1, "should report 1 host");
        assert_eq!(stats.services, 2, "should report 2 services");
        assert_eq!(stats.cves, 1, "should report 1 unique CVE");
        assert_eq!(stats.technologies, 2, "should report 2 technologies (OpenSSH, Apache)");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_shared_cve_appears_as_one_note_with_two_affected_services() {
        let shared_vuln = Vulnerability {
            cve_id: "CVE-2023-99999".to_string(),
            source: "NVD".to_string(),
            cvss: Some(CvssScore {
                score: 7.5,
                severity: Severity::High,
                version: "3.1".to_string(),
            }),
            description: Some("Shared vulnerability".to_string()),
        };

        let port1 = Port {
            port_id: 8080,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(Service {
                name: "http-alt".to_string(),
                product: Some("nginx".to_string()),
                version: None,
                extra_info: None,
                tunnel: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec![],
            }),
            vulnerabilities: vec![shared_vuln.clone()],
            exploits: vec![],
        };

        let port2 = Port {
            port_id: 443,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(Service {
                name: "https".to_string(),
                product: Some("nginx".to_string()),
                version: None,
                extra_info: None,
                tunnel: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec![],
            }),
            vulnerabilities: vec![shared_vuln.clone()],
            exploits: vec![],
        };

        let host = Host {
            ip: "10.0.0.1".to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![],
            os_matches: vec![],
            ports: vec![port1, port2],
        };

        let scan = ScanResult {
            source: "shared.xml".to_string(),
            hosts: vec![host],
        };

        let dir = make_test_dir("shared_cve");
        let stats = generate_vault(&scan, &dir, "shared-label").expect("generate_vault");

        // Only 1 CVE note should exist
        assert_eq!(stats.cves, 1, "shared CVE should produce exactly 1 note");
        let cve_path = dir.join("cves/CVE-2023-99999.md");
        assert!(cve_path.exists(), "CVE note should exist");

        // The CVE note should reference both services
        let content = fs::read_to_string(&cve_path).expect("read CVE note");
        assert!(
            content.contains("10.0.0.1_8080_tcp"),
            "CVE note should reference first service"
        );
        assert!(
            content.contains("10.0.0.1_443_tcp"),
            "CVE note should reference second service"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_service_with_no_cves_still_gets_note() {
        let port = Port {
            port_id: 3306,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(Service {
                name: "mysql".to_string(),
                product: Some("MySQL".to_string()),
                version: None,
                extra_info: None,
                tunnel: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec![],
            }),
            vulnerabilities: vec![],
            exploits: vec![],
        };

        let host = Host {
            ip: "10.0.0.2".to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![],
            os_matches: vec![],
            ports: vec![port],
        };

        let scan = ScanResult {
            source: "mysql.xml".to_string(),
            hosts: vec![host],
        };

        let dir = make_test_dir("no_cve_service");
        generate_vault(&scan, &dir, "no-cve-label").expect("generate_vault");
        let svc_path = dir.join("scans/no-cve-label/services/10.0.0.2_3306_tcp.md");
        assert!(svc_path.exists(), "service note should exist even with no CVEs");
        let content = fs::read_to_string(&svc_path).expect("read service note");
        assert!(
            content.contains("No vulnerabilities found."),
            "service note should say no vulnerabilities"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_service_with_no_product_does_not_create_tech_note() {
        let port = Port {
            port_id: 9999,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(Service {
                name: "unknown".to_string(),
                product: None,
                version: None,
                extra_info: None,
                tunnel: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec![],
            }),
            vulnerabilities: vec![],
            exploits: vec![],
        };

        let host = Host {
            ip: "10.0.0.3".to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![],
            os_matches: vec![],
            ports: vec![port],
        };

        let scan = ScanResult {
            source: "unknown.xml".to_string(),
            hosts: vec![host],
        };

        let dir = make_test_dir("no_product");
        let stats = generate_vault(&scan, &dir, "no-product-label").expect("generate_vault");
        assert_eq!(stats.technologies, 0, "no tech note should be created when product is None");
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Index page tests (Plan 03) ----

    #[test]
    fn generate_vault_creates_global_index_at_root() {
        let (scan, dir) = make_scan("global_index");
        generate_vault(&scan, &dir, "test-label").expect("generate_vault");
        let path = dir.join("_index.md");
        assert!(path.exists(), "_index.md should exist at vault root");
        let content = fs::read_to_string(&path).expect("read _index.md");
        assert!(content.contains("# PortReaper Vault"), "global index should have title");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_creates_scan_index_in_scan_subfolder() {
        let (scan, dir) = make_scan("scan_index");
        generate_vault(&scan, &dir, "test-label").expect("generate_vault");
        let path = dir.join("scans/test-label/_index.md");
        assert!(path.exists(), "scans/test-label/_index.md should exist");
        let content = fs::read_to_string(&path).expect("read scan _index.md");
        assert!(content.contains("# Scan:"), "scan index should have scan title");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_vault_creates_overview_md_in_scan_subfolder() {
        let (scan, dir) = make_scan("overview_md");
        generate_vault(&scan, &dir, "test-label").expect("generate_vault");
        let path = dir.join("scans/test-label/overview.md");
        assert!(path.exists(), "scans/test-label/overview.md should exist at {:?}", path);
        let content = fs::read_to_string(&path).expect("read overview.md");
        assert!(content.contains("# Scan Overview:"), "should have Scan Overview heading");
        assert!(content.contains("## Top CVEs"), "should have Top CVEs section");
        assert!(content.contains("## Hosts"), "should have Hosts section");
        assert!(content.contains("## Services"), "should have Services section");
        assert!(content.contains("[[192.168.1.1]]"), "should have host wikilink");
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- Tests from Plan 01 that must still pass ----

    #[test]
    fn derive_scan_label_has_date_prefix() {
        let label = derive_scan_label("scan_192.168.1.0.xml");
        let parts: Vec<&str> = label.splitn(2, '_').collect();
        assert_eq!(parts.len(), 2);
        assert_eq!(parts[0].len(), 10);
        assert!(parts[0].contains('-'));
    }

    #[test]
    fn derive_scan_label_sanitizes_slashes() {
        let label = derive_scan_label("192.168.1.0/24.xml");
        assert!(!label.contains('/'));
    }

    #[test]
    fn vault_error_write_error_wraps_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = VaultError::WriteError {
            path: "/some/path".to_string(),
            source: io_err,
        };
        let display = err.to_string();
        assert!(display.contains("failed to write vault file"));
        assert!(display.contains("/some/path"));
    }

    #[test]
    fn vault_error_dir_error_wraps_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = VaultError::DirError {
            path: "/some/dir".to_string(),
            source: io_err,
        };
        let display = err.to_string();
        assert!(display.contains("failed to create vault directory"));
        assert!(display.contains("/some/dir"));
    }
}
