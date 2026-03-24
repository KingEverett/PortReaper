use crate::models::{Host, Port};
use crate::util::filename::sanitize_filename;

// ============================================================
// Wikilink helpers (D-05, D-06)
// ============================================================

pub fn host_wikilink(ip: &str) -> String {
    format!("[[{}]]", sanitize_filename(ip))
}

pub fn service_wikilink(ip: &str, port: u16, proto: &str, svc_name: &str, product: Option<&str>) -> String {
    let filename = sanitize_filename(&format!("{}_{}_{}", ip, port, proto));
    let display = match product {
        Some(p) => format!(":{} {} ({})", port, svc_name, p),
        None => format!(":{} {}", port, svc_name),
    };
    format!("[[{}|{}]]", filename, display)
}

pub fn cve_wikilink(cve_id: &str) -> String {
    format!("[[{}]]", sanitize_filename(cve_id))
}

pub fn tech_wikilink(product: &str) -> String {
    format!("[[{}]]", sanitize_filename(product))
}

// ============================================================
// Description truncation
// ============================================================

const MAX_DESC_LEN: usize = 120;

pub fn truncate_description(desc: &str) -> String {
    if desc.len() <= MAX_DESC_LEN {
        return desc.to_string();
    }
    let truncated = &desc[..MAX_DESC_LEN];
    match truncated.rfind(' ') {
        Some(pos) => format!("{}...", &truncated[..pos]),
        None => format!("{}...", truncated),
    }
}

// ============================================================
// Host body rendering (D-09)
// port_severities: (port, proto, svc_name, product, severity_tag)
// ============================================================

pub fn render_host_body(host: &Host, _scan_label: &str) -> String {
    let mut body = format!("# {}\n\n", host.ip);

    if !host.hostnames.is_empty() {
        let names = host.hostnames.join(", ");
        body.push_str(&format!("**Hostnames:** {}\n\n", names));
    }

    if let Some(os) = host.os_matches.first() {
        body.push_str(&format!("**OS:** {}\n\n", os));
    }

    // Open Ports table
    body.push_str("## Open Ports\n\n");
    body.push_str("| Port | Service | Product | Severity |\n");
    body.push_str("|------|---------|---------|----------|\n");

    for port in &host.ports {
        let svc_name = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
        let product = port.service.as_ref().and_then(|s| s.product.as_deref());
        let svc_link = service_wikilink(&host.ip, port.port_id, &port.protocol, svc_name, product);

        let product_display = product.unwrap_or("-");
        let severity = highest_port_severity(port);

        body.push_str(&format!("| {} | {} | {} | {} |\n",
            port.port_id, svc_link, product_display, severity));
    }

    // Vulnerability Summary
    body.push_str("\n## Vulnerability Summary\n\n");
    let mut critical = 0usize;
    let mut high = 0usize;
    let mut medium = 0usize;
    let mut low = 0usize;

    for port in &host.ports {
        for vuln in &port.vulnerabilities {
            if let Some(cvss) = &vuln.cvss {
                use crate::models::Severity;
                match cvss.severity {
                    Severity::Critical => critical += 1,
                    Severity::High => high += 1,
                    Severity::Medium => medium += 1,
                    Severity::Low => low += 1,
                    Severity::None => {}
                }
            }
        }
    }

    body.push_str(&format!(
        "- Critical: {}\n- High: {}\n- Medium: {}\n- Low: {}\n",
        critical, high, medium, low
    ));

    body.push_str("\n## Notes\n\n");
    body
}

fn highest_port_severity(port: &Port) -> &'static str {
    use crate::models::Severity;
    let mut highest = Severity::None;
    for vuln in &port.vulnerabilities {
        if let Some(cvss) = &vuln.cvss {
            let sev = match cvss.severity {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::None => 0,
            };
            let cur = match highest {
                Severity::Critical => 4,
                Severity::High => 3,
                Severity::Medium => 2,
                Severity::Low => 1,
                Severity::None => 0,
            };
            if sev > cur {
                highest = cvss.severity.clone();
            }
        }
    }
    highest.obsidian_tag()
}

// ============================================================
// Service body rendering (D-11)
// vulns_for_table: (cve_id, score, severity_tag, description)
// ============================================================

pub fn render_service_body(
    ip: &str,
    port: &Port,
    vulns_for_table: &[(String, Option<f32>, String, String)],
) -> String {
    let svc_name = port.service.as_ref().map(|s| s.name.as_str()).unwrap_or("unknown");
    let product = port.service.as_ref().and_then(|s| s.product.as_deref());
    let version = port.service.as_ref().and_then(|s| s.version.as_deref());

    let mut body = format!("# {}:{}/{} - {}\n\n", ip, port.port_id, port.protocol, svc_name);

    // Host backlink
    body.push_str(&format!("**Host:** {}\n\n", host_wikilink(ip)));

    // Product link (tech wikilink)
    if let Some(prod) = product {
        body.push_str(&format!("**Product:** {}", tech_wikilink(prod)));
        if let Some(ver) = version {
            body.push_str(&format!(" ({})", ver));
        }
        body.push('\n');
        body.push('\n');
    }

    // CPE code block
    if let Some(svc) = &port.service {
        if !svc.cpe.is_empty() {
            body.push_str("**CPE:**\n```\n");
            for cpe in &svc.cpe {
                body.push_str(cpe);
                body.push('\n');
            }
            body.push_str("```\n\n");
        }
    }

    // Vulnerabilities table
    body.push_str("## Vulnerabilities\n\n");
    if vulns_for_table.is_empty() {
        body.push_str("No vulnerabilities found.\n");
    } else {
        body.push_str("| CVE | Score | Severity | Description |\n");
        body.push_str("|-----|-------|----------|-------------|\n");
        for (cve_id, score, severity, desc) in vulns_for_table {
            let cve_link = cve_wikilink(cve_id);
            let score_display = score.map(|s| format!("{:.1}", s)).unwrap_or_else(|| "N/A".to_string());
            let truncated = truncate_description(desc);
            body.push_str(&format!("| {} | {} | {} | {} |\n",
                cve_link, score_display, severity, truncated));
        }
    }

    body.push_str("\n## Notes\n\n");
    body
}

// ============================================================
// CVE body rendering (D-13)
// affected_services: pre-built service wikilinks
// ============================================================

pub fn render_cve_body(
    cve_id: &str,
    score: Option<f32>,
    severity: &str,
    cvss_version: Option<&str>,
    sources: &[String],
    description: Option<&str>,
    affected_services: &[String],
) -> String {
    let mut body = format!("# {}\n\n", cve_id);

    // Score line
    match (score, cvss_version) {
        (Some(s), Some(v)) => {
            body.push_str(&format!("**CVSS Score:** {:.1} ({}) (CVSS v{})\n\n", s, severity, v));
        }
        (Some(s), None) => {
            body.push_str(&format!("**CVSS Score:** {:.1} ({})\n\n", s, severity));
        }
        _ => {
            body.push_str("**CVSS Score:** N/A\n\n");
        }
    }

    // Sources
    if !sources.is_empty() {
        body.push_str(&format!("**Sources:** {}\n\n", sources.join(", ")));
    }

    // Description
    if let Some(desc) = description {
        body.push_str(desc);
        body.push_str("\n\n");
    }

    // Affected Services
    body.push_str("## Affected Services\n\n");
    for svc in affected_services {
        body.push_str(&format!("- {}\n", svc));
    }

    // References
    body.push_str("\n## References\n\n");
    body.push_str(&format!("- [NVD](https://nvd.nist.gov/vuln/detail/{})\n", cve_id));
    body.push_str(&format!("- [CVE.org](https://www.cve.org/CVERecord?id={})\n", cve_id));

    body.push_str("\n## Notes\n\n");
    body
}

// ============================================================
// Technology body rendering (D-15)
// instances: (ip, port, version)
// ============================================================

pub fn render_tech_body(
    product: &str,
    instances: &[(String, u16, Option<String>)],
    cve_ids: &[String],
) -> String {
    let mut body = format!("# {}\n\n", product);

    // Instances section
    body.push_str("## Instances\n\n");
    for (ip, port, version) in instances {
        match version {
            Some(v) => body.push_str(&format!("- {} :{} (v{})\n", host_wikilink(ip), port, v)),
            None => body.push_str(&format!("- {} :{}\n", host_wikilink(ip), port)),
        }
    }

    // Known CVEs section
    body.push_str("\n## Known CVEs\n\n");
    if cve_ids.is_empty() {
        body.push_str("No known CVEs.\n");
    } else {
        for cve_id in cve_ids {
            body.push_str(&format!("- {}\n", cve_wikilink(cve_id)));
        }
    }

    body.push_str("\n## Notes\n\n");
    body
}

// ============================================================
// Global index body rendering (D-16)
// severity_breakdown: [("critical", 3), ("high", 5), ...]
// critical_findings: [(cve_id, [service_wikilinks])]
// host_entries: [(ip, highest_severity)]
// ============================================================

pub fn render_global_index_body(
    scan_label: &str,
    host_count: usize,
    service_count: usize,
    cve_count: usize,
    severity_breakdown: &[(String, usize)],
    critical_findings: &[(String, Vec<String>)],
    host_entries: &[(String, String)],
) -> String {
    let mut body = String::from("# PortReaper Vault\n\n");

    // Summary table
    body.push_str("## Summary\n\n");
    body.push_str("| Metric | Count |\n");
    body.push_str("|--------|-------|\n");
    body.push_str(&format!("| Hosts | {} |\n", host_count));
    body.push_str(&format!("| Services | {} |\n", service_count));
    body.push_str(&format!("| CVEs | {} |\n", cve_count));
    body.push('\n');

    // Severity Breakdown table
    body.push_str("## Severity Breakdown\n\n");
    body.push_str("| Severity | Count |\n");
    body.push_str("|----------|-------|\n");
    for (severity, count) in severity_breakdown {
        body.push_str(&format!("| {} | {} |\n", severity, count));
    }
    body.push('\n');

    // Critical Findings
    body.push_str("## Critical Findings\n\n");
    if critical_findings.is_empty() {
        body.push_str("No critical findings.\n");
    } else {
        for (cve_id, svc_links) in critical_findings {
            let svc_list = svc_links.join(", ");
            body.push_str(&format!("- {}: affected by {}\n", cve_wikilink(cve_id), svc_list));
        }
    }
    body.push('\n');

    // Scans section
    body.push_str("## Scans\n\n");
    body.push_str(&format!(
        "- [[scans/{}/_index|{}]]\n",
        scan_label, scan_label
    ));
    body.push('\n');

    // Hosts section
    body.push_str("## Hosts\n\n");
    for (ip, severity) in host_entries {
        body.push_str(&format!("- {} (highest: {})\n", host_wikilink(ip), severity));
    }

    body
}

// ============================================================
// Per-scan index body rendering (D-17)
// severity_breakdown: [("critical", 3), ...]
// host_entries: [(ip, highest_severity)]
// ============================================================

pub fn render_scan_index_body(
    scan_label: &str,
    source_file: &str,
    host_count: usize,
    service_count: usize,
    cve_count: usize,
    severity_breakdown: &[(String, usize)],
    host_entries: &[(String, String)],
) -> String {
    let mut body = format!("# Scan: {}\n\n", scan_label);

    body.push_str(&format!("**Source:** {}\n\n", source_file));
    body.push_str(&format!(
        "**Hosts:** {} | **Services:** {} | **CVEs:** {}\n\n",
        host_count, service_count, cve_count
    ));

    // Severity Breakdown table
    body.push_str("## Severity Breakdown\n\n");
    body.push_str("| Severity | Count |\n");
    body.push_str("|----------|-------|\n");
    for (severity, count) in severity_breakdown {
        body.push_str(&format!("| {} | {} |\n", severity, count));
    }
    body.push('\n');

    // Hosts section
    body.push_str("## Hosts\n\n");
    for (ip, severity) in host_entries {
        body.push_str(&format!("- {} (highest: {})\n", host_wikilink(ip), severity));
    }

    body
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Host, Port, Service, Vulnerability, CvssScore, Severity};

    fn make_port(port_id: u16, proto: &str, svc_name: &str, product: Option<&str>, vulns: Vec<Vulnerability>) -> Port {
        Port {
            port_id,
            protocol: proto.to_string(),
            state: "open".to_string(),
            service: Some(Service {
                name: svc_name.to_string(),
                product: product.map(|s| s.to_string()),
                version: None,
                extra_info: None,
                tunnel: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec![],
            }),
            vulnerabilities: vulns,
        }
    }

    // Wikilink helper tests

    #[test]
    fn host_wikilink_produces_simple_bracket() {
        assert_eq!(host_wikilink("192.168.1.1"), "[[192.168.1.1]]");
    }

    #[test]
    fn service_wikilink_with_product() {
        let result = service_wikilink("192.168.1.1", 22, "tcp", "ssh", Some("OpenSSH 7.4"));
        assert_eq!(result, "[[192.168.1.1_22_tcp|:22 ssh (OpenSSH 7.4)]]");
    }

    #[test]
    fn service_wikilink_without_product() {
        let result = service_wikilink("192.168.1.1", 22, "tcp", "ssh", None);
        assert_eq!(result, "[[192.168.1.1_22_tcp|:22 ssh]]");
    }

    #[test]
    fn cve_wikilink_produces_bracket_with_cve_id() {
        assert_eq!(cve_wikilink("CVE-2021-41773"), "[[CVE-2021-41773]]");
    }

    #[test]
    fn tech_wikilink_produces_bracket_with_product() {
        assert_eq!(tech_wikilink("OpenSSH"), "[[OpenSSH]]");
    }

    // render_host_body tests

    #[test]
    fn render_host_body_two_ports_produces_table_with_two_rows() {
        let host = Host {
            ip: "192.168.1.1".to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![],
            os_matches: vec![],
            ports: vec![
                make_port(22, "tcp", "ssh", Some("OpenSSH"), vec![]),
                make_port(80, "tcp", "http", None, vec![]),
            ],
        };
        let body = render_host_body(&host, "test-label");
        // Two service wikilink rows
        assert!(body.contains("192.168.1.1_22_tcp"), "should contain ssh service link");
        assert!(body.contains("192.168.1.1_80_tcp"), "should contain http service link");
    }

    #[test]
    fn render_host_body_includes_vulnerability_summary_section() {
        let vuln = Vulnerability {
            cve_id: "CVE-2021-41773".to_string(),
            source: "NVD".to_string(),
            cvss: Some(CvssScore {
                score: 9.8,
                severity: Severity::Critical,
                version: "3.1".to_string(),
            }),
            description: None,
        };
        let host = Host {
            ip: "10.0.0.1".to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![],
            os_matches: vec![],
            ports: vec![Port {
                port_id: 443,
                protocol: "tcp".to_string(),
                state: "open".to_string(),
                service: None,
                vulnerabilities: vec![vuln],
            }],
        };
        let body = render_host_body(&host, "label");
        assert!(body.contains("## Vulnerability Summary"), "should have Vulnerability Summary section");
        assert!(body.contains("Critical: 1"), "should count critical vulns");
    }

    #[test]
    fn render_host_body_includes_notes_section() {
        let host = Host {
            ip: "10.0.0.1".to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![],
            os_matches: vec![],
            ports: vec![],
        };
        let body = render_host_body(&host, "label");
        assert!(body.contains("## Notes"), "should have Notes section");
    }

    // render_service_body tests

    #[test]
    fn render_service_body_includes_product_tech_wikilink() {
        let port = Port {
            port_id: 22,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(Service {
                name: "ssh".to_string(),
                product: Some("OpenSSH".to_string()),
                version: Some("8.9p1".to_string()),
                extra_info: None,
                tunnel: None,
                hostname: None,
                os_type: None,
                device_type: None,
                cpe: vec!["cpe:/a:openbsd:openssh:8.9p1".to_string()],
            }),
            vulnerabilities: vec![],
        };
        let body = render_service_body("192.168.1.1", &port, &[]);
        assert!(body.contains("[[OpenSSH]]"), "should have product tech wikilink");
        assert!(body.contains("**Host:** [[192.168.1.1]]"), "should have host backlink");
        assert!(body.contains("cpe:/a:openbsd:openssh:8.9p1"), "should have CPE block");
    }

    #[test]
    fn render_service_body_two_vulns_produces_table() {
        let port = Port {
            port_id: 80,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: Some(Service {
                name: "http".to_string(),
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
        };
        let vulns = vec![
            ("CVE-2021-41773".to_string(), Some(9.8f32), "critical".to_string(), "Path traversal".to_string()),
            ("CVE-2021-42013".to_string(), Some(9.8f32), "critical".to_string(), "RCE".to_string()),
        ];
        let body = render_service_body("10.0.0.1", &port, &vulns);
        assert!(body.contains("[[CVE-2021-41773]]"), "should have first CVE link");
        assert!(body.contains("[[CVE-2021-42013]]"), "should have second CVE link");
    }

    #[test]
    fn render_service_body_zero_vulns_shows_no_vulnerabilities_found() {
        let port = Port {
            port_id: 3306,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: None,
            vulnerabilities: vec![],
        };
        let body = render_service_body("10.0.0.1", &port, &[]);
        assert!(body.contains("No vulnerabilities found."), "should show no vulnerabilities message");
    }

    // render_cve_body tests

    #[test]
    fn render_cve_body_includes_score_severity_description_affected_services_references() {
        let sources = vec!["NVD".to_string(), "CVE.org".to_string()];
        let affected = vec![
            "[[192.168.1.1_80_tcp|:80 http]]".to_string(),
        ];
        let body = render_cve_body(
            "CVE-2021-41773",
            Some(9.8),
            "critical",
            Some("3.1"),
            &sources,
            Some("Path traversal vulnerability"),
            &affected,
        );
        assert!(body.contains("**CVSS Score:** 9.8"), "should have score");
        assert!(body.contains("critical"), "should have severity");
        assert!(body.contains("Path traversal vulnerability"), "should have description");
        assert!(body.contains("## Affected Services"), "should have Affected Services section");
        assert!(body.contains("192.168.1.1_80_tcp"), "should have affected service wikilink");
        assert!(body.contains("nvd.nist.gov"), "should have NVD reference link");
        assert!(body.contains("cve.org"), "should have CVE.org reference link");
    }

    // render_tech_body tests

    #[test]
    fn render_tech_body_includes_instances_and_known_cves() {
        let instances = vec![
            ("192.168.1.1".to_string(), 22u16, Some("8.9p1".to_string())),
            ("192.168.1.2".to_string(), 22u16, None),
        ];
        let cve_ids = vec!["CVE-2023-38408".to_string()];
        let body = render_tech_body("OpenSSH", &instances, &cve_ids);
        assert!(body.contains("[[192.168.1.1]]"), "should have first host wikilink");
        assert!(body.contains("[[192.168.1.2]]"), "should have second host wikilink");
        assert!(body.contains("[[CVE-2023-38408]]"), "should have CVE wikilink");
        assert!(body.contains("## Instances"), "should have Instances section");
        assert!(body.contains("## Known CVEs"), "should have Known CVEs section");
    }

    // truncate_description tests

    #[test]
    fn truncate_description_passes_through_short_string() {
        let short = "Short description";
        assert_eq!(truncate_description(short), short);
    }

    #[test]
    fn truncate_description_truncates_at_word_boundary_with_ellipsis() {
        // Create a string longer than 120 chars that ends with a full word before 120
        let long = "A very long description that goes well beyond one hundred and twenty characters, which is the maximum allowed length for display";
        assert!(long.len() > 120, "test string should be longer than 120 chars");
        let result = truncate_description(long);
        assert!(result.len() <= 120 + 3, "result should be at most 123 chars (120 + '...')");
        assert!(result.ends_with("..."), "result should end with ...");
    }

    // render_global_index_body tests

    #[test]
    fn render_global_index_body_produces_portreaper_vault_title() {
        let body = render_global_index_body(
            "test-scan",
            2, 5, 3,
            &[("critical".to_string(), 1), ("high".to_string(), 2)],
            &[],
            &[("192.168.1.1".to_string(), "critical".to_string())],
        );
        assert!(body.contains("# PortReaper Vault"), "should have title");
    }

    #[test]
    fn render_global_index_body_contains_count_table() {
        let body = render_global_index_body(
            "test-scan",
            2, 5, 3,
            &[],
            &[],
            &[],
        );
        assert!(body.contains("| Metric | Count |"), "should have metric table header");
        assert!(body.contains("| Hosts |"), "should have hosts row");
        assert!(body.contains("| Services |"), "should have services row");
        assert!(body.contains("| CVEs |"), "should have CVEs row");
        assert!(body.contains("| 2 |"), "should have hosts count");
        assert!(body.contains("| 5 |"), "should have services count");
        assert!(body.contains("| 3 |"), "should have CVEs count");
    }

    #[test]
    fn render_global_index_body_contains_severity_breakdown_table() {
        let body = render_global_index_body(
            "test-scan",
            2, 5, 3,
            &[("critical".to_string(), 3), ("high".to_string(), 5)],
            &[],
            &[],
        );
        assert!(body.contains("| Severity | Count |"), "should have severity table header");
        assert!(body.contains("| critical |"), "should have critical row");
        assert!(body.contains("| high |"), "should have high row");
        assert!(body.contains("| 3 |"), "should have critical count");
    }

    #[test]
    fn render_global_index_body_includes_critical_findings_with_cve_wikilinks() {
        let body = render_global_index_body(
            "test-scan",
            1, 2, 1,
            &[("critical".to_string(), 1)],
            &[("CVE-2023-38408".to_string(), vec!["[[192.168.1.1_22_tcp|:22 ssh]]".to_string()])],
            &[("192.168.1.1".to_string(), "critical".to_string())],
        );
        assert!(body.contains("## Critical Findings"), "should have Critical Findings section");
        assert!(body.contains("[[CVE-2023-38408]]"), "should have CVE wikilink in critical findings");
    }

    #[test]
    fn render_global_index_body_includes_hosts_list() {
        let body = render_global_index_body(
            "test-scan",
            1, 1, 0,
            &[],
            &[],
            &[("192.168.1.1".to_string(), "high".to_string())],
        );
        assert!(body.contains("## Hosts"), "should have Hosts section");
        assert!(body.contains("[[192.168.1.1]]"), "should have host wikilink");
        assert!(body.contains("high"), "should show severity");
    }

    // render_scan_index_body tests

    #[test]
    fn render_scan_index_body_produces_scan_title() {
        let body = render_scan_index_body(
            "2026-03-21_192.168.1.1",
            "scan.xml",
            1, 2, 1,
            &[("critical".to_string(), 1)],
            &[("192.168.1.1".to_string(), "critical".to_string())],
        );
        assert!(body.contains("# Scan: 2026-03-21_192.168.1.1"), "should have scan title");
    }

    #[test]
    fn render_scan_index_body_includes_source_file() {
        let body = render_scan_index_body(
            "test-label",
            "scan_vulnerable.xml",
            1, 2, 1,
            &[],
            &[],
        );
        assert!(body.contains("**Source:**"), "should have Source field");
        assert!(body.contains("scan_vulnerable.xml"), "should have source filename");
    }

    #[test]
    fn render_scan_index_body_includes_counts_and_severity_table() {
        let body = render_scan_index_body(
            "test-label",
            "scan.xml",
            1, 2, 3,
            &[("high".to_string(), 2), ("medium".to_string(), 1)],
            &[],
        );
        assert!(body.contains("**Hosts:** 1"), "should have hosts count");
        assert!(body.contains("**Services:** 2"), "should have services count");
        assert!(body.contains("**CVEs:** 3"), "should have CVEs count");
        assert!(body.contains("| Severity | Count |"), "should have severity table");
        assert!(body.contains("| high |"), "should have high row");
        assert!(body.contains("| medium |"), "should have medium row");
    }

    #[test]
    fn render_scan_index_body_includes_hosts_list() {
        let body = render_scan_index_body(
            "test-label",
            "scan.xml",
            1, 1, 0,
            &[],
            &[("10.0.0.1".to_string(), "low".to_string())],
        );
        assert!(body.contains("## Hosts"), "should have Hosts section");
        assert!(body.contains("[[10.0.0.1]]"), "should have host wikilink");
        assert!(body.contains("low"), "should show severity");
    }
}
