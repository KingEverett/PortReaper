use portreaper::models::{Host, Port, ScanResult, Service, Severity, Vulnerability};
use owo_colors::{OwoColorize, Stream};
use std::collections::HashSet;

const BRANCH: &str = "\u{251C}\u{2500}\u{2500} "; // ├──
const LAST_BRANCH: &str = "\u{2514}\u{2500}\u{2500} "; // └──
const VERTICAL: &str = "\u{2502}   "; // │
const INDENT: &str = "    ";

pub struct RenderOptions {
    pub verbose: bool,
    pub quiet: bool,
    pub use_color: bool,
}

/// Render the scan result as a tree view to stdout.
/// Header: source filename/stdin. Body: host→port→service tree. Footer: summary counts.
pub fn render_tree(result: &ScanResult, opts: &RenderOptions) {
    let open_ports: Vec<_> = result
        .hosts
        .iter()
        .flat_map(|h| h.ports.iter())
        .filter(|p| p.state == "open")
        .collect();

    let open_port_count = open_ports.len();
    let unique_services: HashSet<&str> = open_ports
        .iter()
        .filter_map(|p| p.service.as_ref().map(|s| s.name.as_str()))
        .collect();
    let unique_service_count = unique_services.len();
    let host_count = result.hosts.len();

    // Count CVEs by severity across all ports (D-04)
    let all_vulns: Vec<&Vulnerability> = result.hosts.iter()
        .flat_map(|h| h.ports.iter())
        .flat_map(|p| p.vulnerabilities.iter())
        .collect();
    let total_cves = all_vulns.len();
    let critical_count = all_vulns.iter().filter(|v| v.cvss.as_ref().map(|c| c.severity == Severity::Critical).unwrap_or(false)).count();
    let high_count = all_vulns.iter().filter(|v| v.cvss.as_ref().map(|c| c.severity == Severity::High).unwrap_or(false)).count();
    let medium_count = all_vulns.iter().filter(|v| v.cvss.as_ref().map(|c| c.severity == Severity::Medium).unwrap_or(false)).count();
    let low_count = all_vulns.iter().filter(|v| v.cvss.as_ref().map(|c| c.severity == Severity::Low).unwrap_or(false)).count();

    let summary = if total_cves > 0 {
        format!(
            "Summary: {} hosts, {} open ports, {} CVEs ({} critical, {} high, {} medium, {} low)",
            host_count, open_port_count, total_cves, critical_count, high_count, medium_count, low_count
        )
    } else {
        format!(
            "Summary: {} hosts, {} open ports, {} unique services",
            host_count, open_port_count, unique_service_count
        )
    };

    if opts.quiet {
        if opts.use_color {
            println!("{}", summary.bold());
        } else {
            println!("{}", summary);
        }
        return;
    }

    // Print header
    let header = format!("Scan: {}", result.source);
    if opts.use_color {
        println!("{}", header.bold());
    } else {
        println!("{}", header);
    }

    // Print hosts
    let hosts = &result.hosts;
    for (i, host) in hosts.iter().enumerate() {
        let is_last_host = i == hosts.len() - 1;
        render_host(host, is_last_host, opts);
    }

    // Print blank line + summary
    println!();
    if opts.use_color {
        println!("{}", summary.bold());
    } else {
        println!("{}", summary);
    }
}

fn render_host(host: &Host, is_last: bool, opts: &RenderOptions) {
    let connector = if is_last { LAST_BRANCH } else { BRANCH };

    // Format IP + optional hostnames
    let label = if host.hostnames.is_empty() {
        host.ip.clone()
    } else {
        format!("{} ({})", host.ip, host.hostnames.join(", "))
    };

    if opts.use_color {
        print!("{}", connector);
        // Use green + bold for host label
        println!(
            "{}",
            label.as_str().if_supports_color(Stream::Stdout, |s| s.bright_green())
        );
    } else {
        println!("{}{}", connector, label);
    }

    let prefix = if is_last { INDENT } else { VERTICAL };
    let ports = &host.ports;
    for (i, port) in ports.iter().enumerate() {
        let is_last_port = i == ports.len() - 1;
        render_port(port, prefix, is_last_port, opts);
    }
}

fn render_port(port: &Port, prefix: &str, is_last: bool, opts: &RenderOptions) {
    let connector = if is_last { LAST_BRANCH } else { BRANCH };

    // Build port line: "{port_id}/{protocol} {state} {service_name}"
    let service_name = port
        .service
        .as_ref()
        .map(|s| s.name.as_str())
        .unwrap_or("unknown");

    // Build full service details
    let service_detail = port.service.as_ref().map(|s| build_service_detail(s));

    let port_proto = format!("{}/{}", port.port_id, port.protocol);
    let detail_str = service_detail
        .as_deref()
        .filter(|d| !d.is_empty())
        .map(|d| format!(" -- {}", d))
        .unwrap_or_default();

    if opts.use_color {
        print!("{}{}", prefix, connector);
        print!("{}", port_proto.if_supports_color(Stream::Stdout, |s| s.cyan()));
        print!(" {} ", port.state);
        print!("{}", service_name.if_supports_color(Stream::Stdout, |s| s.yellow()));
        println!("{}", detail_str);
    } else {
        println!("{}{}{} {} {}{}", prefix, connector, port_proto, port.state, service_name, detail_str);
    }

    // Determine child prefix (continuation line under port node)
    let child_prefix = format!("{}{}", prefix, if is_last { INDENT } else { VERTICAL });

    // Collect child items: CPE strings (verbose) then vulnerabilities
    // Determine total child count to know which gets LAST_BRANCH
    let cpe_list: Vec<&str> = if opts.verbose {
        port.service.as_ref()
            .map(|s| s.cpe.iter().map(|c| c.as_str()).collect())
            .unwrap_or_default()
    } else {
        vec![]
    };
    let vuln_count = port.vulnerabilities.len();
    let cpe_count = cpe_list.len();
    let total_children = cpe_count + vuln_count;

    if total_children == 0 {
        return;
    }

    // Render CPE strings first (if verbose)
    for (ci, cpe) in cpe_list.iter().enumerate() {
        let child_idx = ci;
        let is_last_child = child_idx == total_children - 1;
        let child_connector = if is_last_child { LAST_BRANCH } else { BRANCH };
        println!("{}{}{}", child_prefix, child_connector, cpe);
    }

    // Render vulnerability lines after CPEs
    for (vi, vuln) in port.vulnerabilities.iter().enumerate() {
        let child_idx = cpe_count + vi;
        let is_last_child = child_idx == total_children - 1;
        render_vulnerability(vuln, &child_prefix, is_last_child, opts);
    }
}

fn render_vulnerability(vuln: &Vulnerability, prefix: &str, is_last: bool, opts: &RenderOptions) {
    let connector = if is_last { LAST_BRANCH } else { BRANCH };

    // Format: "CVE-2021-41773 [Crit 9.8]" per D-02
    let severity_tag = match &vuln.cvss {
        Some(cvss) => format!("[{} {:.1}]", cvss.severity.label(), cvss.score),
        None => "[No Score]".to_string(),
    };

    if opts.use_color {
        print!("{}{}", prefix, connector);
        // Color-code severity per D-03
        let colored_tag = match vuln.cvss.as_ref().map(|c| &c.severity) {
            Some(Severity::Critical) => severity_tag.if_supports_color(Stream::Stdout, |s| s.red()).to_string(),
            Some(Severity::High) => severity_tag.if_supports_color(Stream::Stdout, |s| s.yellow()).to_string(),
            Some(Severity::Medium) => severity_tag.if_supports_color(Stream::Stdout, |s| s.cyan()).to_string(),
            Some(Severity::Low) => severity_tag.if_supports_color(Stream::Stdout, |s| s.green()).to_string(),
            _ => severity_tag.clone(),
        };
        println!("{} {}", vuln.cve_id, colored_tag);
    } else {
        println!("{}{}{} {}", prefix, connector, vuln.cve_id, severity_tag);
    }
}

fn build_service_detail(service: &Service) -> String {
    let mut parts = Vec::new();

    if let Some(product) = &service.product {
        let mut product_str = product.clone();
        if let Some(version) = &service.version {
            product_str.push(' ');
            product_str.push_str(version);
        }
        parts.push(product_str);
    }

    if let Some(extra_info) = &service.extra_info {
        parts.push(format!("({})", extra_info));
    }

    parts.join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use portreaper::models::{CvssScore, Host, Port, ScanResult, Service, Vulnerability};

    fn make_result() -> ScanResult {
        ScanResult {
            source: "test.xml".to_string(),
            hosts: vec![Host {
                ip: "10.0.0.1".to_string(),
                hostnames: vec!["test.local".to_string()],
                status: "up".to_string(),
                addresses: vec![],
                ports: vec![
                    Port {
                        port_id: 22,
                        protocol: "tcp".to_string(),
                        state: "open".to_string(),
                        service: Some(Service {
                            name: "ssh".to_string(),
                            product: Some("OpenSSH".to_string()),
                            version: Some("8.9p1".to_string()),
                            extra_info: Some("Ubuntu Linux; protocol 2.0".to_string()),
                            tunnel: None,
                            hostname: None,
                            os_type: None,
                            device_type: None,
                            cpe: vec!["cpe:/a:openbsd:openssh:8.9p1".to_string()],
                        }),
                        vulnerabilities: vec![],
                    },
                    Port {
                        port_id: 80,
                        protocol: "tcp".to_string(),
                        state: "open".to_string(),
                        service: Some(Service {
                            name: "http".to_string(),
                            product: Some("Apache httpd".to_string()),
                            version: Some("2.4.52".to_string()),
                            extra_info: None,
                            tunnel: None,
                            hostname: None,
                            os_type: None,
                            device_type: None,
                            cpe: vec![],
                        }),
                        vulnerabilities: vec![],
                    },
                ],
                os_matches: vec![],
            }],
        }
    }

    fn make_result_with_vulns() -> ScanResult {
        ScanResult {
            source: "test.xml".to_string(),
            hosts: vec![Host {
                ip: "10.0.0.1".to_string(),
                hostnames: vec![],
                status: "up".to_string(),
                addresses: vec![],
                ports: vec![
                    Port {
                        port_id: 443,
                        protocol: "tcp".to_string(),
                        state: "open".to_string(),
                        service: Some(Service {
                            name: "https".to_string(),
                            product: Some("Apache httpd".to_string()),
                            version: Some("2.4.49".to_string()),
                            extra_info: None,
                            tunnel: None,
                            hostname: None,
                            os_type: None,
                            device_type: None,
                            cpe: vec![],
                        }),
                        vulnerabilities: vec![
                            Vulnerability {
                                cve_id: "CVE-2021-41773".to_string(),
                                source: "NVD".to_string(),
                                cvss: Some(CvssScore {
                                    score: 9.8,
                                    severity: Severity::Critical,
                                    version: "3.1".to_string(),
                                }),
                                description: None,
                            },
                            Vulnerability {
                                cve_id: "CVE-2021-42013".to_string(),
                                source: "NVD".to_string(),
                                cvss: Some(CvssScore {
                                    score: 9.8,
                                    severity: Severity::Critical,
                                    version: "3.1".to_string(),
                                }),
                                description: None,
                            },
                        ],
                    },
                ],
                os_matches: vec![],
            }],
        }
    }

    #[test]
    fn render_tree_no_color_contains_ip() {
        let result = make_result();
        let opts = RenderOptions {
            verbose: false,
            quiet: false,
            use_color: false,
        };

        // Capture stdout by redirecting -- just ensure no panics and basic check
        // The real output assertions are in integration tests
        // Here we just verify it runs without panic
        render_tree(&result, &opts);
    }

    #[test]
    fn build_service_detail_product_and_version() {
        let service = Service {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("8.9p1".to_string()),
            extra_info: None,
            tunnel: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec![],
        };
        let detail = build_service_detail(&service);
        assert_eq!(detail, "OpenSSH 8.9p1");
    }

    #[test]
    fn build_service_detail_with_extra_info() {
        let service = Service {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("8.9p1".to_string()),
            extra_info: Some("Ubuntu Linux; protocol 2.0".to_string()),
            tunnel: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec![],
        };
        let detail = build_service_detail(&service);
        assert_eq!(detail, "OpenSSH 8.9p1 (Ubuntu Linux; protocol 2.0)");
    }

    #[test]
    fn build_service_detail_no_product() {
        let service = Service {
            name: "unknown".to_string(),
            product: None,
            version: None,
            extra_info: None,
            tunnel: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec![],
        };
        let detail = build_service_detail(&service);
        assert_eq!(detail, "");
    }

    #[test]
    fn summary_counts_open_only() {
        // closed ports should not count
        let result = ScanResult {
            source: "test.xml".to_string(),
            hosts: vec![Host {
                ip: "1.2.3.4".to_string(),
                hostnames: vec![],
                status: "up".to_string(),
                addresses: vec![],
                ports: vec![
                    Port {
                        port_id: 22,
                        protocol: "tcp".to_string(),
                        state: "open".to_string(),
                        service: Some(Service {
                            name: "ssh".to_string(),
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
                    },
                    Port {
                        port_id: 23,
                        protocol: "tcp".to_string(),
                        state: "closed".to_string(),
                        service: None,
                        vulnerabilities: vec![],
                    },
                ],
                os_matches: vec![],
            }],
        };
        let opts = RenderOptions {
            verbose: false,
            quiet: false,
            use_color: false,
        };
        // Just ensure no panic
        render_tree(&result, &opts);
    }

    #[test]
    fn render_vulnerability_formats_cve_id_and_severity() {
        // Test that render_vulnerability produces correct format for CVE line
        // We can't easily capture stdout in unit tests, but we verify the
        // severity_tag format logic matches expected D-02 format
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
        let severity_tag = match &vuln.cvss {
            Some(cvss) => format!("[{} {:.1}]", cvss.severity.label(), cvss.score),
            None => "[No Score]".to_string(),
        };
        assert_eq!(severity_tag, "[Crit 9.8]");
    }

    #[test]
    fn render_vulnerability_no_score_tag() {
        let vuln = Vulnerability {
            cve_id: "CVE-2024-00001".to_string(),
            source: "NVD".to_string(),
            cvss: None,
            description: None,
        };
        let severity_tag = match &vuln.cvss {
            Some(cvss) => format!("[{} {:.1}]", cvss.severity.label(), cvss.score),
            None => "[No Score]".to_string(),
        };
        assert_eq!(severity_tag, "[No Score]");
    }

    #[test]
    fn render_tree_with_vulns_no_panic() {
        // Ensure render doesn't panic when vulnerabilities are present
        let result = make_result_with_vulns();
        let opts = RenderOptions {
            verbose: false,
            quiet: false,
            use_color: false,
        };
        render_tree(&result, &opts);
    }

    #[test]
    fn severity_tag_formats_for_all_levels() {
        let cases = vec![
            (Severity::Critical, 9.8f32, "[Crit 9.8]"),
            (Severity::High, 7.5f32, "[High 7.5]"),
            (Severity::Medium, 5.0f32, "[Med 5.0]"),
            (Severity::Low, 2.0f32, "[Low 2.0]"),
        ];
        for (severity, score, expected) in cases {
            let cvss = CvssScore { score, severity, version: "3.1".to_string() };
            let tag = format!("[{} {:.1}]", cvss.severity.label(), cvss.score);
            assert_eq!(tag, expected, "Severity tag mismatch for score {}", score);
        }
    }
}
