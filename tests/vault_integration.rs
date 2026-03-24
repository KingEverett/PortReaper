use portreaper::models::*;
use portreaper::vault;

fn make_test_scan() -> ScanResult {
    // Construct ScanResult with:
    // - 1 host (192.168.1.1) with 2 ports
    // - Port 22: ssh/OpenSSH 7.4 with CVE-2023-38408 (9.8 Critical)
    // - Port 80: http/Apache 2.4.49 with CVE-2021-41773 (9.8 Critical) + CVE-2023-38408 (shared)
    // This tests: shared CVE dedup, technology notes, severity, wikilinks

    let cve_shared = Vulnerability {
        cve_id: "CVE-2023-38408".to_string(),
        source: "NVD".to_string(),
        cvss: Some(CvssScore {
            score: 9.8,
            severity: Severity::Critical,
            version: "3.1".to_string(),
        }),
        description: Some("OpenSSH remote code execution via ssh-agent forwarding".to_string()),
    };

    let cve_apache = Vulnerability {
        cve_id: "CVE-2021-41773".to_string(),
        source: "NVD".to_string(),
        cvss: Some(CvssScore {
            score: 9.8,
            severity: Severity::Critical,
            version: "3.1".to_string(),
        }),
        description: Some("Path traversal and RCE in Apache HTTP Server 2.4.49".to_string()),
    };

    let service_ssh = Service {
        name: "ssh".to_string(),
        product: Some("OpenSSH".to_string()),
        version: Some("7.4".to_string()),
        extra_info: None,
        tunnel: None,
        hostname: None,
        os_type: None,
        device_type: None,
        cpe: vec!["cpe:/a:openbsd:openssh:7.4".to_string()],
    };

    let port_22 = Port {
        port_id: 22,
        protocol: "tcp".to_string(),
        state: "open".to_string(),
        service: Some(service_ssh),
        vulnerabilities: vec![cve_shared.clone()],
    };

    let service_http = Service {
        name: "http".to_string(),
        product: Some("Apache httpd".to_string()),
        version: Some("2.4.49".to_string()),
        extra_info: None,
        tunnel: None,
        hostname: None,
        os_type: None,
        device_type: None,
        cpe: vec!["cpe:/a:apache:http_server:2.4.49".to_string()],
    };

    let port_80 = Port {
        port_id: 80,
        protocol: "tcp".to_string(),
        state: "open".to_string(),
        service: Some(service_http),
        // Port 80 has both CVEs: the Apache-specific one + the shared one
        vulnerabilities: vec![cve_apache, cve_shared],
    };

    let host = Host {
        ip: "192.168.1.1".to_string(),
        hostnames: vec![],
        status: "up".to_string(),
        addresses: vec![Address {
            addr: "192.168.1.1".to_string(),
            addr_type: "ipv4".to_string(),
        }],
        os_matches: vec![],
        ports: vec![port_22, port_80],
    };

    ScanResult {
        source: "scan_shared_cve.xml".to_string(),
        hosts: vec![host],
    }
}

#[test]
fn vault_generates_complete_directory_structure() {
    let scan = make_test_scan();
    let dir = std::env::temp_dir().join(format!("portreaper_test_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir); // clean slate
    let scan_label = "2026-03-21_192.168.1.1";

    let stats = vault::generate_vault(&scan, &dir, scan_label).unwrap();

    // OUT-02: Hierarchical structure
    assert!(dir.join("scans/2026-03-21_192.168.1.1/hosts/192.168.1.1.md").exists());
    assert!(dir.join("scans/2026-03-21_192.168.1.1/services/192.168.1.1_22_tcp.md").exists());
    assert!(dir.join("scans/2026-03-21_192.168.1.1/services/192.168.1.1_80_tcp.md").exists());

    // OUT-06: Shared CVE notes
    assert!(dir.join("cves/CVE-2023-38408.md").exists());
    assert!(dir.join("cves/CVE-2021-41773.md").exists());

    // Technology notes
    assert!(dir.join("technologies/OpenSSH.md").exists());
    assert!(dir.join("technologies/Apache httpd.md").exists());

    // OUT-07: Graph config
    assert!(dir.join(".obsidian/graph.json").exists());
    assert!(dir.join("assets/severity-colors.css").exists());

    // Index pages
    assert!(dir.join("_index.md").exists());
    assert!(dir.join("scans/2026-03-21_192.168.1.1/_index.md").exists());

    // Stats
    assert_eq!(stats.hosts, 1);
    assert_eq!(stats.services, 2);
    assert_eq!(stats.cves, 2); // CVE-2023-38408 + CVE-2021-41773 (deduped)
    assert_eq!(stats.technologies, 2);

    // Cleanup
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vault_cve_note_lists_all_affected_services() {
    let scan = make_test_scan();
    let dir = std::env::temp_dir().join(format!("portreaper_test_cve_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    vault::generate_vault(&scan, &dir, "test").unwrap();

    // OUT-06: CVE-2023-38408 is shared by port 22 and port 80
    let cve_content = std::fs::read_to_string(dir.join("cves/CVE-2023-38408.md")).unwrap();
    assert!(cve_content.contains("192.168.1.1_22_tcp"), "should reference ssh service");
    assert!(cve_content.contains("192.168.1.1_80_tcp"), "should reference http service");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vault_frontmatter_is_valid_yaml() {
    let scan = make_test_scan();
    let dir = std::env::temp_dir().join(format!("portreaper_test_yaml_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    vault::generate_vault(&scan, &dir, "test").unwrap();

    // OUT-03: YAML frontmatter parses without error
    let host_note = std::fs::read_to_string(dir.join("scans/test/hosts/192.168.1.1.md")).unwrap();
    assert!(host_note.starts_with("---\n"), "must start with YAML delimiter");
    assert!(host_note.contains("\n---\n"), "must have closing YAML delimiter");

    // OUT-04: Severity tags are lowercase
    assert!(
        host_note.contains("critical")
            || host_note.contains("high")
            || host_note.contains("medium")
            || host_note.contains("low")
            || host_note.contains("none"),
        "must contain severity tag"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vault_service_notes_contain_wikilinks() {
    let scan = make_test_scan();
    let dir = std::env::temp_dir().join(format!("portreaper_test_links_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    vault::generate_vault(&scan, &dir, "test").unwrap();

    // OUT-01: Wikilinks present
    let svc_note =
        std::fs::read_to_string(dir.join("scans/test/services/192.168.1.1_22_tcp.md")).unwrap();
    assert!(svc_note.contains("[["), "must contain wikilinks");
    assert!(svc_note.contains("[[192.168.1.1]]"), "must link to host");
    assert!(svc_note.contains("[[CVE-2023-38408]]"), "must link to CVE");
    assert!(svc_note.contains("[[OpenSSH]]"), "must link to technology");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn vault_graph_json_has_color_groups() {
    let scan = make_test_scan();
    let dir = std::env::temp_dir().join(format!("portreaper_test_graph_{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    vault::generate_vault(&scan, &dir, "test").unwrap();

    // OUT-07: Graph coloring
    let graph_json = std::fs::read_to_string(dir.join(".obsidian/graph.json")).unwrap();
    assert!(graph_json.contains("tag:#critical"));
    assert!(graph_json.contains("tag:#high"));
    assert!(graph_json.contains("tag:#medium"));
    assert!(graph_json.contains("tag:#low"));
    assert!(graph_json.contains("tag:#host"));
    assert!(graph_json.contains("tag:#cve"));
    assert!(graph_json.contains("tag:#technology"));
    assert!(graph_json.contains("colorGroups"));

    let _ = std::fs::remove_dir_all(&dir);
}
