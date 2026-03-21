use portreaper::parser::text::parse_text;

const SCAN_BASIC_TXT: &str = include_str!("fixtures/scan_basic.txt");

#[test]
fn text_basic_parses_one_host() {
    let result = parse_text(SCAN_BASIC_TXT, "scan_basic.txt").expect("parse failed");
    assert_eq!(result.hosts.len(), 1);
    assert_eq!(result.hosts[0].ip, "192.168.1.1");
}

#[test]
fn text_basic_has_three_ports() {
    let result = parse_text(SCAN_BASIC_TXT, "scan_basic.txt").expect("parse failed");
    let ports = &result.hosts[0].ports;
    assert_eq!(ports.len(), 3, "expected 3 ports, got {}", ports.len());
    let port_ids: Vec<u16> = ports.iter().map(|p| p.port_id).collect();
    assert!(port_ids.contains(&22), "port 22 missing");
    assert!(port_ids.contains(&80), "port 80 missing");
    assert!(port_ids.contains(&443), "port 443 missing");
}

#[test]
fn text_basic_port22_service_name() {
    let result = parse_text(SCAN_BASIC_TXT, "scan_basic.txt").expect("parse failed");
    let port22 = result.hosts[0]
        .ports
        .iter()
        .find(|p| p.port_id == 22)
        .expect("port 22 not found");
    let svc = port22.service.as_ref().expect("service missing on port 22");
    assert_eq!(svc.name, "ssh");
}

#[test]
fn text_basic_port22_version_info() {
    let result = parse_text(SCAN_BASIC_TXT, "scan_basic.txt").expect("parse failed");
    let port22 = result.hosts[0]
        .ports
        .iter()
        .find(|p| p.port_id == 22)
        .expect("port 22 not found");
    let svc = port22.service.as_ref().expect("service missing on port 22");
    // In text format, version info goes into the product field
    let product = svc.product.as_deref().unwrap_or("");
    assert!(
        product.contains("OpenSSH"),
        "expected version containing 'OpenSSH', got {:?}",
        svc.product
    );
}

#[test]
fn text_empty_input_produces_no_hosts_no_panic() {
    let result = parse_text("", "empty.txt").expect("parse failed on empty input");
    assert_eq!(result.hosts.len(), 0);
}

#[test]
fn text_malformed_lines_skipped_no_panic() {
    let content = "Starting Nmap 7.94\nNmap scan report for 10.0.0.1\nHost is up.\ngarbage line here !!!\n22/tcp open ssh\nNmap done: 1 IP\n";
    let result = parse_text(content, "malformed.txt").expect("parse should not fail");
    // Should still find the host
    assert_eq!(result.hosts.len(), 1);
}
