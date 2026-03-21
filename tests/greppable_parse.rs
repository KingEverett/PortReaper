use portreaper::parser::greppable::parse_greppable;

const SCAN_BASIC_GREP: &str = include_str!("fixtures/scan_basic.grep");

#[test]
fn grep_basic_parses_one_host() {
    let result = parse_greppable(SCAN_BASIC_GREP, "scan_basic.grep").expect("parse failed");
    assert_eq!(result.hosts.len(), 1);
    assert_eq!(result.hosts[0].ip, "192.168.1.1");
}

#[test]
fn grep_basic_has_three_ports() {
    let result = parse_greppable(SCAN_BASIC_GREP, "scan_basic.grep").expect("parse failed");
    let ports = &result.hosts[0].ports;
    assert_eq!(ports.len(), 3, "expected 3 ports, got {}", ports.len());
    let port_ids: Vec<u16> = ports.iter().map(|p| p.port_id).collect();
    assert!(port_ids.contains(&22), "port 22 missing");
    assert!(port_ids.contains(&80), "port 80 missing");
    assert!(port_ids.contains(&443), "port 443 missing");
}

#[test]
fn grep_basic_port80_service_name() {
    let result = parse_greppable(SCAN_BASIC_GREP, "scan_basic.grep").expect("parse failed");
    let port80 = result.hosts[0]
        .ports
        .iter()
        .find(|p| p.port_id == 80)
        .expect("port 80 not found");
    let svc = port80.service.as_ref().expect("service missing on port 80");
    assert_eq!(svc.name, "http");
}

#[test]
fn grep_comment_lines_skipped() {
    let content = "# Nmap 7.94 scan\n# Another comment\nHost: 10.0.0.1 ()\tStatus: Up\nHost: 10.0.0.1 ()\tPorts: 22/open/tcp//ssh//OpenSSH 8.9p1/\n";
    let result = parse_greppable(content, "test.grep").expect("parse failed");
    assert_eq!(result.hosts.len(), 1);
    assert_eq!(result.hosts[0].ip, "10.0.0.1");
}

#[test]
fn grep_malformed_lines_skipped_no_panic() {
    let content = "# Nmap 7.94\nHost: 192.168.1.1 ()\tStatus: Up\nHost: 192.168.1.1 ()\tPorts: not_valid_port_data\n";
    let result = parse_greppable(content, "malformed.grep").expect("parse should not fail");
    // Host should still be parsed, just no ports from malformed data
    assert_eq!(result.hosts.len(), 1);
}
