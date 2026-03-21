use portreaper::parser::xml::parse_xml;

const SCAN_BASIC: &str = include_str!("fixtures/scan_basic.xml");
const SCAN_MULTI_HOST: &str = include_str!("fixtures/scan_multi_host.xml");
const SCAN_MINIMAL_SERVICE: &str = include_str!("fixtures/scan_minimal_service.xml");

#[test]
fn xml_basic_parses_one_host() {
    let result = parse_xml(SCAN_BASIC, "scan_basic.xml").expect("parse failed");
    assert_eq!(result.hosts.len(), 1);
    assert_eq!(result.hosts[0].ip, "192.168.1.1");
}

#[test]
fn xml_basic_has_three_ports() {
    let result = parse_xml(SCAN_BASIC, "scan_basic.xml").expect("parse failed");
    assert_eq!(result.hosts[0].ports.len(), 3);
    let port_ids: Vec<u16> = result.hosts[0].ports.iter().map(|p| p.port_id).collect();
    assert!(port_ids.contains(&22));
    assert!(port_ids.contains(&80));
    assert!(port_ids.contains(&443));
}

#[test]
fn xml_basic_port22_service_fields() {
    let result = parse_xml(SCAN_BASIC, "scan_basic.xml").expect("parse failed");
    let port22 = result.hosts[0]
        .ports
        .iter()
        .find(|p| p.port_id == 22)
        .expect("port 22 not found");
    let svc = port22.service.as_ref().expect("service missing");
    assert_eq!(svc.product.as_deref(), Some("OpenSSH"));
    assert_eq!(svc.version.as_deref(), Some("8.9p1"));
    assert_eq!(
        svc.extra_info.as_deref(),
        Some("Ubuntu Linux; protocol 2.0")
    );
}

#[test]
fn xml_basic_port22_cpe_extracted() {
    let result = parse_xml(SCAN_BASIC, "scan_basic.xml").expect("parse failed");
    let port22 = result.hosts[0]
        .ports
        .iter()
        .find(|p| p.port_id == 22)
        .expect("port 22 not found");
    let svc = port22.service.as_ref().expect("service missing");
    assert!(
        svc.cpe.contains(&"cpe:/a:openbsd:openssh:8.9p1".to_string()),
        "expected CPE not found: {:?}",
        svc.cpe
    );
}

#[test]
fn xml_basic_port443_product_version_none() {
    let result = parse_xml(SCAN_BASIC, "scan_basic.xml").expect("parse failed");
    let port443 = result.hosts[0]
        .ports
        .iter()
        .find(|p| p.port_id == 443)
        .expect("port 443 not found");
    let svc = port443.service.as_ref().expect("service missing");
    assert!(
        svc.product.is_none(),
        "expected product=None, got {:?}",
        svc.product
    );
    assert!(
        svc.version.is_none(),
        "expected version=None, got {:?}",
        svc.version
    );
}

#[test]
fn xml_multi_host_parses_three_hosts() {
    let result = parse_xml(SCAN_MULTI_HOST, "scan_multi_host.xml").expect("parse failed");
    assert_eq!(result.hosts.len(), 3, "expected 3 hosts, got {}", result.hosts.len());
    let ips: Vec<&str> = result.hosts.iter().map(|h| h.ip.as_str()).collect();
    assert!(ips.contains(&"192.168.1.1"), "missing 192.168.1.1");
    assert!(ips.contains(&"192.168.1.2"), "missing 192.168.1.2");
    assert!(ips.contains(&"192.168.1.3"), "missing 192.168.1.3");
}

#[test]
fn xml_minimal_service_parses_without_error() {
    let result = parse_xml(SCAN_MINIMAL_SERVICE, "scan_minimal_service.xml").expect("parse failed");
    assert_eq!(result.hosts.len(), 1);
    let port = &result.hosts[0].ports[0];
    let svc = port.service.as_ref().expect("service missing");
    assert_eq!(svc.name, "http-proxy");
    assert!(svc.product.is_none(), "expected product=None for minimal service");
}

#[test]
fn xml_basic_host_has_hostname() {
    let result = parse_xml(SCAN_BASIC, "scan_basic.xml").expect("parse failed");
    let host = &result.hosts[0];
    assert!(
        host.hostnames.contains(&"router.local".to_string()),
        "expected hostname 'router.local', got {:?}",
        host.hostnames
    );
}

#[test]
fn xml_basic_host_has_two_addresses() {
    let result = parse_xml(SCAN_BASIC, "scan_basic.xml").expect("parse failed");
    let host = &result.hosts[0];
    assert_eq!(host.addresses.len(), 2, "expected 2 addresses, got {:?}", host.addresses);
    let has_ipv4 = host.addresses.iter().any(|a| a.addr_type == "ipv4");
    let has_mac = host.addresses.iter().any(|a| a.addr_type == "mac");
    assert!(has_ipv4, "no ipv4 address found");
    assert!(has_mac, "no mac address found");
}
