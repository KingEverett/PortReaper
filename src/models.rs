/// Normalized scan result -- parser-agnostic representation.
/// All parsers (XML, text, greppable) produce this same structure.

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub source: String, // filename or "stdin"
    pub hosts: Vec<Host>,
}

#[derive(Debug, Clone)]
pub struct Host {
    pub ip: String,
    pub hostnames: Vec<String>,
    pub status: String, // "up", "down"
    pub addresses: Vec<Address>,
    pub ports: Vec<Port>,
    pub os_matches: Vec<String>, // OS detection results, optional
}

#[derive(Debug, Clone)]
pub struct Address {
    pub addr: String,
    pub addr_type: String, // "ipv4", "ipv6", "mac"
}

#[derive(Debug, Clone)]
pub struct Port {
    pub port_id: u16,
    pub protocol: String, // "tcp", "udp"
    pub state: String,    // "open", "filtered", "closed"
    pub service: Option<Service>,
}

#[derive(Debug, Clone)]
pub struct Service {
    pub name: String,
    pub product: Option<String>,
    pub version: Option<String>,
    pub extra_info: Option<String>,
    pub tunnel: Option<String>,
    pub hostname: Option<String>,
    pub os_type: Option<String>,
    pub device_type: Option<String>,
    pub cpe: Vec<String>, // CPE URIs like "cpe:/a:openbsd:openssh:8.9p1"
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_result_with_empty_hosts() {
        let result = ScanResult {
            source: "test.xml".to_string(),
            hosts: vec![],
        };
        assert_eq!(result.hosts.len(), 0);
        assert_eq!(result.source, "test.xml");
    }

    #[test]
    fn host_with_all_option_fields_none() {
        let host = Host {
            ip: "192.168.1.1".to_string(),
            hostnames: vec![],
            status: "up".to_string(),
            addresses: vec![],
            ports: vec![],
            os_matches: vec![],
        };
        assert_eq!(host.ip, "192.168.1.1");
        assert!(host.ports.is_empty());
    }

    #[test]
    fn service_product_version_extrainfo_are_option() {
        let service = Service {
            name: "http".to_string(),
            product: None,
            version: None,
            extra_info: None,
            tunnel: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec![],
        };
        assert!(service.product.is_none());
        assert!(service.version.is_none());
        assert!(service.extra_info.is_none());
    }

    #[test]
    fn service_with_all_fields_present() {
        let service = Service {
            name: "ssh".to_string(),
            product: Some("OpenSSH".to_string()),
            version: Some("8.9p1".to_string()),
            extra_info: Some("Ubuntu Linux; protocol 2.0".to_string()),
            tunnel: None,
            hostname: None,
            os_type: None,
            device_type: None,
            cpe: vec!["cpe:/a:openbsd:openssh:8.9p1".to_string()],
        };
        assert_eq!(service.product.as_deref(), Some("OpenSSH"));
        assert_eq!(service.version.as_deref(), Some("8.9p1"));
        assert_eq!(service.cpe.len(), 1);
    }
}
