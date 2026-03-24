/// Exploit record from ExploitDB/SearchSploit.
#[derive(Debug, Clone)]
pub struct Exploit {
    pub title: String,
    pub edb_id: String,
    pub exploit_type: String, // "remote", "local", "dos", etc.
    pub platform: String,
    pub path: String,           // local filesystem path to exploit file
    pub cve_refs: Vec<String>,  // CVE IDs parsed from Codes field
    pub verified: bool,
    pub date_published: String,
}

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
    pub vulnerabilities: Vec<Vulnerability>,
    pub exploits: Vec<Exploit>,
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

#[derive(Debug, Clone, PartialEq)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
    None,
}

impl Severity {
    pub fn from_score(score: f32) -> Self {
        match score {
            s if s >= 9.0 => Self::Critical,
            s if s >= 7.0 => Self::High,
            s if s >= 4.0 => Self::Medium,
            s if s > 0.0 => Self::Low,
            _ => Self::None,
        }
    }

    pub fn from_str(s: &str) -> Self {
        match s.to_ascii_uppercase().as_str() {
            "CRITICAL" => Self::Critical,
            "HIGH" => Self::High,
            "MEDIUM" => Self::Medium,
            "LOW" => Self::Low,
            _ => Self::None,
        }
    }

    pub fn label(&self) -> &'static str {
        match self {
            Self::Critical => "Crit",
            Self::High => "High",
            Self::Medium => "Med",
            Self::Low => "Low",
            Self::None => "None",
        }
    }

    /// Lowercase tag string for Obsidian frontmatter tags.
    /// Distinct from label() which returns short display labels ("Crit", "High", etc.).
    pub fn obsidian_tag(&self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::None => "none",
        }
    }
}

#[derive(Debug, Clone)]
pub struct CvssScore {
    pub score: f32,
    pub severity: Severity,
    pub version: String, // "2.0", "3.0", "3.1", "4.0"
}

#[derive(Debug, Clone)]
pub struct Vulnerability {
    pub cve_id: String,
    pub source: String, // "NVD", "CVE.org"
    pub cvss: Option<CvssScore>,
    pub description: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_obsidian_tag_critical() {
        assert_eq!(Severity::Critical.obsidian_tag(), "critical");
    }

    #[test]
    fn severity_obsidian_tag_high() {
        assert_eq!(Severity::High.obsidian_tag(), "high");
    }

    #[test]
    fn severity_obsidian_tag_medium() {
        assert_eq!(Severity::Medium.obsidian_tag(), "medium");
    }

    #[test]
    fn severity_obsidian_tag_low() {
        assert_eq!(Severity::Low.obsidian_tag(), "low");
    }

    #[test]
    fn severity_obsidian_tag_none() {
        assert_eq!(Severity::None.obsidian_tag(), "none");
    }

    #[test]
    fn severity_from_score_critical() {
        assert_eq!(Severity::from_score(9.8), Severity::Critical);
        assert_eq!(Severity::from_score(9.0), Severity::Critical);
    }

    #[test]
    fn severity_from_score_high() {
        assert_eq!(Severity::from_score(7.5), Severity::High);
        assert_eq!(Severity::from_score(7.0), Severity::High);
    }

    #[test]
    fn severity_from_score_medium() {
        assert_eq!(Severity::from_score(4.0), Severity::Medium);
        assert_eq!(Severity::from_score(5.5), Severity::Medium);
    }

    #[test]
    fn severity_from_score_low() {
        assert_eq!(Severity::from_score(2.0), Severity::Low);
        assert_eq!(Severity::from_score(0.1), Severity::Low);
    }

    #[test]
    fn severity_from_score_none() {
        assert_eq!(Severity::from_score(0.0), Severity::None);
    }

    #[test]
    fn severity_from_str_variants() {
        assert_eq!(Severity::from_str("CRITICAL"), Severity::Critical);
        assert_eq!(Severity::from_str("HIGH"), Severity::High);
        assert_eq!(Severity::from_str("MEDIUM"), Severity::Medium);
        assert_eq!(Severity::from_str("LOW"), Severity::Low);
        assert_eq!(Severity::from_str("NONE"), Severity::None);
    }

    #[test]
    fn severity_label() {
        assert_eq!(Severity::Critical.label(), "Crit");
        assert_eq!(Severity::High.label(), "High");
        assert_eq!(Severity::Medium.label(), "Med");
        assert_eq!(Severity::Low.label(), "Low");
        assert_eq!(Severity::None.label(), "None");
    }

    #[test]
    fn vulnerability_can_be_constructed() {
        let vuln = Vulnerability {
            cve_id: "CVE-2021-41773".to_string(),
            source: "NVD".to_string(),
            cvss: Some(CvssScore {
                score: 9.8,
                severity: Severity::Critical,
                version: "3.1".to_string(),
            }),
            description: Some("Path traversal and RCE".to_string()),
        };
        assert_eq!(vuln.cve_id, "CVE-2021-41773");
        assert_eq!(vuln.source, "NVD");
    }

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

    #[test]
    fn exploit_struct_can_be_constructed_with_all_fields() {
        let exploit = Exploit {
            title: "OpenSSH 7.7 - Username Enumeration".to_string(),
            edb_id: "45939".to_string(),
            exploit_type: "remote".to_string(),
            platform: "linux".to_string(),
            path: "/usr/share/exploitdb/exploits/linux/remote/45939.py".to_string(),
            cve_refs: vec!["CVE-2018-15473".to_string()],
            verified: false,
            date_published: "2018-09-26".to_string(),
        };
        assert_eq!(exploit.edb_id, "45939");
        assert_eq!(exploit.exploit_type, "remote");
        assert!(!exploit.verified);
        assert_eq!(exploit.cve_refs.len(), 1);
    }

    #[test]
    fn port_exploits_field_defaults_to_empty_vec() {
        let port = Port {
            port_id: 22,
            protocol: "tcp".to_string(),
            state: "open".to_string(),
            service: None,
            vulnerabilities: vec![],
            exploits: vec![],
        };
        assert!(port.exploits.is_empty(), "Port.exploits should default to empty");
    }
}
