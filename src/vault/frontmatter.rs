use serde::Serialize;

#[derive(Serialize)]
pub struct HostFrontmatter {
    pub ip: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub hostnames: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    pub highest_severity: String,
    pub tags: Vec<String>,
    pub scan_label: String,
}

#[derive(Serialize)]
pub struct ServiceFrontmatter {
    pub host: String,
    pub port: u16,
    pub protocol: String,
    pub service: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    pub highest_severity: String,
    pub tags: Vec<String>,
    pub scan_label: String,
}

#[derive(Serialize)]
pub struct CveFrontmatter {
    pub cve_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_score: Option<f32>,
    pub severity: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cvss_version: Option<String>,
    pub sources: Vec<String>,
    pub tags: Vec<String>,
    pub first_seen: String,
}

#[derive(Serialize)]
pub struct TechFrontmatter {
    pub product: String,
    pub versions_seen: Vec<String>,
    pub tags: Vec<String>,
    pub first_seen: String,
}

/// Render a complete Obsidian note: YAML frontmatter delimited by --- plus body.
/// Uses serde_yml for safe YAML serialization (never format! for YAML values).
pub fn render_note(frontmatter: &impl Serialize, body: &str) -> Result<String, super::VaultError> {
    let yaml = serde_yml::to_string(frontmatter)
        .map_err(|e| super::VaultError::YamlError(e.to_string()))?;
    Ok(format!("---\n{}---\n\n{}", yaml, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn host_frontmatter_serializes_required_fields() {
        let fm = HostFrontmatter {
            ip: "192.168.1.1".to_string(),
            hostnames: vec!["host.local".to_string()],
            os: Some("Linux 5.15".to_string()),
            highest_severity: "high".to_string(),
            tags: vec!["host".to_string(), "high".to_string()],
            scan_label: "2026-03-24_scan.xml".to_string(),
        };
        let yaml = serde_yml::to_string(&fm).expect("serialize");
        assert!(yaml.contains("ip:"), "yaml should contain ip field");
        assert!(yaml.contains("192.168.1.1"));
        assert!(yaml.contains("hostnames:"));
        assert!(yaml.contains("os:"));
        assert!(yaml.contains("highest_severity:"));
        assert!(yaml.contains("tags:"));
        assert!(yaml.contains("scan_label:"));
    }

    #[test]
    fn service_frontmatter_skips_none_product_and_version() {
        let fm = ServiceFrontmatter {
            host: "192.168.1.1".to_string(),
            port: 80,
            protocol: "tcp".to_string(),
            service: "http".to_string(),
            product: None,
            version: None,
            highest_severity: "none".to_string(),
            tags: vec!["host".to_string()],
            scan_label: "2026-03-24_scan.xml".to_string(),
        };
        let yaml = serde_yml::to_string(&fm).expect("serialize");
        assert!(!yaml.contains("product:"), "None product should be skipped");
        assert!(!yaml.contains("version:"), "None version should be skipped");
        assert!(yaml.contains("host:"));
        assert!(yaml.contains("port:"));
    }

    #[test]
    fn cve_frontmatter_serializes_required_fields() {
        let fm = CveFrontmatter {
            cve_id: "CVE-2021-41773".to_string(),
            cvss_score: Some(9.8),
            severity: "critical".to_string(),
            cvss_version: Some("3.1".to_string()),
            sources: vec!["NVD".to_string()],
            tags: vec!["cve".to_string(), "critical".to_string()],
            first_seen: "2026-03-24".to_string(),
        };
        let yaml = serde_yml::to_string(&fm).expect("serialize");
        assert!(yaml.contains("cve_id:"));
        assert!(yaml.contains("CVE-2021-41773"));
        assert!(yaml.contains("cvss_score:"));
        assert!(yaml.contains("severity:"));
        assert!(yaml.contains("sources:"));
        assert!(yaml.contains("tags:"));
        assert!(yaml.contains("first_seen:"));
    }

    #[test]
    fn tech_frontmatter_serializes_required_fields() {
        let fm = TechFrontmatter {
            product: "OpenSSH".to_string(),
            versions_seen: vec!["8.9p1".to_string(), "9.0".to_string()],
            tags: vec!["technology".to_string()],
            first_seen: "2026-03-24".to_string(),
        };
        let yaml = serde_yml::to_string(&fm).expect("serialize");
        assert!(yaml.contains("product:"));
        assert!(yaml.contains("OpenSSH"));
        assert!(yaml.contains("versions_seen:"));
        assert!(yaml.contains("tags:"));
        assert!(yaml.contains("first_seen:"));
    }

    #[test]
    fn render_note_wraps_yaml_in_delimiters_and_appends_body() {
        let fm = TechFrontmatter {
            product: "nginx".to_string(),
            versions_seen: vec!["1.24.0".to_string()],
            tags: vec!["technology".to_string()],
            first_seen: "2026-03-24".to_string(),
        };
        let body = "## Description\n\nThis is nginx.";
        let note = render_note(&fm, body).expect("render_note");
        assert!(note.starts_with("---\n"), "should start with --- delimiter");
        assert!(note.contains("\n---\n\n"), "should have closing --- delimiter");
        assert!(note.ends_with(body), "should end with body");
    }

    #[test]
    fn frontmatter_with_yaml_special_chars_serializes_safely() {
        // CVE descriptions often contain colons, quotes, and hash characters
        let fm = CveFrontmatter {
            cve_id: "CVE-2021-99999".to_string(),
            cvss_score: None,
            severity: "medium".to_string(),
            cvss_version: None,
            sources: vec!["NVD".to_string()],
            tags: vec!["cve".to_string()],
            first_seen: "2026-03-24: special".to_string(),
        };
        let yaml = serde_yml::to_string(&fm).expect("serialize should not panic with special chars");
        // The YAML should be parseable back
        assert!(!yaml.is_empty());
        assert!(yaml.contains("cve_id:"));
    }
}
