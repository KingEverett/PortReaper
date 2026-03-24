// Frontmatter serde structs — implemented in Task 2
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
