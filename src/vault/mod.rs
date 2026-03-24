pub mod frontmatter;
pub mod graph_config;
pub mod writer;

use std::path::Path;

use crate::models::ScanResult;

/// Errors that can occur during vault generation.
#[derive(Debug, thiserror::Error)]
pub enum VaultError {
    #[error("failed to write vault file {path}: {source}")]
    WriteError { path: String, source: std::io::Error },
    #[error("failed to create vault directory {path}: {source}")]
    DirError { path: String, source: std::io::Error },
    #[error("YAML serialization failed: {0}")]
    YamlError(String),
}

/// Statistics from vault generation for reporting.
pub struct VaultStats {
    pub hosts: usize,
    pub services: usize,
    pub cves: usize,
    pub technologies: usize,
}

/// Derive a scan label from the source filename.
/// Format: `{YYYY-MM-DD}_{sanitized_source}` per D-03 fallback.
/// ScanResult currently lacks nmap metadata fields so date + filename is the correct path.
pub fn derive_scan_label(source: &str) -> String {
    let date = chrono::Local::now().format("%Y-%m-%d").to_string();
    let sanitized = crate::util::filename::sanitize_filename(source);
    format!("{date}_{sanitized}")
}

/// Generate the vault structure from a scan result.
/// Stub implementation — full implementation in Plan 02.
pub fn generate_vault(
    _scan: &ScanResult,
    _vault_path: &Path,
    _scan_label: &str,
) -> Result<VaultStats, VaultError> {
    Ok(VaultStats {
        hosts: 0,
        services: 0,
        cves: 0,
        technologies: 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_scan_label_has_date_prefix() {
        let label = derive_scan_label("scan_192.168.1.0.xml");
        // Should start with date in YYYY-MM-DD format
        let parts: Vec<&str> = label.splitn(2, '_').collect();
        assert_eq!(parts.len(), 2);
        // Date portion should be 10 chars: YYYY-MM-DD
        assert_eq!(parts[0].len(), 10);
        assert!(parts[0].contains('-'));
    }

    #[test]
    fn derive_scan_label_sanitizes_slashes() {
        let label = derive_scan_label("192.168.1.0/24.xml");
        assert!(!label.contains('/'));
    }

    #[test]
    fn vault_error_write_error_wraps_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = VaultError::WriteError {
            path: "/some/path".to_string(),
            source: io_err,
        };
        let display = err.to_string();
        assert!(display.contains("failed to write vault file"));
        assert!(display.contains("/some/path"));
    }

    #[test]
    fn vault_error_dir_error_wraps_io_error() {
        let io_err = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "permission denied");
        let err = VaultError::DirError {
            path: "/some/dir".to_string(),
            source: io_err,
        };
        let display = err.to_string();
        assert!(display.contains("failed to create vault directory"));
        assert!(display.contains("/some/dir"));
    }

    #[test]
    fn generate_vault_stub_returns_zero_stats() {
        use std::path::Path;
        let scan = ScanResult {
            source: "test.xml".to_string(),
            hosts: vec![],
        };
        let result = generate_vault(&scan, Path::new("/tmp"), "test-label").unwrap();
        assert_eq!(result.hosts, 0);
        assert_eq!(result.services, 0);
        assert_eq!(result.cves, 0);
        assert_eq!(result.technologies, 0);
    }
}
