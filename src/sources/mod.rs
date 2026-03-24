use thiserror::Error;

pub mod cve_org;
pub mod nvd;
pub mod osv;
pub mod searchsploit;

#[derive(Debug, Error)]
pub enum VulnLookupError {
    #[error("no results found for {cpe}")]
    Empty { cpe: String },

    #[error("rate limited by source: retry after {retry_after_secs}s")]
    RateLimited { retry_after_secs: u64 },

    #[error("network failure querying {url}: {source}")]
    NetworkFailure {
        url: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },
}

/// Pluggable vulnerability data source.
/// Implementations added in Phase 2 (NVD, CVE.org).
pub trait VulnSource: Send + Sync {
    /// Human-readable name for this source (e.g., "NVD", "CVE.org")
    fn name(&self) -> &str;
    /// Look up vulnerabilities for a given CPE string (2.2 or 2.3 format).
    fn lookup_cpe(
        &self,
        cpe: &str,
    ) -> impl std::future::Future<Output = Result<Vec<crate::models::Vulnerability>, VulnLookupError>>
           + Send;
}

/// Error type for exploit lookup operations.
#[derive(Debug, Error)]
pub enum ExploitLookupError {
    #[error("binary not found: {binary}")]
    BinaryNotFound { binary: String },

    #[error("empty results for {query}")]
    Empty { query: String },

    #[error("subprocess failed: {msg}")]
    SubprocessFailed { msg: String },

    #[error("json parse error: {msg}")]
    ParseError { msg: String },
}

/// Pluggable exploit data source (e.g., SearchSploit).
/// Distinct from VulnSource because exploits are not CVEs.
pub trait ExploitSource: Send + Sync {
    /// Human-readable name for this source (e.g., "SearchSploit")
    fn name(&self) -> &str;
    /// Search for exploits by product name and version string.
    fn search_product(
        &self,
        product: &str,
        version: &str,
    ) -> impl std::future::Future<Output = Result<Vec<crate::models::Exploit>, ExploitLookupError>>
           + Send;
}

/// Convert nmap CPE 2.2 URI binding to NVD API v2 CPE 2.3 formatted string binding.
/// "cpe:/a:openbsd:openssh:8.9p1" → "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"
/// If input is already CPE 2.3 format (starts with "cpe:2.3"), returns it unchanged.
pub fn cpe22_to_cpe23(cpe: &str) -> String {
    if let Some(rest) = cpe.strip_prefix("cpe:/") {
        let parts: Vec<&str> = rest.splitn(4, ':').collect();
        let part = parts.first().copied().unwrap_or("*");
        let vendor = parts.get(1).copied().unwrap_or("*");
        let product = parts.get(2).copied().unwrap_or("*");
        let version = parts.get(3).copied().unwrap_or("*");
        format!("cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*")
    } else {
        cpe.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::error::Error;
    use std::fmt;

    #[test]
    fn vuln_lookup_error_empty_variant() {
        let e = VulnLookupError::Empty {
            cpe: "cpe:/a:apache:http_server:2.4.52".to_string(),
        };
        let msg = format!("{}", e);
        assert!(msg.contains("no results found"));
        assert!(msg.contains("cpe:/a:apache:http_server:2.4.52"));
    }

    #[test]
    fn vuln_lookup_error_rate_limited_variant() {
        let e = VulnLookupError::RateLimited {
            retry_after_secs: 60,
        };
        let msg = format!("{}", e);
        assert!(msg.contains("rate limited"));
        assert!(msg.contains("60"));
    }

    #[test]
    fn vuln_lookup_error_network_failure_variant() {
        #[derive(Debug)]
        struct MockErr;
        impl fmt::Display for MockErr {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                write!(f, "connection refused")
            }
        }
        impl Error for MockErr {}

        let e = VulnLookupError::NetworkFailure {
            url: "https://nvd.nist.gov/api".to_string(),
            source: Box::new(MockErr),
        };
        let msg = format!("{}", e);
        assert!(msg.contains("network failure"));
        assert!(msg.contains("https://nvd.nist.gov/api"));
    }

    #[test]
    fn vuln_lookup_error_implements_error_trait() {
        // Verify all variants implement std::error::Error (Display + Debug)
        let e = VulnLookupError::Empty {
            cpe: "cpe:/test".to_string(),
        };
        // Can be used as &dyn Error
        let _: &dyn Error = &e;
        // Debug works
        let dbg = format!("{:?}", e);
        assert!(dbg.contains("Empty"));
    }

    #[test]
    fn cpe22_to_cpe23_openssh() {
        let result = cpe22_to_cpe23("cpe:/a:openbsd:openssh:8.9p1");
        assert_eq!(result, "cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*");
    }

    #[test]
    fn cpe22_to_cpe23_already_v23_passthrough() {
        let input = "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*";
        let result = cpe22_to_cpe23(input);
        assert_eq!(result, input);
    }

    #[test]
    fn cpe22_to_cpe23_no_version() {
        let result = cpe22_to_cpe23("cpe:/a:vendor:product");
        assert_eq!(result, "cpe:2.3:a:vendor:product:*:*:*:*:*:*:*:*");
    }

    #[test]
    fn vuln_lookup_error_variants_are_distinct() {
        // All three variants can be constructed and are distinct
        let empty = VulnLookupError::Empty {
            cpe: "cpe:/test".to_string(),
        };
        let rate_limited = VulnLookupError::RateLimited {
            retry_after_secs: 30,
        };
        // Verify they have different Display messages
        let empty_msg = format!("{}", empty);
        let rate_msg = format!("{}", rate_limited);
        assert_ne!(empty_msg, rate_msg);
    }

    #[test]
    fn exploit_lookup_error_variants_are_distinct() {
        let binary_not_found = ExploitLookupError::BinaryNotFound {
            binary: "searchsploit".to_string(),
        };
        let empty = ExploitLookupError::Empty {
            query: "openssh 7.4".to_string(),
        };
        let subprocess_failed = ExploitLookupError::SubprocessFailed {
            msg: "non-zero exit code".to_string(),
        };
        let parse_error = ExploitLookupError::ParseError {
            msg: "unexpected token".to_string(),
        };

        let msgs: Vec<String> = vec![
            format!("{}", binary_not_found),
            format!("{}", empty),
            format!("{}", subprocess_failed),
            format!("{}", parse_error),
        ];

        // All four should be distinct
        for i in 0..msgs.len() {
            for j in (i + 1)..msgs.len() {
                assert_ne!(msgs[i], msgs[j], "variants {} and {} should differ", i, j);
            }
        }

        // BinaryNotFound should mention the binary name
        assert!(msgs[0].contains("searchsploit"), "BinaryNotFound should mention binary name");
    }
}
