use thiserror::Error;

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
}
