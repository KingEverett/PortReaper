use serde::Deserialize;
use crate::sources::{ExploitLookupError, ExploitSource};

// Private serde structs for JSON deserialization from searchsploit -j output.
#[derive(Deserialize)]
struct SearchSploitOutput {
    #[serde(rename = "RESULTS_EXPLOIT")]
    results_exploit: Vec<SearchSploitEntry>,
}

#[derive(Deserialize)]
struct SearchSploitEntry {
    #[serde(rename = "Title")]
    title: String,
    #[serde(rename = "EDB-ID")]
    edb_id: String,
    #[serde(rename = "Type")]
    exploit_type: String,
    #[serde(rename = "Platform")]
    platform: String,
    #[serde(rename = "Path")]
    path: String,
    #[serde(rename = "Codes")]
    codes: String,
    #[serde(rename = "Verified")]
    verified: String, // "0" or "1"
    #[serde(rename = "Date_Published")]
    date_published: String,
}

/// Extract CVE references from a semicolon-separated Codes field.
/// Filters to only entries starting with "CVE-"; discards OSVDB, BID, etc.
pub fn parse_cve_refs(codes: &str) -> Vec<String> {
    codes
        .split(';')
        .map(|s| s.trim())
        .filter(|s| s.starts_with("CVE-"))
        .map(|s| s.to_string())
        .collect()
}

fn entry_to_exploit(entry: &SearchSploitEntry) -> crate::models::Exploit {
    crate::models::Exploit {
        title: entry.title.clone(),
        edb_id: entry.edb_id.clone(),
        exploit_type: entry.exploit_type.clone(),
        platform: entry.platform.clone(),
        path: entry.path.clone(),
        cve_refs: parse_cve_refs(&entry.codes),
        verified: entry.verified == "1",
        date_published: entry.date_published.clone(),
    }
}

/// An ExploitSource backed by the local `searchsploit` binary.
///
/// Construction via `try_new()` checks if the binary is on PATH.
/// Returns `None` when not found — callers should print a warning and skip.
pub struct SearchSploitSource {
    binary_path: std::path::PathBuf,
}

impl SearchSploitSource {
    /// Returns `Some(source)` if the `searchsploit` binary is found on PATH, `None` otherwise.
    /// Per D-02: caller should print a stderr warning when `None` is returned.
    pub fn try_new() -> Option<Self> {
        let output = std::process::Command::new("searchsploit")
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match output {
            Ok(_) => Some(Self {
                binary_path: std::path::PathBuf::from("searchsploit"),
            }),
            Err(_) => None,
        }
    }

    /// Constructs a `SearchSploitSource` using a custom binary path.
    /// Used in tests to inject a nonexistent or mock binary path.
    #[cfg(test)]
    pub fn with_binary_path(path: std::path::PathBuf) -> Option<Self> {
        // Check if the binary exists at the specified path
        let output = std::process::Command::new(&path)
            .arg("--help")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status();
        match output {
            Ok(_) => Some(Self { binary_path: path }),
            Err(_) => None,
        }
    }
}

impl ExploitSource for SearchSploitSource {
    fn name(&self) -> &str {
        "SearchSploit"
    }

    async fn search_product(
        &self,
        product: &str,
        version: &str,
    ) -> Result<Vec<crate::models::Exploit>, ExploitLookupError> {
        let query = format!("{} {}", product, version);
        let output = tokio::process::Command::new(&self.binary_path)
            .arg("-j")
            .arg(&query)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .output()
            .await
            .map_err(|e| ExploitLookupError::SubprocessFailed {
                msg: format!("failed to run searchsploit: {}", e),
            })?;

        if !output.status.success() {
            return Err(ExploitLookupError::SubprocessFailed {
                msg: format!("searchsploit exited with {}", output.status),
            });
        }

        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: SearchSploitOutput =
            serde_json::from_str(&stdout).map_err(|e| ExploitLookupError::ParseError {
                msg: format!("failed to parse searchsploit JSON: {}", e),
            })?;

        if parsed.results_exploit.is_empty() {
            return Err(ExploitLookupError::Empty { query });
        }

        let exploits: Vec<_> = parsed.results_exploit.iter().map(entry_to_exploit).collect();
        Ok(exploits)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cve_refs_filters_non_cve() {
        let result = parse_cve_refs("CVE-2012-2336;CVE-2012-2311;OSVDB-81633");
        assert_eq!(result, vec!["CVE-2012-2336", "CVE-2012-2311"]);
    }

    #[test]
    fn parse_cve_refs_empty_string() {
        let result = parse_cve_refs("");
        assert!(result.is_empty(), "empty Codes string should produce empty vec");
    }

    #[test]
    fn parse_cve_refs_single_entry_no_semicolons() {
        let result = parse_cve_refs("CVE-2021-41773");
        assert_eq!(result, vec!["CVE-2021-41773"]);
    }

    #[test]
    fn parse_cve_refs_all_non_cve() {
        let result = parse_cve_refs("OSVDB-81633;BID-12345;EDB-40136");
        assert!(result.is_empty(), "all non-CVE codes should produce empty vec");
    }

    #[test]
    fn searchsploit_output_deserialization_from_fixture() {
        let fixture = include_str!("../../tests/fixtures/searchsploit_openssh74.json");
        let output: SearchSploitOutput =
            serde_json::from_str(fixture).expect("fixture should deserialize");
        assert_eq!(
            output.results_exploit.len(),
            2,
            "fixture has 2 exploits"
        );
        assert_eq!(output.results_exploit[0].edb_id, "40136");
        assert_eq!(output.results_exploit[1].edb_id, "45233");
    }

    #[test]
    fn verified_field_mapping() {
        // Verified="1" → verified=true
        let entry_verified = SearchSploitEntry {
            title: "Test".to_string(),
            edb_id: "1".to_string(),
            exploit_type: "remote".to_string(),
            platform: "linux".to_string(),
            path: "/path".to_string(),
            codes: "".to_string(),
            verified: "1".to_string(),
            date_published: "2021-01-01".to_string(),
        };
        let exploit = entry_to_exploit(&entry_verified);
        assert!(exploit.verified, "Verified='1' should map to true");

        // Verified="0" → verified=false
        let entry_unverified = SearchSploitEntry {
            verified: "0".to_string(),
            ..entry_verified
        };
        let exploit = entry_to_exploit(&entry_unverified);
        assert!(!exploit.verified, "Verified='0' should map to false");
    }

    #[test]
    fn empty_results_exploit_deserializes_to_empty_vec() {
        let json = r#"{"SEARCH":"nothing","RESULTS_EXPLOIT":[],"DB_PATH_EXPLOIT":"/usr/share/exploitdb","DB_PATH_SHELLCODE":"/usr/share/exploitdb","RESULTS_SHELLCODE":[]}"#;
        let output: SearchSploitOutput =
            serde_json::from_str(json).expect("empty RESULTS_EXPLOIT should deserialize");
        assert!(
            output.results_exploit.is_empty(),
            "empty RESULTS_EXPLOIT should produce empty vec"
        );
    }

    #[test]
    fn try_new_returns_none_for_nonexistent_binary() {
        // We test try_new() indirectly by verifying with_binary_path returns None
        // for a nonexistent path — same codepath as try_new() when binary not found.
        let result = SearchSploitSource::with_binary_path(
            std::path::PathBuf::from("/nonexistent/path/to/searchsploit_xxxxx"),
        );
        assert!(result.is_none(), "nonexistent binary should return None");
    }

    #[test]
    fn searchsploit_source_name_returns_searchsploit() {
        // Create a source with a dummy path that won't be invoked just for name()
        // We construct directly since we're only testing the name method
        let source = SearchSploitSource {
            binary_path: std::path::PathBuf::from("searchsploit"),
        };
        assert_eq!(source.name(), "SearchSploit");
    }

    #[test]
    fn fixture_exploits_have_correct_cve_refs() {
        let fixture = include_str!("../../tests/fixtures/searchsploit_openssh74.json");
        let output: SearchSploitOutput =
            serde_json::from_str(fixture).expect("fixture should deserialize");

        // First exploit: "CVE-2016-6210;OSVDB-140070" → only CVE-2016-6210
        let exploit0 = entry_to_exploit(&output.results_exploit[0]);
        assert_eq!(exploit0.cve_refs, vec!["CVE-2016-6210"]);
        assert!(exploit0.verified, "first exploit has Verified=1");

        // Second exploit: "CVE-2018-15473" → CVE-2018-15473
        let exploit1 = entry_to_exploit(&output.results_exploit[1]);
        assert_eq!(exploit1.cve_refs, vec!["CVE-2018-15473"]);
        assert!(!exploit1.verified, "second exploit has Verified=0");
    }
}
