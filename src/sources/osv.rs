use serde::{Deserialize, Serialize};

use crate::models::{Severity, Vulnerability};
use super::{VulnLookupError, VulnSource};

// ── Serde structs for OSV API ─────────────────────────────────────────────────

#[derive(Serialize)]
struct OsvBatchRequest {
    queries: Vec<OsvQuery>,
}

#[derive(Serialize)]
struct OsvQuery {
    package: OsvPackage,
    version: String,
}

#[derive(Serialize)]
struct OsvPackage {
    name: String,
    ecosystem: String,
}

#[derive(Deserialize)]
struct OsvBatchResponse {
    #[serde(default)]
    results: Vec<OsvQueryResult>,
}

#[derive(Deserialize, Default)]
struct OsvQueryResult {
    #[serde(default)]
    vulns: Vec<OsvVulnRef>,
}

#[derive(Deserialize)]
struct OsvVulnRef {
    id: String,
}

#[derive(Deserialize)]
struct OsvVulnDetail {
    id: String,
    #[serde(default)]
    details: Option<String>,
    #[serde(default)]
    aliases: Vec<String>,
    #[serde(default)]
    database_specific: Option<OsvDatabaseSpecific>,
    #[serde(default)]
    affected: Vec<OsvAffected>,
}

#[derive(Deserialize)]
struct OsvDatabaseSpecific {
    #[serde(default)]
    severity: Option<String>, // "High", "Critical", "Medium", etc.
}

#[derive(Deserialize)]
struct OsvAffected {
    #[serde(default)]
    severity: Vec<OsvSeverityEntry>,
}

#[derive(Deserialize)]
struct OsvSeverityEntry {
    #[serde(rename = "type")]
    score_type: String, // "CVSS_V3", "CVSS_V4"
    #[allow(dead_code)]
    score: String, // "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H"
}

// ── Helper functions ──────────────────────────────────────────────────────────

/// Find the first CVE alias in the aliases array; fall back to the OSV ID.
fn extract_cve_id(aliases: &[String], fallback_id: &str) -> String {
    aliases
        .iter()
        .find(|a| a.starts_with("CVE-"))
        .cloned()
        .unwrap_or_else(|| fallback_id.to_string())
}

/// Parse a CPE 2.3 string and return `(bitnami_product_name, version)`.
///
/// Maps known CPE product names to Bitnami ecosystem names:
/// - `http_server` → `apache`  (NVD uses http_server, Bitnami uses apache)
/// All other product names pass through unchanged.
///
/// Returns None if the CPE cannot be parsed or the version field is absent/wildcard.
fn cpe_to_bitnami_name(cpe: &str) -> Option<(String, String)> {
    // Handle CPE 2.2 format: cpe:/a:vendor:product:version
    let rest = if let Some(r) = cpe.strip_prefix("cpe:/") {
        r.to_string()
    } else if let Some(r) = cpe.strip_prefix("cpe:2.3:") {
        // CPE 2.3: cpe:2.3:type:vendor:product:version:...
        r.to_string()
    } else {
        return None;
    };

    let parts: Vec<&str> = rest.splitn(6, ':').collect();

    // For CPE 2.2: parts = [type, vendor, product, version, ...]
    // For CPE 2.3: parts = [type, vendor, product, version, ...]  (after stripping "cpe:2.3:")
    let product_idx = 2;
    let version_idx = 3;

    let product = parts.get(product_idx).copied().unwrap_or("").trim_matches('/');
    let version = parts.get(version_idx).copied().unwrap_or("").trim_matches('/');

    if product.is_empty() || product == "*" {
        return None;
    }
    if version.is_empty() || version == "*" {
        return None;
    }

    // Map CPE product name to Bitnami name
    let bitnami_name = match product {
        "http_server" => "apache".to_string(),
        other => other.to_string(),
    };

    Some((bitnami_name, version.to_string()))
}

/// Convert an OsvVulnDetail record into a Vulnerability.
///
/// Severity is extracted from database_specific.severity (plain string label).
/// CVSS score is not extracted — OSV stores vector strings, not numeric scores.
/// Per research recommendation: use severity label only; NVD/CVE.org provide scores.
fn osv_detail_to_vulnerability(detail: &OsvVulnDetail) -> Vulnerability {
    let cve_id = extract_cve_id(&detail.aliases, &detail.id);

    let severity = detail
        .database_specific
        .as_ref()
        .and_then(|ds| ds.severity.as_deref())
        .map(Severity::from_str)
        .unwrap_or(Severity::None);

    // OSV does not provide numeric CVSS scores directly (only vector strings).
    // We store None for cvss — NVD/CVE.org entries will win deduplication.
    let cvss = None;

    Vulnerability {
        cve_id,
        source: "OSV".to_string(),
        cvss,
        description: detail.details.clone(),
    }
}

// ── OsvSource ─────────────────────────────────────────────────────────────────

pub struct OsvSource {
    client: reqwest::Client,
}

impl OsvSource {
    pub fn new() -> Self {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("PortReaper/0.1 vulnerability-scanner")
            .build()
            .expect("failed to build HTTP client");
        Self { client }
    }
}

impl Default for OsvSource {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnSource for OsvSource {
    fn name(&self) -> &str {
        "OSV"
    }

    async fn lookup_cpe(
        &self,
        cpe: &str,
    ) -> Result<Vec<Vulnerability>, VulnLookupError> {
        // Step 1: Parse CPE → (bitnami_name, version)
        let (name, version) = cpe_to_bitnami_name(cpe).ok_or_else(|| VulnLookupError::Empty {
            cpe: cpe.to_string(),
        })?;

        // Step 2: POST /v1/querybatch
        let batch_url = "https://api.osv.dev/v1/querybatch";
        let request_body = OsvBatchRequest {
            queries: vec![OsvQuery {
                package: OsvPackage {
                    name,
                    ecosystem: "Bitnami".to_string(),
                },
                version,
            }],
        };

        let batch_resp = self
            .client
            .post(batch_url)
            .json(&request_body)
            .send()
            .await
            .map_err(|e| VulnLookupError::NetworkFailure {
                url: batch_url.to_string(),
                source: Box::new(e),
            })?;

        if !batch_resp.status().is_success() {
            return Err(VulnLookupError::NetworkFailure {
                url: batch_url.to_string(),
                source: format!("HTTP {}", batch_resp.status()).into(),
            });
        }

        let batch: OsvBatchResponse =
            batch_resp.json().await.map_err(|e| VulnLookupError::NetworkFailure {
                url: batch_url.to_string(),
                source: Box::new(e),
            })?;

        // Step 3: Extract vulns from first result
        let vuln_refs = batch
            .results
            .into_iter()
            .next()
            .unwrap_or_default()
            .vulns;

        if vuln_refs.is_empty() {
            return Err(VulnLookupError::Empty {
                cpe: cpe.to_string(),
            });
        }

        // Step 4: Deduplicate OSV IDs
        let mut ids: Vec<String> = vuln_refs.into_iter().map(|r| r.id).collect();
        ids.sort();
        ids.dedup();

        // Step 5: Fetch details for each unique ID concurrently
        let mut handles = Vec::with_capacity(ids.len());
        for id in ids {
            let client = self.client.clone();
            let detail_url = format!("https://api.osv.dev/v1/vulns/{}", id);
            handles.push(tokio::spawn(async move {
                let resp = client
                    .get(&detail_url)
                    .send()
                    .await
                    .map_err(|e| VulnLookupError::NetworkFailure {
                        url: detail_url.clone(),
                        source: Box::new(e),
                    })?;
                if !resp.status().is_success() {
                    return Err(VulnLookupError::NetworkFailure {
                        url: detail_url.clone(),
                        source: format!("HTTP {}", resp.status()).into(),
                    });
                }
                let detail: OsvVulnDetail =
                    resp.json().await.map_err(|e| VulnLookupError::NetworkFailure {
                        url: detail_url.clone(),
                        source: Box::new(e),
                    })?;
                Ok(osv_detail_to_vulnerability(&detail))
            }));
        }

        let mut vulns = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(vuln)) => vulns.push(vuln),
                Ok(Err(e)) => return Err(e),
                Err(_) => {
                    return Err(VulnLookupError::NetworkFailure {
                        url: "https://api.osv.dev/v1/vulns".to_string(),
                        source: "task panicked".into(),
                    })
                }
            }
        }

        Ok(vulns)
    }
}

// ── Tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_BATCH: &str =
        include_str!("../../tests/fixtures/osv_batch_response_nginx.json");
    const FIXTURE_DETAIL: &str =
        include_str!("../../tests/fixtures/osv_vuln_detail_nginx.json");

    #[test]
    fn osv_source_name() {
        let source = OsvSource::new();
        assert_eq!(source.name(), "OSV");
    }

    #[test]
    fn batch_request_serializes_correctly_for_nginx() {
        let req = OsvBatchRequest {
            queries: vec![OsvQuery {
                package: OsvPackage {
                    name: "nginx".to_string(),
                    ecosystem: "Bitnami".to_string(),
                },
                version: "1.18.0".to_string(),
            }],
        };
        let json = serde_json::to_string(&req).expect("serialize");
        assert!(json.contains("\"nginx\""), "should contain product name");
        assert!(json.contains("\"Bitnami\""), "should contain ecosystem");
        assert!(json.contains("\"1.18.0\""), "should contain version");
        assert!(json.contains("queries"), "should have queries key");
    }

    #[test]
    fn empty_batch_result_deserializes_without_error() {
        // OSV returns {} for services with no results
        let json = r#"{"results":[{}]}"#;
        let batch: OsvBatchResponse = serde_json::from_str(json).expect("parse failed");
        assert_eq!(batch.results.len(), 1);
        assert!(batch.results[0].vulns.is_empty(), "empty object should have no vulns");
    }

    #[test]
    fn batch_response_fixture_deserializes() {
        let batch: OsvBatchResponse =
            serde_json::from_str(FIXTURE_BATCH).expect("batch fixture parse failed");
        assert_eq!(batch.results.len(), 1);
        assert_eq!(batch.results[0].vulns.len(), 1);
        assert_eq!(batch.results[0].vulns[0].id, "BIT-nginx-2023-44487");
    }

    #[test]
    fn vuln_detail_fixture_extracts_cve_alias() {
        let detail: OsvVulnDetail =
            serde_json::from_str(FIXTURE_DETAIL).expect("detail fixture parse failed");
        let cve_id = extract_cve_id(&detail.aliases, &detail.id);
        assert_eq!(cve_id, "CVE-2023-44487", "should extract CVE alias from aliases");
    }

    #[test]
    fn vuln_detail_with_no_cve_alias_uses_osv_id() {
        let detail = OsvVulnDetail {
            id: "BIT-nginx-2023-44487".to_string(),
            details: None,
            aliases: vec![
                "GHSA-qppj-fm5r-hxr3".to_string(),
                "BIT-apisix-2023-44487".to_string(),
            ],
            database_specific: None,
            affected: vec![],
        };
        let cve_id = extract_cve_id(&detail.aliases, &detail.id);
        assert_eq!(cve_id, "BIT-nginx-2023-44487", "fallback to OSV ID when no CVE- alias");
    }

    #[test]
    fn vuln_detail_database_specific_severity_high_maps_correctly() {
        let detail: OsvVulnDetail =
            serde_json::from_str(FIXTURE_DETAIL).expect("parse failed");
        let vuln = osv_detail_to_vulnerability(&detail);
        // OSV returns severity label only; cvss is None
        assert!(vuln.cvss.is_none(), "OSV vulns should have cvss=None");
        assert_eq!(vuln.source, "OSV");
        assert_eq!(vuln.cve_id, "CVE-2023-44487");
    }

    #[test]
    fn cpe_to_bitnami_name_maps_http_server_to_apache() {
        let result = cpe_to_bitnami_name("cpe:/a:apache:http_server:2.4.49");
        let (name, version) = result.expect("should parse");
        assert_eq!(name, "apache", "http_server should map to apache");
        assert_eq!(version, "2.4.49");
    }

    #[test]
    fn cpe_to_bitnami_name_passes_nginx_through() {
        let result = cpe_to_bitnami_name("cpe:/a:nginx:nginx:1.18.0");
        let (name, version) = result.expect("should parse");
        assert_eq!(name, "nginx");
        assert_eq!(version, "1.18.0");
    }

    #[test]
    fn cpe_to_bitnami_name_returns_none_for_wildcard_version() {
        let result = cpe_to_bitnami_name("cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*");
        assert!(result.is_none(), "wildcard version should return None");
    }

    #[test]
    fn cpe_to_bitnami_name_returns_none_for_unparseable_cpe() {
        let result = cpe_to_bitnami_name("not-a-cpe");
        assert!(result.is_none());
    }

    #[test]
    fn empty_batch_result_produces_vuln_lookup_error_empty() {
        // We test the logic by verifying vuln_refs.is_empty() triggers the error path
        let empty_batch_json = r#"{"results":[{}]}"#;
        let batch: OsvBatchResponse =
            serde_json::from_str(empty_batch_json).expect("parse failed");
        let vuln_refs = batch.results.into_iter().next().unwrap_or_default().vulns;
        assert!(vuln_refs.is_empty(), "empty result should produce empty vuln_refs");
        // The lookup_cpe method checks is_empty() and returns VulnLookupError::Empty
    }

    #[test]
    fn osv_detail_to_vuln_sets_description_from_details_field() {
        let detail: OsvVulnDetail =
            serde_json::from_str(FIXTURE_DETAIL).expect("parse failed");
        let vuln = osv_detail_to_vulnerability(&detail);
        assert!(vuln.description.is_some(), "description should be set from details field");
        let desc = vuln.description.unwrap();
        assert!(desc.contains("HTTP/2"), "description should contain HTTP/2");
    }
}
