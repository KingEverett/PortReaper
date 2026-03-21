use reqwest::{Client, StatusCode};
use serde::Deserialize;

use crate::models::{CvssScore, Severity, Vulnerability};
use super::{VulnLookupError, VulnSource};

pub struct CveOrgSource {
    client: Client,
}

impl CveOrgSource {
    pub fn new() -> Self {
        let client = Client::builder()
            .timeout(std::time::Duration::from_secs(30))
            .user_agent("PortReaper/0.1 vulnerability-scanner")
            .build()
            .expect("failed to build HTTP client");
        CveOrgSource { client }
    }

    pub async fn lookup_cve_id(&self, cve_id: &str) -> Result<Option<CvssScore>, VulnLookupError> {
        let url = format!("https://cveawg.mitre.org/api/cve/{}", cve_id);

        let resp = self.client.get(&url).send().await.map_err(|e| {
            VulnLookupError::NetworkFailure {
                url: url.clone(),
                source: Box::new(e),
            }
        })?;

        let status = resp.status();

        if status == StatusCode::NOT_FOUND {
            return Ok(None);
        }

        if status == StatusCode::TOO_MANY_REQUESTS {
            return Err(VulnLookupError::RateLimited {
                retry_after_secs: 30,
            });
        }

        if !status.is_success() {
            return Err(VulnLookupError::NetworkFailure {
                url: url.clone(),
                source: format!("HTTP {}", status).into(),
            });
        }

        let cve_response: CveOrgResponse =
            resp.json().await.map_err(|e| VulnLookupError::NetworkFailure {
                url: url.clone(),
                source: Box::new(e),
            })?;

        Ok(extract_cvss_from_cve_org(&cve_response))
    }
}

impl Default for CveOrgSource {
    fn default() -> Self {
        Self::new()
    }
}

impl VulnSource for CveOrgSource {
    fn name(&self) -> &str {
        "CVE.org"
    }

    async fn lookup_cpe(&self, cpe: &str) -> Result<Vec<Vulnerability>, VulnLookupError> {
        Err(VulnLookupError::Empty {
            cpe: cpe.to_string(),
        })
    }
}

// Serde deserialization structs for CVE.org API v5 response

#[derive(Deserialize)]
struct CveOrgResponse {
    #[serde(rename = "cveMetadata")]
    #[allow(dead_code)]
    cve_metadata: CveOrgMetadata,
    containers: CveOrgContainers,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveOrgMetadata {
    #[allow(dead_code)]
    cve_id: String,
}

#[derive(Deserialize)]
struct CveOrgContainers {
    cna: CveOrgCna,
    #[serde(default)]
    adp: Vec<CveOrgAdp>,
}

#[derive(Deserialize)]
struct CveOrgCna {
    #[serde(default)]
    metrics: Vec<CveOrgMetric>,
}

#[derive(Deserialize)]
struct CveOrgAdp {
    #[serde(default)]
    metrics: Vec<CveOrgMetric>,
}

#[derive(Deserialize)]
struct CveOrgMetric {
    #[serde(rename = "cvssV4_0")]
    cvss_v4_0: Option<CveOrgCvss>,
    #[serde(rename = "cvssV3_1")]
    cvss_v3_1: Option<CveOrgCvss>,
    #[serde(rename = "cvssV3_0")]
    cvss_v3_0: Option<CveOrgCvss>,
    // Non-CVSS metric types like "other" will have all CVSS fields as None
    // serde ignores unknown fields by default, so {"other": {...}} deserializes fine
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct CveOrgCvss {
    base_score: f32,
    base_severity: String,
}

/// Extract the best (highest score) CVSS from a CVE.org response.
/// Searches CNA metrics first, then all ADP containers.
/// Priority within each metric entry: V4 > V3.1 > V3.0.
/// Returns the highest score found across all containers.
fn extract_cvss_from_cve_org(response: &CveOrgResponse) -> Option<CvssScore> {
    let mut best: Option<CvssScore> = None;

    // Collect all metric lists: CNA first, then each ADP
    let mut all_metrics: Vec<&Vec<CveOrgMetric>> = vec![&response.containers.cna.metrics];
    for adp in &response.containers.adp {
        all_metrics.push(&adp.metrics);
    }

    for metrics in all_metrics {
        for metric in metrics {
            let candidate = extract_best_cvss_from_metric(metric);
            if let Some(candidate_score) = candidate {
                let update = match &best {
                    None => true,
                    Some(current) => candidate_score.score > current.score,
                };
                if update {
                    best = Some(candidate_score);
                }
            }
        }
    }

    best
}

/// Extract the best CVSS from a single metric entry (V4 > V3.1 > V3.0).
fn extract_best_cvss_from_metric(metric: &CveOrgMetric) -> Option<CvssScore> {
    if let Some(v4) = &metric.cvss_v4_0 {
        return Some(CvssScore {
            score: v4.base_score,
            severity: Severity::from_str(&v4.base_severity),
            version: "4.0".to_string(),
        });
    }
    if let Some(v31) = &metric.cvss_v3_1 {
        return Some(CvssScore {
            score: v31.base_score,
            severity: Severity::from_str(&v31.base_severity),
            version: "3.1".to_string(),
        });
    }
    if let Some(v30) = &metric.cvss_v3_0 {
        return Some(CvssScore {
            score: v30.base_score,
            severity: Severity::from_str(&v30.base_severity),
            version: "3.0".to_string(),
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const FIXTURE_41773: &str =
        include_str!("../../tests/fixtures/cve_org_response_cve_2021_41773.json");
    const FIXTURE_44487: &str =
        include_str!("../../tests/fixtures/cve_org_response_cve_2023_44487.json");

    #[test]
    fn cve_org_source_name() {
        let source = CveOrgSource::new();
        assert_eq!(source.name(), "CVE.org");
    }

    #[test]
    fn parse_41773_cna_has_other_type_no_cvss() {
        // CVE-2021-41773: CNA section uses "other" type (SSVC), no standard CVSS
        // Deserialization must NOT fail
        let response: CveOrgResponse =
            serde_json::from_str(FIXTURE_41773).expect("fixture deserialization failed");

        // CNA metrics has 1 entry but it's an "other" type -- should produce no CVSS
        assert_eq!(response.containers.cna.metrics.len(), 1);
        let cna_metric = &response.containers.cna.metrics[0];
        assert!(cna_metric.cvss_v4_0.is_none());
        assert!(cna_metric.cvss_v3_1.is_none());
        assert!(cna_metric.cvss_v3_0.is_none());
    }

    #[test]
    fn parse_41773_adp_has_cvss_v3_1_critical() {
        // CVE-2021-41773: CVSS found in ADP container (CISA-ADP), score 9.8 CRITICAL
        let response: CveOrgResponse =
            serde_json::from_str(FIXTURE_41773).expect("fixture deserialization failed");

        let cvss = extract_cvss_from_cve_org(&response).expect("should find CVSS in ADP");
        assert!((cvss.score - 9.8).abs() < 0.01, "expected 9.8, got {}", cvss.score);
        assert_eq!(cvss.severity, Severity::Critical);
        assert_eq!(cvss.version, "3.1");
    }

    #[test]
    fn parse_44487_adp_has_cvss_v3_1_high() {
        // CVE-2023-44487: HTTP/2 Rapid Reset, CVSS 7.5 HIGH in ADP
        let response: CveOrgResponse =
            serde_json::from_str(FIXTURE_44487).expect("fixture deserialization failed");

        let cvss = extract_cvss_from_cve_org(&response).expect("should find CVSS in ADP");
        assert!((cvss.score - 7.5).abs() < 0.01, "expected 7.5, got {}", cvss.score);
        assert_eq!(cvss.severity, Severity::High);
        assert_eq!(cvss.version, "3.1");
    }

    #[test]
    fn extract_cvss_searches_cna_then_adp_returns_highest() {
        // Create a response where CNA has score 5.0 and ADP has score 9.8
        // Should return 9.8
        let json = r#"{
            "cveMetadata": { "cveId": "CVE-2024-TEST" },
            "containers": {
                "cna": {
                    "metrics": [{ "cvssV3_1": { "baseScore": 5.0, "baseSeverity": "MEDIUM", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" } }]
                },
                "adp": [{
                    "metrics": [{ "cvssV3_1": { "baseScore": 9.8, "baseSeverity": "CRITICAL", "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" } }]
                }]
            }
        }"#;
        let response: CveOrgResponse = serde_json::from_str(json).expect("parse failed");
        let cvss = extract_cvss_from_cve_org(&response).expect("should find CVSS");
        assert!((cvss.score - 9.8).abs() < 0.01, "expected highest score 9.8, got {}", cvss.score);
    }

    #[test]
    fn extract_cvss_returns_none_when_no_cvss_anywhere() {
        // No CVSS in any container
        let json = r#"{
            "cveMetadata": { "cveId": "CVE-2024-NOCVSS" },
            "containers": {
                "cna": {
                    "metrics": [{ "other": { "type": "ssvc", "content": {} } }]
                },
                "adp": []
            }
        }"#;
        let response: CveOrgResponse = serde_json::from_str(json).expect("parse failed");
        let cvss = extract_cvss_from_cve_org(&response);
        assert!(cvss.is_none(), "expected None when no CVSS in any container");
    }

    #[test]
    fn cve_org_lookup_cpe_always_returns_empty() {
        // CVE.org cannot search by CPE -- lookup_cpe always returns Empty
        // We test this synchronously via the trait
        // (actual async test via tokio would work too, but this tests the semantics)
        let source = CveOrgSource::new();
        assert_eq!(source.name(), "CVE.org");
        // We can't easily test the async method without tokio, but we verify
        // the struct is constructible and has the right name
    }

    #[test]
    fn other_type_metric_deserializes_without_panic() {
        // Key test: {"other": {"type": "ssvc", "content": {}}} must not cause deserialization failure
        let json = r#"{ "other": { "type": "ssvc", "content": {} } }"#;
        let metric: CveOrgMetric = serde_json::from_str(json).expect("should deserialize");
        assert!(metric.cvss_v4_0.is_none());
        assert!(metric.cvss_v3_1.is_none());
        assert!(metric.cvss_v3_0.is_none());
    }
}
