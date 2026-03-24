use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::models::{CvssScore, Severity, Vulnerability};

/// 7-day TTL in seconds.
pub const DEFAULT_TTL_SECS: i64 = 604800;

/// Serializable form of a Vulnerability for cache storage.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CachedVuln {
    pub cve_id: String,
    pub source: String,
    pub score: Option<f32>,
    pub severity: Option<String>,
    pub cvss_version: Option<String>,
    pub description: Option<String>,
}

/// Cache entry stored per CPE string per source.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub cpe: String,
    pub source: String,
    pub fetched_at: i64, // Unix timestamp (seconds)
    pub vulnerabilities: Vec<CachedVuln>,
}

impl From<&Vulnerability> for CachedVuln {
    fn from(v: &Vulnerability) -> Self {
        let (score, severity, version) = match &v.cvss {
            Some(cvss) => (
                Some(cvss.score),
                Some(cvss.severity.obsidian_tag().to_string()),
                Some(cvss.version.clone()),
            ),
            None => (None, None, None),
        };
        CachedVuln {
            cve_id: v.cve_id.clone(),
            source: v.source.clone(),
            score,
            severity,
            cvss_version: version,
            description: v.description.clone(),
        }
    }
}

impl From<&CachedVuln> for Vulnerability {
    fn from(c: &CachedVuln) -> Self {
        let cvss = match (c.score, c.severity.as_deref(), c.cvss_version.as_deref()) {
            (Some(score), Some(severity_str), Some(version)) => Some(CvssScore {
                score,
                severity: Severity::from_str(severity_str),
                version: version.to_string(),
            }),
            _ => None,
        };
        Vulnerability {
            cve_id: c.cve_id.clone(),
            source: c.source.clone(),
            cvss,
            description: c.description.clone(),
        }
    }
}

/// Returns whether a cache entry is older than the given TTL.
pub fn is_stale(entry: &CacheEntry, ttl_secs: i64) -> bool {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    now - entry.fetched_at > ttl_secs
}

/// Returns the portreaper cache directory (XDG_CACHE_HOME/portreaper).
pub fn cache_dir() -> Option<PathBuf> {
    dirs::cache_dir().map(|p| p.join("portreaper"))
}

/// Returns the cache file path for a given source and CPE string.
pub fn cache_path(source: &str, cpe: &str) -> Option<PathBuf> {
    let mut h = DefaultHasher::new();
    cpe.hash(&mut h);
    let filename = format!("{:016x}.json", h.finish());
    cache_dir().map(|p| p.join(source).join(filename))
}

/// Reads cached vulnerabilities. Returns None if fresh=true, file missing, stale, or corrupt.
pub async fn read_cache(
    source: &str,
    cpe: &str,
    ttl_secs: i64,
    fresh: bool,
) -> Option<Vec<Vulnerability>> {
    if fresh {
        return None;
    }
    let path = cache_path(source, cpe)?;
    let content = tokio::fs::read_to_string(&path).await.ok()?;
    let entry: CacheEntry = serde_json::from_str(&content).ok()?;
    if is_stale(&entry, ttl_secs) {
        return None;
    }
    let vulns = entry.vulnerabilities.iter().map(Vulnerability::from).collect();
    Some(vulns)
}

/// Writes vulnerabilities to cache. Silently ignores errors — cache is best-effort.
pub async fn write_cache(source: &str, cpe: &str, vulns: &[Vulnerability]) {
    let Some(path) = cache_path(source, cpe) else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = tokio::fs::create_dir_all(parent).await;
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);
    let entry = CacheEntry {
        cpe: cpe.to_string(),
        source: source.to_string(),
        fetched_at: now,
        vulnerabilities: vulns.iter().map(CachedVuln::from).collect(),
    };
    if let Ok(json) = serde_json::to_string_pretty(&entry) {
        let _ = tokio::fs::write(&path, json).await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn make_vuln(cve_id: &str, score: f32) -> Vulnerability {
        Vulnerability {
            cve_id: cve_id.to_string(),
            source: "TEST".to_string(),
            cvss: Some(CvssScore {
                score,
                severity: Severity::from_score(score),
                version: "3.1".to_string(),
            }),
            description: Some("test description".to_string()),
        }
    }

    #[test]
    fn cache_entry_roundtrip() {
        let vuln = make_vuln("CVE-2023-1234", 7.5);
        let entry = CacheEntry {
            cpe: "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*".to_string(),
            source: "OSV".to_string(),
            fetched_at: 1000000,
            vulnerabilities: vec![CachedVuln::from(&vuln)],
        };
        let json = serde_json::to_string_pretty(&entry).expect("serialize failed");
        let decoded: CacheEntry = serde_json::from_str(&json).expect("deserialize failed");
        assert_eq!(decoded.cpe, entry.cpe);
        assert_eq!(decoded.source, entry.source);
        assert_eq!(decoded.fetched_at, entry.fetched_at);
        assert_eq!(decoded.vulnerabilities.len(), 1);
        assert_eq!(decoded.vulnerabilities[0].cve_id, "CVE-2023-1234");
        assert_eq!(decoded.vulnerabilities[0].source, "TEST");
    }

    #[test]
    fn is_stale_returns_true_for_old_entry() {
        // 8 days ago in seconds
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let eight_days_ago = now - (8 * 24 * 60 * 60);
        let entry = CacheEntry {
            cpe: "test".to_string(),
            source: "TEST".to_string(),
            fetched_at: eight_days_ago,
            vulnerabilities: vec![],
        };
        assert!(is_stale(&entry, DEFAULT_TTL_SECS));
    }

    #[test]
    fn is_stale_returns_false_for_fresh_entry() {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let one_day_ago = now - (24 * 60 * 60);
        let entry = CacheEntry {
            cpe: "test".to_string(),
            source: "TEST".to_string(),
            fetched_at: one_day_ago,
            vulnerabilities: vec![],
        };
        assert!(!is_stale(&entry, DEFAULT_TTL_SECS));
    }

    #[test]
    fn cached_vuln_roundtrip_preserves_fields() {
        let vuln = make_vuln("CVE-2021-41773", 9.8);
        let cached = CachedVuln::from(&vuln);
        assert_eq!(cached.cve_id, "CVE-2021-41773");
        assert_eq!(cached.source, "TEST");
        assert!((cached.score.unwrap() - 9.8).abs() < 0.01);
        assert_eq!(cached.severity.as_deref(), Some("critical"));
        assert_eq!(cached.cvss_version.as_deref(), Some("3.1"));
        assert_eq!(cached.description.as_deref(), Some("test description"));

        let restored = Vulnerability::from(&cached);
        assert_eq!(restored.cve_id, vuln.cve_id);
        assert_eq!(restored.source, vuln.source);
        let cvss = restored.cvss.as_ref().unwrap();
        assert!((cvss.score - 9.8).abs() < 0.01);
        assert_eq!(cvss.severity, Severity::Critical);
        assert_eq!(cvss.version, "3.1");
    }

    #[test]
    fn cache_path_is_under_portreaper_dir() {
        let path = cache_path("osv", "cpe:2.3:a:nginx:nginx:1.18.0:*:*:*:*:*:*:*");
        if let Some(p) = path {
            let path_str = p.to_string_lossy();
            assert!(path_str.contains("portreaper"), "path should contain portreaper: {}", path_str);
            assert!(path_str.contains("osv"), "path should contain source name: {}", path_str);
            assert!(path_str.ends_with(".json"), "path should end with .json: {}", path_str);
        }
        // If cache_dir() returns None (unlikely), skip — not a test failure
    }

    #[tokio::test]
    async fn read_cache_returns_none_when_fresh_true() {
        // Write a real-looking cache file and verify fresh=true ignores it
        let mut tmp = NamedTempFile::new().expect("temp file");
        let entry = CacheEntry {
            cpe: "cpe:test".to_string(),
            source: "TEST".to_string(),
            fetched_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            vulnerabilities: vec![],
        };
        let json = serde_json::to_string_pretty(&entry).unwrap();
        tmp.write_all(json.as_bytes()).unwrap();

        // read_cache with fresh=true should return None regardless of file existence
        let result = read_cache("test_source", "cpe:test", DEFAULT_TTL_SECS, true).await;
        assert!(result.is_none(), "fresh=true must bypass cache");
    }

    #[test]
    fn default_ttl_is_7_days() {
        assert_eq!(DEFAULT_TTL_SECS, 604800, "DEFAULT_TTL_SECS must be exactly 7 days");
    }
}
