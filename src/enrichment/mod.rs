use std::collections::HashMap;
use std::future::Future;
use std::sync::Arc;

use tokio::sync::Semaphore;
use tokio::time::{Duration, sleep};

use crate::models::{Vulnerability, ScanResult};
use crate::sources::{VulnLookupError, VulnSource, ExploitSource, ExploitLookupError};
use crate::sources::nvd::NvdSource;
use crate::sources::cve_org::CveOrgSource;
use crate::sources::osv::OsvSource;
use crate::sources::searchsploit::SearchSploitSource;
use crate::cache;

/// Statistics returned by enrich_scan, summarising what was done.
#[derive(Debug, Default)]
pub struct EnrichmentStats {
    /// Number of services that had CPE strings and were queried.
    pub services_queried: usize,
    /// Number of services skipped due to missing CPE strings.
    pub services_skipped: usize,
    /// Total number of unique CVEs found across all services.
    pub cves_found: usize,
    /// Total number of exploits found across all services.
    pub exploits_found: usize,
    /// Human-readable failure messages, e.g. "NVD: rate limited (3 services affected)".
    pub source_failures: Vec<String>,
    /// Per-source status: (source_name, success). Built at end of enrichment.
    pub source_status: Vec<(String, bool)>,
}

/// Options controlling enrichment behaviour.
pub struct EnrichmentOptions {
    /// Maximum number of concurrent source queries (default: 5).
    pub concurrency: usize,
    /// When true, suppress progress output to stderr.
    pub quiet: bool,
    /// When true, bypass cache and re-fetch all data per D-12.
    pub fresh: bool,
    /// Lowercase source names that are disabled per D-14.
    pub disabled_sources: Vec<String>,
}

impl Default for EnrichmentOptions {
    fn default() -> Self {
        Self {
            concurrency: 5,
            quiet: false,
            fresh: false,
            disabled_sources: vec![],
        }
    }
}

impl EnrichmentOptions {
    /// Returns true if the named source is enabled (not in disabled_sources).
    pub fn source_enabled(&self, name: &str) -> bool {
        !self.disabled_sources.contains(&name.to_lowercase())
    }
}

/// Orchestrate vulnerability enrichment for a complete scan result.
///
/// For every service with CPE strings, queries NVD + OSV for CVEs by CPE, then
/// enriches each found CVE with CVE.org CVSS data. Uses a semaphore to
/// bound concurrency. Applies exponential backoff on rate-limit errors.
/// Deduplicates CVEs by ID, keeping the highest CVSS score.
/// Optionally invokes SearchSploit for exploit lookup.
/// Cache is checked before network calls; results written after fetch.
///
/// Services with no CPE strings are skipped with a warning on stderr.
/// If a source fails for a service, partial results from other services
/// are still collected and returned.
pub async fn enrich_scan(
    scan: &mut ScanResult,
    nvd: Option<Arc<NvdSource>>,
    cve_org: Option<Arc<CveOrgSource>>,
    osv: Option<Arc<OsvSource>>,
    searchsploit: Option<Arc<SearchSploitSource>>,
    opts: &EnrichmentOptions,
) -> EnrichmentStats {
    let mut stats = EnrichmentStats::default();

    // Collect (host_idx, port_idx, port_id, protocol, service_label, cpe_list, product, version)
    // for services with CPEs (or product for searchsploit)
    let mut work_items: Vec<(usize, usize, u16, String, String, Vec<String>, Option<String>, Option<String>)> = Vec::new();

    for (host_idx, host) in scan.hosts.iter().enumerate() {
        for (port_idx, port) in host.ports.iter().enumerate() {
            let service = match &port.service {
                Some(s) => s,
                None => {
                    if !opts.quiet {
                        eprintln!(
                            "Warning: {}/{}: no service info -- skipping vuln lookup",
                            port.port_id, port.protocol
                        );
                    }
                    stats.services_skipped += 1;
                    continue;
                }
            };
            if service.cpe.is_empty() {
                let service_name = &service.name;
                if !opts.quiet {
                    eprintln!(
                        "Warning: {}/{} {}: no CPE -- skipping vuln lookup",
                        port.port_id, port.protocol, service_name
                    );
                }
                stats.services_skipped += 1;
                continue;
            }
            let product_version = format!(
                "{} {}",
                service.product.as_deref().unwrap_or(&service.name),
                service.version.as_deref().unwrap_or("(unknown)")
            );
            work_items.push((
                host_idx,
                port_idx,
                port.port_id,
                port.protocol.clone(),
                product_version,
                service.cpe.clone(),
                service.product.clone(),
                service.version.clone(),
            ));
        }
    }

    let total = work_items.len();
    stats.services_queried = total;

    if total == 0 {
        return stats;
    }

    let semaphore = Arc::new(Semaphore::new(opts.concurrency));
    let fresh = opts.fresh;

    // Track per-source success/failure across all tasks
    let nvd_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let nvd_successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let osv_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let osv_successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cve_org_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let cve_org_successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ss_failures = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let ss_successes = Arc::new(std::sync::atomic::AtomicUsize::new(0));

    // Spawn tasks for each service
    let mut task_handles = Vec::new();
    for (n, (host_idx, port_idx, _port_id, _protocol, product_version, cpe_list, product, version)) in
        work_items.into_iter().enumerate()
    {
        let sem = semaphore.clone();
        let nvd_arc = nvd.clone();
        let cve_org_arc = cve_org.clone();
        let osv_arc = osv.clone();
        let ss_arc = searchsploit.clone();
        let quiet = opts.quiet;

        let nvd_fail_cnt = nvd_failures.clone();
        let nvd_ok_cnt = nvd_successes.clone();
        let osv_fail_cnt = osv_failures.clone();
        let osv_ok_cnt = osv_successes.clone();
        let cve_org_fail_cnt = cve_org_failures.clone();
        let cve_org_ok_cnt = cve_org_successes.clone();
        let ss_fail_cnt = ss_failures.clone();
        let ss_ok_cnt = ss_successes.clone();

        let handle = tokio::spawn(async move {
            let _permit = sem.acquire().await.expect("semaphore closed");

            let pos = n + 1;
            let mut all_vulns: Vec<Vulnerability> = Vec::new();
            let mut failure: Option<String> = None;

            // ── NVD lookup with cache ──────────────────────────────────────────
            if let Some(ref nvd_ref) = nvd_arc {
                for cpe in &cpe_list {
                    // Check cache first
                    if let Some(cached) = cache::read_cache("nvd", cpe, cache::DEFAULT_TTL_SECS, fresh).await {
                        if !quiet {
                            eprintln!(
                                "[{}/{}] NVD (cached): {}... {} CVEs",
                                pos, total, product_version, cached.len()
                            );
                        }
                        nvd_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        all_vulns.extend(cached);
                    } else {
                        let nvd = &**nvd_ref;
                        match with_retry(|| nvd.lookup_cpe(cpe)).await {
                            Ok(vulns) => {
                                cache::write_cache("nvd", cpe, &vulns).await;
                                if !quiet {
                                    eprintln!(
                                        "[{}/{}] NVD: {}... {} CVEs",
                                        pos, total, product_version, vulns.len()
                                    );
                                }
                                nvd_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                all_vulns.extend(vulns);
                            }
                            Err(VulnLookupError::Empty { .. }) => {
                                // No results — not a failure
                                nvd_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                let msg = format!("NVD error for {}: {}", product_version, e);
                                if failure.is_none() {
                                    failure = Some(msg);
                                }
                                nvd_fail_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            }

            // ── OSV lookup with cache ──────────────────────────────────────────
            if let Some(ref osv_ref) = osv_arc {
                for cpe in &cpe_list {
                    if let Some(cached) = cache::read_cache("osv", cpe, cache::DEFAULT_TTL_SECS, fresh).await {
                        if !quiet {
                            eprintln!(
                                "[{}/{}] OSV (cached): {}... {} CVEs",
                                pos, total, product_version, cached.len()
                            );
                        }
                        osv_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        all_vulns.extend(cached);
                    } else {
                        let osv = &**osv_ref;
                        match with_retry(|| osv.lookup_cpe(cpe)).await {
                            Ok(vulns) => {
                                cache::write_cache("osv", cpe, &vulns).await;
                                if !quiet {
                                    eprintln!(
                                        "[{}/{}] OSV: {}... {} CVEs",
                                        pos, total, product_version, vulns.len()
                                    );
                                }
                                osv_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                all_vulns.extend(vulns);
                            }
                            Err(VulnLookupError::Empty { .. }) => {
                                // No results — not a failure
                                osv_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                let msg = format!("OSV error for {}: {}", product_version, e);
                                if failure.is_none() {
                                    failure = Some(msg);
                                }
                                osv_fail_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            }

            // ── CVE.org enrichment (per-CVE, no cache — enriches existing CVEs) ─
            if let Some(ref cve_org_ref) = cve_org_arc {
                if !all_vulns.is_empty() {
                    if !quiet {
                        eprintln!(
                            "[CVE.org] Enriching {} CVEs for {}...",
                            all_vulns.len(),
                            product_version
                        );
                    }
                    let cve_org = &**cve_org_ref;
                    for vuln in &mut all_vulns {
                        match with_retry(|| cve_org.lookup_cve_id(&vuln.cve_id)).await {
                            Ok(Some(cve_org_score)) => {
                                let should_update = match &vuln.cvss {
                                    None => true,
                                    Some(existing) => cve_org_score.score > existing.score,
                                };
                                if should_update {
                                    vuln.cvss = Some(cve_org_score);
                                    vuln.source = "CVE.org".to_string();
                                }
                                cve_org_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Ok(None) | Err(VulnLookupError::Empty { .. }) => {
                                // CVE.org has no record -- keep NVD/OSV data
                                cve_org_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                            Err(e) => {
                                if failure.is_none() {
                                    failure = Some(format!("CVE.org error for {}: {}", vuln.cve_id, e));
                                }
                                cve_org_fail_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            }
                        }
                    }
                }
            }

            // ── Deduplicate vulns from NVD + OSV ──────────────────────────────
            let deduped = dedup_vulnerabilities(all_vulns);

            // ── SearchSploit exploit lookup ────────────────────────────────────
            let mut exploits = Vec::new();
            if let Some(ref ss_ref) = ss_arc {
                if let (Some(prod), Some(ver)) = (&product, &version) {
                    let ss = &**ss_ref;
                    match ss.search_product(prod, ver).await {
                        Ok(found) => {
                            if !quiet {
                                eprintln!(
                                    "[{}/{}] SearchSploit: {} {}... {} exploits",
                                    pos, total, prod, ver, found.len()
                                );
                            }
                            ss_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            exploits = found;
                        }
                        Err(ExploitLookupError::Empty { .. }) => {
                            // No exploits found — not a failure
                            ss_ok_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                        Err(e) => {
                            let msg = format!("SearchSploit error for {} {}: {}", prod, ver, e);
                            if failure.is_none() {
                                failure = Some(msg);
                            }
                            ss_fail_cnt.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        }
                    }
                }
            }

            (host_idx, port_idx, deduped, exploits, failure)
        });
        task_handles.push(handle);
    }

    // Collect results from all tasks
    for handle in task_handles {
        let (host_idx, port_idx, vulns, exploits, failure) = handle.await.expect("task panicked");
        let vuln_count = vulns.len();
        let exploit_count = exploits.len();
        scan.hosts[host_idx].ports[port_idx].vulnerabilities = vulns;
        scan.hosts[host_idx].ports[port_idx].exploits = exploits;
        stats.cves_found += vuln_count;
        stats.exploits_found += exploit_count;
        if let Some(msg) = failure {
            stats.source_failures.push(msg);
        }
    }

    // Build source_status per D-16
    let nvd_ok = nvd_successes.load(std::sync::atomic::Ordering::Relaxed);
    let nvd_fail = nvd_failures.load(std::sync::atomic::Ordering::Relaxed);
    let osv_ok = osv_successes.load(std::sync::atomic::Ordering::Relaxed);
    let osv_fail = osv_failures.load(std::sync::atomic::Ordering::Relaxed);
    let cve_org_ok = cve_org_successes.load(std::sync::atomic::Ordering::Relaxed);
    let cve_org_fail = cve_org_failures.load(std::sync::atomic::Ordering::Relaxed);
    let ss_ok = ss_successes.load(std::sync::atomic::Ordering::Relaxed);
    let ss_fail = ss_failures.load(std::sync::atomic::Ordering::Relaxed);

    if nvd.is_some() {
        stats.source_status.push(("NVD".to_string(), nvd_fail == 0 && nvd_ok > 0 || nvd_fail == 0));
    }
    if osv.is_some() {
        stats.source_status.push(("OSV".to_string(), osv_fail == 0 && osv_ok > 0 || osv_fail == 0));
    }
    if cve_org.is_some() {
        stats.source_status.push(("CVE.org".to_string(), cve_org_fail == 0 && cve_org_ok > 0 || cve_org_fail == 0));
    }
    if searchsploit.is_some() {
        stats.source_status.push(("SearchSploit".to_string(), ss_fail == 0 && ss_ok > 0 || ss_fail == 0));
    }

    stats
}

/// Deduplicate vulnerabilities by CVE ID.
/// When duplicate CVE IDs are present, keeps the entry with the highest CVSS score.
/// If one has cvss: Some and other has cvss: None, keeps the Some.
pub fn dedup_vulnerabilities(vulns: Vec<Vulnerability>) -> Vec<Vulnerability> {
    let mut best: HashMap<String, Vulnerability> = HashMap::new();

    for vuln in vulns {
        let key = vuln.cve_id.clone();
        match best.get(&key) {
            None => {
                best.insert(key, vuln);
            }
            Some(existing) => {
                let replace = match (&existing.cvss, &vuln.cvss) {
                    (None, Some(_)) => true,
                    (Some(_), None) => false,
                    (Some(a), Some(b)) => b.score > a.score,
                    (None, None) => false,
                };
                if replace {
                    best.insert(key, vuln);
                }
            }
        }
    }

    best.into_values().collect()
}

/// Retry an async operation with exponential backoff.
///
/// Retries on RateLimited and NetworkFailure. Returns immediately on Empty.
/// Delays: 1s, 2s, 4s (3 attempts total before giving up).
pub async fn with_retry<F, Fut, T>(f: F) -> Result<T, VulnLookupError>
where
    F: Fn() -> Fut,
    Fut: Future<Output = Result<T, VulnLookupError>>,
{
    let delays = [
        Duration::from_secs(1),
        Duration::from_secs(2),
        Duration::from_secs(4),
    ];

    let mut last_err = None;
    for (attempt, &delay) in delays.iter().enumerate() {
        match f().await {
            Ok(val) => return Ok(val),
            Err(VulnLookupError::Empty { cpe }) => {
                // Empty is not a transient error -- return immediately without retrying
                return Err(VulnLookupError::Empty { cpe });
            }
            Err(e) => {
                last_err = Some(e);
                if attempt < delays.len() - 1 {
                    // Sleep only if more attempts remain
                    sleep(delay).await;
                }
            }
        }
    }

    // All 3 attempts exhausted
    Err(last_err.expect("delays array is non-empty"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{CvssScore, Severity, Vulnerability};
    use crate::sources::VulnLookupError;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc as StdArc;

    fn make_vuln(cve_id: &str, score: Option<f32>) -> Vulnerability {
        Vulnerability {
            cve_id: cve_id.to_string(),
            source: "NVD".to_string(),
            cvss: score.map(|s| CvssScore {
                score: s,
                severity: Severity::from_score(s),
                version: "3.1".to_string(),
            }),
            description: None,
        }
    }

    #[test]
    fn dedup_keeps_highest_cvss_for_same_cve_id() {
        let vulns = vec![
            make_vuln("CVE-2021-41773", Some(5.0)),
            make_vuln("CVE-2021-41773", Some(9.8)),
        ];
        let deduped = dedup_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 1);
        let cvss = deduped[0].cvss.as_ref().expect("should have CVSS");
        assert!((cvss.score - 9.8).abs() < 0.01, "expected 9.8, got {}", cvss.score);
    }

    #[test]
    fn dedup_keeps_some_over_none_cvss() {
        let vulns = vec![
            make_vuln("CVE-2021-41773", None),
            make_vuln("CVE-2021-41773", Some(7.5)),
        ];
        let deduped = dedup_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0].cvss.is_some(), "should keep the entry with CVSS");
        let cvss = deduped[0].cvss.as_ref().unwrap();
        assert!((cvss.score - 7.5).abs() < 0.01);
    }

    #[test]
    fn dedup_keeps_all_with_different_cve_ids() {
        let vulns = vec![
            make_vuln("CVE-2021-41773", Some(9.8)),
            make_vuln("CVE-2023-44487", Some(7.5)),
        ];
        let mut deduped = dedup_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 2);
        deduped.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));
        assert_eq!(deduped[0].cve_id, "CVE-2021-41773");
        assert_eq!(deduped[1].cve_id, "CVE-2023-44487");
    }

    #[test]
    fn dedup_both_none_cvss_keeps_one() {
        let vulns = vec![
            make_vuln("CVE-2021-41773", None),
            make_vuln("CVE-2021-41773", None),
        ];
        let deduped = dedup_vulnerabilities(vulns);
        assert_eq!(deduped.len(), 1);
        assert!(deduped[0].cvss.is_none());
    }

    #[tokio::test]
    async fn with_retry_returns_ok_on_first_success() {
        let call_count = StdArc::new(AtomicUsize::new(0));
        let cc = call_count.clone();
        let result = with_retry(|| {
            let count = cc.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Ok::<u32, VulnLookupError>(42)
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 42);
        assert_eq!(call_count.load(Ordering::SeqCst), 1, "should only call once on success");
    }

    #[tokio::test]
    async fn with_retry_returns_empty_immediately_without_retry() {
        let call_count = StdArc::new(AtomicUsize::new(0));
        let cc = call_count.clone();
        let result = with_retry(|| {
            let count = cc.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Err::<Vec<crate::models::Vulnerability>, VulnLookupError>(
                    VulnLookupError::Empty {
                        cpe: "cpe:/a:test:test:1.0".to_string(),
                    },
                )
            }
        })
        .await;
        assert!(matches!(result, Err(VulnLookupError::Empty { .. })));
        assert_eq!(call_count.load(Ordering::SeqCst), 1, "Empty should not be retried");
    }

    #[tokio::test]
    async fn with_retry_retries_3_times_on_rate_limited() {
        let call_count = StdArc::new(AtomicUsize::new(0));
        let cc = call_count.clone();
        // Override delays to zero for test speed -- we test the retry count only
        // The actual with_retry uses [1s, 2s, 4s] delays; in tests we just verify
        // the retry count by having the function always fail with RateLimited
        let result = with_retry(|| {
            let count = cc.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                Err::<Vec<crate::models::Vulnerability>, VulnLookupError>(
                    VulnLookupError::RateLimited {
                        retry_after_secs: 0,
                    },
                )
            }
        })
        .await;
        assert!(matches!(result, Err(VulnLookupError::RateLimited { .. })));
        assert_eq!(
            call_count.load(Ordering::SeqCst),
            3,
            "should attempt exactly 3 times on persistent RateLimited"
        );
    }

    #[tokio::test]
    async fn with_retry_returns_ok_after_two_failures() {
        let call_count = StdArc::new(AtomicUsize::new(0));
        let cc = call_count.clone();
        let result = with_retry(|| {
            let count = cc.clone();
            async move {
                let n = count.fetch_add(1, Ordering::SeqCst);
                if n < 2 {
                    Err::<u32, VulnLookupError>(VulnLookupError::RateLimited {
                        retry_after_secs: 0,
                    })
                } else {
                    Ok(99u32)
                }
            }
        })
        .await;
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 99);
        assert_eq!(call_count.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn enrichment_stats_default() {
        let stats = EnrichmentStats::default();
        assert_eq!(stats.services_queried, 0);
        assert_eq!(stats.services_skipped, 0);
        assert_eq!(stats.cves_found, 0);
        assert_eq!(stats.exploits_found, 0);
        assert!(stats.source_failures.is_empty());
        assert!(stats.source_status.is_empty());
    }

    #[test]
    fn enrichment_options_default_concurrency_5() {
        let opts = EnrichmentOptions::default();
        assert_eq!(opts.concurrency, 5);
        assert!(!opts.quiet);
        assert!(!opts.fresh);
        assert!(opts.disabled_sources.is_empty());
    }

    #[test]
    fn source_enabled_returns_true_for_enabled_source() {
        let opts = EnrichmentOptions {
            disabled_sources: vec!["osv".to_string()],
            ..Default::default()
        };
        assert!(opts.source_enabled("nvd"), "nvd should be enabled");
        assert!(!opts.source_enabled("osv"), "osv should be disabled");
        assert!(!opts.source_enabled("OSV"), "OSV (uppercase) should be disabled (case-insensitive)");
    }

    #[test]
    fn source_enabled_all_enabled_by_default() {
        let opts = EnrichmentOptions::default();
        assert!(opts.source_enabled("nvd"));
        assert!(opts.source_enabled("osv"));
        assert!(opts.source_enabled("cveorg"));
        assert!(opts.source_enabled("searchsploit"));
    }
}
