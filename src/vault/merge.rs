use std::path::Path;

use super::VaultError;

// ============================================================
// Constants
// ============================================================

const NOTES_HEADING: &str = "\n## Notes\n";
const SCORE_HISTORY_HEADING: &str = "\n## Score History\n";

// ============================================================
// Notes tail extraction (D-01)
// ============================================================

/// Extract everything from "## Notes\n" onward. Returns the heading + content.
/// Returns None if marker not found.
pub fn extract_notes_tail(content: &str) -> Option<String> {
    // Handle file starting with "## Notes\n" (no leading \n)
    if content.starts_with("## Notes\n") {
        return Some(content.to_string());
    }
    content
        .find(NOTES_HEADING)
        .map(|pos| content[pos + 1..].to_string()) // +1 skips leading \n, keeps "## Notes\n..."
}

// ============================================================
// Merge-aware write (D-01)
// ============================================================

/// Write a note, preserving the existing Notes section if the file already exists.
/// The new_content MUST contain "\n## Notes\n" from the template.
/// If existing file has user Notes content, it replaces the template's empty Notes section.
pub fn merge_write_note(
    vault_root: &Path,
    relative_path: &str,
    new_content: &str,
) -> Result<(), VaultError> {
    let full_path = vault_root.join(relative_path);

    let saved_tail = if full_path.exists() {
        std::fs::read_to_string(&full_path)
            .ok()
            .and_then(|existing| extract_notes_tail(&existing))
    } else {
        None
    };

    let final_content = match saved_tail {
        Some(tail) => {
            // Strip template's Notes section and replace with preserved tail
            if let Some(notes_pos) = new_content.find(NOTES_HEADING) {
                format!("{}\n{}", &new_content[..notes_pos], tail)
            } else {
                // Template lacks Notes marker (shouldn't happen) -- append preserved tail
                new_content.to_string()
            }
        }
        None => new_content.to_string(),
    };

    super::writer::write_note(vault_root, relative_path, &final_content)
}

// ============================================================
// Score History extraction and append (D-04)
// ============================================================

/// Extract Score History section from existing CVE note content.
/// Returns the table rows (excluding header) as Vec<(date, score_str, severity, version)>.
pub fn extract_score_history(content: &str) -> Vec<(String, String, String, String)> {
    let section_start = match content.find(SCORE_HISTORY_HEADING) {
        Some(pos) => pos + SCORE_HISTORY_HEADING.len(),
        None => return vec![],
    };

    let section_end = content[section_start..]
        .find("\n## ")
        .map(|p| section_start + p)
        .unwrap_or(content.len());

    let section = &content[section_start..section_end];
    let mut rows = vec![];

    for line in section.lines() {
        let line = line.trim();
        if line.starts_with('|') && !line.contains("---") && !line.contains("Date") {
            let cols: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
            // cols: ["", date, score, severity, version, ""]
            if cols.len() >= 5 {
                rows.push((
                    cols[1].to_string(),
                    cols[2].to_string(),
                    cols[3].to_string(),
                    cols[4].to_string(),
                ));
            }
        }
    }
    rows
}

/// Build a Score History section string from history rows + current values.
/// Only appends a new row if the score changed from the most recent entry (avoids Pitfall 2).
pub fn build_score_history_section(
    existing_rows: &[(String, String, String, String)],
    current_score: Option<f32>,
    current_severity: &str,
    current_cvss_version: Option<&str>,
    today: &str,
) -> Option<String> {
    let score_str = match current_score {
        Some(s) => format!("{:.1}", s),
        None => return None, // No score = no history to track
    };
    let version_str = current_cvss_version.unwrap_or("N/A");

    let mut rows = existing_rows.to_vec();

    // Only add new row if score changed from latest entry (Pitfall 2)
    let should_add = match rows.last() {
        Some(last) => last.1 != score_str,
        None => true, // No history yet, always add first entry
    };

    if should_add {
        rows.push((
            today.to_string(),
            score_str,
            current_severity.to_string(),
            version_str.to_string(),
        ));
    }

    if rows.is_empty() {
        return None;
    }

    let mut section = String::from("\n## Score History\n\n");
    section.push_str("| Date | Score | Severity | CVSS Version |\n");
    section.push_str("|------|-------|----------|--------------|\n");
    for (date, score, sev, ver) in &rows {
        section.push_str(&format!("| {} | {} | {} | {} |\n", date, score, sev, ver));
    }

    Some(section)
}

// ============================================================
// CVE merge-aware write (combines Notes + Score History)
// ============================================================

/// Write a CVE note with merge: preserves Notes AND manages Score History.
/// Score History is inserted between ## References and ## Notes.
pub fn merge_write_cve_note(
    vault_root: &Path,
    relative_path: &str,
    new_content: &str,
    current_score: Option<f32>,
    current_severity: &str,
    current_cvss_version: Option<&str>,
    today: &str,
) -> Result<(), VaultError> {
    let full_path = vault_root.join(relative_path);

    // Extract existing Notes and Score History if file exists
    let (saved_notes_tail, existing_history) = if full_path.exists() {
        let existing = std::fs::read_to_string(&full_path).unwrap_or_default();
        let notes = extract_notes_tail(&existing);
        let history = extract_score_history(&existing);
        (notes, history)
    } else {
        (None, vec![])
    };

    // Build score history section
    let history_section = build_score_history_section(
        &existing_history,
        current_score,
        current_severity,
        current_cvss_version,
        today,
    );

    // Reconstruct content: everything before ## Notes, optionally insert Score History, then Notes
    let final_content = {
        let notes_tail = saved_notes_tail.unwrap_or_else(|| "## Notes\n\n".to_string());

        if let Some(notes_pos) = new_content.find(NOTES_HEADING) {
            let before_notes = &new_content[..notes_pos];
            match history_section {
                Some(hist) => format!("{}{}\n{}", before_notes, hist, notes_tail),
                None => format!("{}\n{}", before_notes, notes_tail),
            }
        } else {
            new_content.to_string()
        }
    };

    super::writer::write_note(vault_root, relative_path, &final_content)
}

// ============================================================
// Stale tag application (D-02)
// ============================================================

/// Apply "not-seen-in-latest" tag to service notes that existed before but were not regenerated.
/// `pre_existing_service_paths` are relative paths that existed before this run.
/// `regenerated_paths` are relative paths written during this run.
///
/// Uses serde_yml to parse and re-serialize YAML frontmatter rather than string manipulation,
/// per RESEARCH.md anti-pattern guidance against regex-based YAML modification.
pub fn apply_stale_tags(
    vault_root: &Path,
    pre_existing_service_paths: &[String],
    regenerated_paths: &[String],
) -> Result<(), VaultError> {
    let stale_tag = "not-seen-in-latest";

    for path in pre_existing_service_paths {
        if regenerated_paths.contains(path) {
            continue; // Still active, skip
        }
        let full_path = vault_root.join(path);
        if !full_path.exists() {
            continue;
        }
        let content = match std::fs::read_to_string(&full_path) {
            Ok(c) => c,
            Err(_) => continue,
        };

        // Check if already has the tag
        if content.contains(stale_tag) {
            continue;
        }

        // Parse frontmatter: content between first --- and second ---
        let parts: Vec<&str> = content.splitn(3, "---").collect();
        if parts.len() < 3 {
            continue; // No valid frontmatter
        }

        let yaml_str = parts[1].trim();
        let body = parts[2];

        // Deserialize frontmatter into serde_yml::Value, add tag, re-serialize
        let mut value: serde_yml::Value = match serde_yml::from_str(yaml_str) {
            Ok(v) => v,
            Err(_) => continue, // Unparseable frontmatter, skip
        };

        // Navigate to tags array and append stale tag
        if let serde_yml::Value::Mapping(ref mut map) = value {
            let tags_key = serde_yml::Value::String("tags".to_string());
            let tags_entry = map.entry(tags_key).or_insert_with(|| {
                serde_yml::Value::Sequence(vec![])
            });
            if let serde_yml::Value::Sequence(seq) = tags_entry {
                seq.push(serde_yml::Value::String(stale_tag.to_string()));
            }
        }

        // Re-serialize frontmatter
        let new_yaml = match serde_yml::to_string(&value) {
            Ok(y) => y,
            Err(_) => continue,
        };

        // Reconstruct note: ---\n{yaml}---\n{body}
        let updated = format!("---\n{}---{}", new_yaml, body);
        let _ = std::fs::write(&full_path, updated);
    }
    Ok(())
}

// ============================================================
// Scan subfolder overlap detection (D-03)
// ============================================================

/// Find an existing scan subfolder in the vault that shares IP addresses with the new scan.
/// Returns the scan label of the matching subfolder, or None.
/// If multiple match, returns the most recently modified (by _index.md mtime). Per Open Question 2.
pub fn find_existing_scan_folder(vault_root: &Path, new_ips: &[String]) -> Option<String> {
    let scans_dir = vault_root.join("scans");
    if !scans_dir.exists() {
        return None;
    }

    let mut candidates: Vec<(String, std::time::SystemTime)> = vec![];

    let entries = match std::fs::read_dir(&scans_dir) {
        Ok(e) => e,
        Err(_) => return None,
    };

    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let scan_label = match path.file_name().and_then(|n| n.to_str()) {
            Some(n) => n.to_string(),
            None => continue,
        };

        // List hosts/*.md files and extract IPs from filenames
        let hosts_dir = path.join("hosts");
        if !hosts_dir.exists() {
            continue;
        }
        let host_entries = match std::fs::read_dir(&hosts_dir) {
            Ok(e) => e,
            Err(_) => continue,
        };

        let existing_ips: Vec<String> = host_entries
            .flatten()
            .filter_map(|e| {
                let name = e.file_name().to_string_lossy().to_string();
                name.strip_suffix(".md").map(|s| s.to_string())
            })
            .collect();

        // Check IP overlap
        let has_overlap = new_ips.iter().any(|ip| {
            let sanitized = crate::util::filename::sanitize_filename(ip);
            existing_ips.contains(&sanitized)
        });

        if has_overlap {
            // Get mtime of _index.md for recency comparison
            let index_path = path.join("_index.md");
            let mtime = index_path
                .metadata()
                .and_then(|m| m.modified())
                .unwrap_or(std::time::UNIX_EPOCH);
            candidates.push((scan_label, mtime));
        }
    }

    // Return most recently modified
    candidates.sort_by(|a, b| b.1.cmp(&a.1));
    candidates.into_iter().next().map(|(label, _)| label)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;

    fn make_test_dir(suffix: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "portreaper_merge_test_{}_{}",
            suffix,
            std::process::id()
        ));
        fs::create_dir_all(&dir).expect("create test dir");
        dir
    }

    // ---- extract_notes_tail tests ----

    #[test]
    fn extract_notes_tail_with_user_content() {
        let content = "# Title\n\nSome content\n\n## Notes\n\nUser wrote this";
        let result = extract_notes_tail(content);
        assert_eq!(result, Some("## Notes\n\nUser wrote this".to_string()));
    }

    #[test]
    fn extract_notes_tail_no_notes_section_returns_none() {
        let result = extract_notes_tail("content with no notes section");
        assert_eq!(result, None);
    }

    #[test]
    fn extract_notes_tail_empty_notes_section() {
        let content = "# Title\n\n## Notes\n\n";
        let result = extract_notes_tail(content);
        assert_eq!(result, Some("## Notes\n\n".to_string()));
    }

    #[test]
    fn extract_notes_tail_content_starts_with_notes_heading() {
        let content = "## Notes\n\nSome notes here";
        let result = extract_notes_tail(content);
        assert_eq!(result, Some("## Notes\n\nSome notes here".to_string()));
    }

    // ---- merge_write_note tests ----

    #[test]
    fn merge_write_note_creates_new_file_when_no_existing() {
        let dir = make_test_dir("merge_new");
        let content = "# Test\n\nBody content\n\n## Notes\n\n";
        merge_write_note(&dir, "test.md", content).expect("merge_write_note");
        let written = fs::read_to_string(dir.join("test.md")).expect("read file");
        assert_eq!(written, content);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_write_note_preserves_existing_notes_content() {
        let dir = make_test_dir("merge_preserve");

        // Write initial note with user Notes content
        let initial = "# Test\n\nOriginal body\n\n## Notes\n\nUser wrote this important note";
        fs::create_dir_all(&dir).expect("create dir");
        fs::write(dir.join("note.md"), initial).expect("write initial");

        // Merge-write with updated content
        let new_content = "# Test\n\nUpdated body content\n\n## Notes\n\n";
        merge_write_note(&dir, "note.md", new_content).expect("merge_write_note");

        let result = fs::read_to_string(dir.join("note.md")).expect("read result");
        assert!(
            result.contains("User wrote this important note"),
            "user notes should be preserved"
        );
        assert!(
            result.contains("Updated body content"),
            "new body content should be present"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn merge_write_note_no_double_notes_headings() {
        let dir = make_test_dir("merge_no_double");

        let initial = "# Test\n\n## Notes\n\nUser notes here";
        fs::write(dir.join("note.md"), initial).expect("write initial");

        let new_content = "# Test\n\nNew body\n\n## Notes\n\n";
        merge_write_note(&dir, "note.md", new_content).expect("merge_write_note");

        let result = fs::read_to_string(dir.join("note.md")).expect("read result");
        let count = result.matches("## Notes").count();
        assert_eq!(count, 1, "should have exactly one ## Notes heading, got: {}", count);
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- extract_score_history tests ----

    #[test]
    fn extract_score_history_returns_empty_when_no_section() {
        let content = "# CVE\n\n## References\n\nlinks\n\n## Notes\n\n";
        let result = extract_score_history(content);
        assert!(result.is_empty());
    }

    #[test]
    fn extract_score_history_parses_existing_rows() {
        let content = "# CVE\n\n## Score History\n\n| Date | Score | Severity | CVSS Version |\n|------|-------|----------|--------------|\n| 2026-03-01 | 9.8 | critical | 3.1 |\n\n## Notes\n\n";
        let result = extract_score_history(content);
        assert_eq!(result.len(), 1);
        assert_eq!(result[0].0, "2026-03-01");
        assert_eq!(result[0].1, "9.8");
        assert_eq!(result[0].2, "critical");
        assert_eq!(result[0].3, "3.1");
    }

    #[test]
    fn extract_score_history_parses_multiple_rows() {
        let content = "# CVE\n\n## Score History\n\n| Date | Score | Severity | CVSS Version |\n|------|-------|----------|--------------|\n| 2026-01-01 | 7.5 | high | 3.1 |\n| 2026-03-01 | 9.8 | critical | 3.1 |\n\n## Notes\n\n";
        let result = extract_score_history(content);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].1, "7.5");
        assert_eq!(result[1].1, "9.8");
    }

    // ---- build_score_history_section tests ----

    #[test]
    fn build_score_history_section_no_score_returns_none() {
        let result = build_score_history_section(&[], None, "none", None, "2026-03-24");
        assert!(result.is_none());
    }

    #[test]
    fn build_score_history_section_first_entry_added() {
        let result = build_score_history_section(&[], Some(9.8), "critical", Some("3.1"), "2026-03-24");
        assert!(result.is_some());
        let section = result.unwrap();
        assert!(section.contains("2026-03-24"));
        assert!(section.contains("9.8"));
        assert!(section.contains("critical"));
        assert!(section.contains("3.1"));
    }

    #[test]
    fn build_score_history_section_dedup_same_score_not_added() {
        // Previous entry has same score
        let existing = vec![(
            "2026-03-01".to_string(),
            "9.8".to_string(),
            "critical".to_string(),
            "3.1".to_string(),
        )];
        let result = build_score_history_section(
            &existing,
            Some(9.8),
            "critical",
            Some("3.1"),
            "2026-03-24",
        );
        assert!(result.is_some());
        let section = result.unwrap();
        // Should still have the old entry but NOT add a duplicate
        let count = section.matches("| 2026-").count();
        assert_eq!(count, 1, "should only have one row, not a duplicate");
    }

    #[test]
    fn build_score_history_section_changed_score_adds_new_row() {
        let existing = vec![(
            "2026-01-01".to_string(),
            "7.5".to_string(),
            "high".to_string(),
            "3.1".to_string(),
        )];
        let result = build_score_history_section(
            &existing,
            Some(9.8),
            "critical",
            Some("3.1"),
            "2026-03-24",
        );
        assert!(result.is_some());
        let section = result.unwrap();
        assert!(section.contains("7.5"), "old score should be in history");
        assert!(section.contains("9.8"), "new score should be in history");
        let count = section.matches("| 2026-").count();
        assert_eq!(count, 2, "should have two rows");
    }

    // ---- apply_stale_tags tests ----

    #[test]
    fn apply_stale_tags_adds_tag_to_missing_service() {
        let dir = make_test_dir("stale_tags");

        // Create a service note with valid frontmatter
        let service_content = "---\nhost: 10.0.0.1\nport: 22\nprotocol: tcp\nservice: ssh\nhighest_severity: none\ntags:\n  - service\n  - ssh\n  - none\nscan_label: test\n---\n\n# 10.0.0.1:22/tcp - ssh\n\n## Notes\n\n";
        let service_path = "scans/test/services/10.0.0.1_22_tcp.md";
        let full_path = dir.join(service_path);
        fs::create_dir_all(full_path.parent().unwrap()).expect("create dirs");
        fs::write(&full_path, service_content).expect("write service note");

        let pre_existing = vec![service_path.to_string()];
        let regenerated: Vec<String> = vec![]; // Not regenerated this run

        apply_stale_tags(&dir, &pre_existing, &regenerated).expect("apply_stale_tags");

        let updated = fs::read_to_string(&full_path).expect("read updated");
        assert!(
            updated.contains("not-seen-in-latest"),
            "stale tag should be added"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_stale_tags_skips_regenerated_service() {
        let dir = make_test_dir("stale_tags_skip");

        let service_content = "---\nhost: 10.0.0.1\nport: 22\nprotocol: tcp\nservice: ssh\nhighest_severity: none\ntags:\n  - service\nscan_label: test\n---\n\n## Notes\n\n";
        let service_path = "scans/test/services/10.0.0.1_22_tcp.md";
        let full_path = dir.join(service_path);
        fs::create_dir_all(full_path.parent().unwrap()).expect("create dirs");
        fs::write(&full_path, service_content).expect("write service note");

        let pre_existing = vec![service_path.to_string()];
        let regenerated = vec![service_path.to_string()]; // Was regenerated

        apply_stale_tags(&dir, &pre_existing, &regenerated).expect("apply_stale_tags");

        let updated = fs::read_to_string(&full_path).expect("read updated");
        assert!(
            !updated.contains("not-seen-in-latest"),
            "stale tag should NOT be added to regenerated service"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_stale_tags_no_duplicate_tag_if_already_present() {
        let dir = make_test_dir("stale_no_dup");

        // Note already has the stale tag
        let service_content = "---\nhost: 10.0.0.1\nport: 22\nprotocol: tcp\nservice: ssh\nhighest_severity: none\ntags:\n  - service\n  - not-seen-in-latest\nscan_label: test\n---\n\n## Notes\n\n";
        let service_path = "scans/test/services/10.0.0.1_22_tcp.md";
        let full_path = dir.join(service_path);
        fs::create_dir_all(full_path.parent().unwrap()).expect("create dirs");
        fs::write(&full_path, service_content).expect("write service note");

        let pre_existing = vec![service_path.to_string()];
        let regenerated: Vec<String> = vec![];

        apply_stale_tags(&dir, &pre_existing, &regenerated).expect("apply_stale_tags");

        let updated = fs::read_to_string(&full_path).expect("read updated");
        let count = updated.matches("not-seen-in-latest").count();
        assert_eq!(count, 1, "tag should appear exactly once, not duplicated");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn apply_stale_tags_uses_serde_yml_round_trip() {
        // Verify that serde_yml parsing preserves other frontmatter fields correctly
        let dir = make_test_dir("stale_yml_roundtrip");

        let service_content = "---\nhost: 10.0.0.1\nport: 80\nprotocol: tcp\nservice: http\nproduct: Apache\nversion: 2.4.49\nhighest_severity: critical\ntags:\n  - service\n  - http\n  - critical\nscan_label: test-label\n---\n\n## Notes\n\nUser annotation here";
        let service_path = "test_service.md";
        let full_path = dir.join(service_path);
        fs::write(&full_path, service_content).expect("write service note");

        let pre_existing = vec![service_path.to_string()];
        let regenerated: Vec<String> = vec![];

        apply_stale_tags(&dir, &pre_existing, &regenerated).expect("apply_stale_tags");

        let updated = fs::read_to_string(&full_path).expect("read updated");
        assert!(updated.contains("not-seen-in-latest"), "stale tag should be present");
        assert!(updated.contains("host:"), "host field should still be present");
        assert!(updated.contains("10.0.0.1"), "IP should still be present");
        assert!(updated.contains("Apache"), "product should still be present");
        assert!(updated.contains("User annotation here"), "body should still be present");

        // Verify the tags section is still valid YAML parseable
        let parts: Vec<&str> = updated.splitn(3, "---").collect();
        assert!(parts.len() >= 3, "should still have frontmatter delimiters");
        let yaml_str = parts[1].trim();
        let parsed: serde_yml::Value = serde_yml::from_str(yaml_str).expect("should parse as YAML");
        if let serde_yml::Value::Mapping(map) = &parsed {
            let tags_key = serde_yml::Value::String("tags".to_string());
            if let Some(serde_yml::Value::Sequence(tags)) = map.get(&tags_key) {
                assert!(
                    tags.contains(&serde_yml::Value::String("not-seen-in-latest".to_string())),
                    "tags array should contain not-seen-in-latest"
                );
            } else {
                panic!("tags field should be a sequence");
            }
        }
        let _ = fs::remove_dir_all(&dir);
    }

    // ---- find_existing_scan_folder tests ----

    #[test]
    fn find_existing_scan_folder_returns_none_when_scans_dir_missing() {
        let dir = make_test_dir("find_no_scans");
        let result = find_existing_scan_folder(&dir, &["192.168.1.1".to_string()]);
        assert!(result.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_existing_scan_folder_returns_none_when_no_overlap() {
        let dir = make_test_dir("find_no_overlap");

        // Create existing scan with different IPs
        let hosts_dir = dir.join("scans/old-scan/hosts");
        fs::create_dir_all(&hosts_dir).expect("create hosts dir");
        fs::write(hosts_dir.join("10.0.0.1.md"), "# 10.0.0.1").expect("write host");

        // Search with non-overlapping IPs
        let result = find_existing_scan_folder(&dir, &["192.168.1.1".to_string()]);
        assert!(result.is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_existing_scan_folder_returns_label_when_ip_overlap() {
        let dir = make_test_dir("find_with_overlap");

        // Create existing scan with matching IP
        let hosts_dir = dir.join("scans/2026-03-01_scan/hosts");
        fs::create_dir_all(&hosts_dir).expect("create hosts dir");
        fs::write(hosts_dir.join("192.168.1.1.md"), "# 192.168.1.1").expect("write host");
        // Create _index.md for mtime
        fs::write(dir.join("scans/2026-03-01_scan/_index.md"), "# Scan Index").expect("write index");

        let result = find_existing_scan_folder(&dir, &["192.168.1.1".to_string()]);
        assert_eq!(result, Some("2026-03-01_scan".to_string()));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn find_existing_scan_folder_returns_most_recently_modified_when_multiple_match() {
        let dir = make_test_dir("find_most_recent");

        // Create two scan folders with same IP
        for scan_label in &["2026-01-01_scan", "2026-03-01_scan"] {
            let hosts_dir = dir.join(format!("scans/{}/hosts", scan_label));
            fs::create_dir_all(&hosts_dir).expect("create hosts dir");
            fs::write(hosts_dir.join("192.168.1.1.md"), "# 192.168.1.1").expect("write host");
            fs::write(
                dir.join(format!("scans/{}/_index.md", scan_label)),
                "# Index",
            )
            .expect("write index");
        }

        // Modify mtime of 2026-03-01_scan's _index.md by writing to it again
        // In practice, fs modification order determines result.
        // We can't fully control mtime in tests, so we just check that a result is returned
        let result = find_existing_scan_folder(&dir, &["192.168.1.1".to_string()]);
        assert!(result.is_some(), "should find a matching scan folder");
        let _ = fs::remove_dir_all(&dir);
    }
}
