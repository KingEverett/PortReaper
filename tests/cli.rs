use std::process::Command;

fn portreaper() -> Command {
    Command::new(env!("CARGO_BIN_EXE_portreaper"))
}

/// Helper: run portreaper and return (stdout, stderr, exit_code)
fn run(args: &[&str]) -> (String, String, i32) {
    let output = portreaper()
        .args(args)
        .output()
        .expect("failed to execute portreaper");
    let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
    let code = output.status.code().unwrap_or(-1);
    (stdout, stderr, code)
}

#[test]
fn test_basic_xml_parse() {
    let (stdout, stderr, code) = run(&["tests/fixtures/scan_basic.xml"]);
    assert_eq!(code, 0, "expected exit 0, got {}\nstderr: {}", code, stderr);
    assert!(stdout.contains("192.168.1.1"), "stdout missing 192.168.1.1:\n{}", stdout);
    assert!(stdout.contains("ssh"), "stdout missing 'ssh':\n{}", stdout);
    assert!(stdout.contains("http"), "stdout missing 'http':\n{}", stdout);
    assert!(stdout.contains("Summary:"), "stdout missing 'Summary:':\n{}", stdout);
}

#[test]
fn test_multi_host_all_present() {
    let (stdout, _stderr, code) = run(&["tests/fixtures/scan_multi_host.xml"]);
    assert_eq!(code, 0, "expected exit 0");
    assert!(stdout.contains("192.168.1.1"), "stdout missing 192.168.1.1:\n{}", stdout);
    assert!(stdout.contains("192.168.1.2"), "stdout missing 192.168.1.2:\n{}", stdout);
    assert!(stdout.contains("192.168.1.3"), "stdout missing 192.168.1.3:\n{}", stdout);
}

#[test]
fn test_file_not_found() {
    let (stdout, stderr, code) = run(&["nonexistent_file_xyz.xml"]);
    assert_eq!(code, 2, "expected exit 2 for nonexistent file, got {}\nstdout: {}\nstderr: {}", code, stdout, stderr);
    assert!(
        stderr.contains("file not found"),
        "stderr missing 'file not found':\n{}", stderr
    );
}

#[test]
fn test_verbose_shows_cpe() {
    let (stdout, _stderr, code) = run(&["tests/fixtures/scan_basic.xml", "-v"]);
    assert_eq!(code, 0, "expected exit 0");
    assert!(
        stdout.contains("cpe:/a:openbsd:openssh:8.9p1"),
        "stdout missing CPE string with -v flag:\n{}", stdout
    );
}

#[test]
fn test_quiet_summary_only() {
    let (stdout, _stderr, code) = run(&["tests/fixtures/scan_basic.xml", "-q"]);
    assert_eq!(code, 0, "expected exit 0");
    assert!(stdout.contains("Summary:"), "stdout missing 'Summary:' in quiet mode:\n{}", stdout);
    // Tree should not be rendered -- no box drawing characters
    assert!(
        !stdout.contains("\u{251C}") && !stdout.contains("\u{2514}") && !stdout.contains("\u{2502}"),
        "stdout contains tree characters in quiet mode (should be summary only):\n{}", stdout
    );
    // Also should not show the IP in tree form
    // The summary itself might show counts, but not the tree
    // Check no "Scan:" header
    assert!(!stdout.contains("Scan:"), "stdout has 'Scan:' header in quiet mode:\n{}", stdout);
}

#[test]
fn test_tree_has_unicode_chars() {
    let (stdout, _stderr, code) = run(&["tests/fixtures/scan_basic.xml"]);
    assert_eq!(code, 0, "expected exit 0");
    // Check for Unicode box-drawing chars in output
    assert!(
        stdout.contains("\u{251C}") || stdout.contains("\u{2514}") || stdout.contains("\u{2502}"),
        "stdout missing Unicode tree characters:\n{}", stdout
    );
}

#[test]
fn test_piped_output_no_ansi() {
    // Command captures stdout as pipe (not TTY), so color should be auto-disabled
    let output = portreaper()
        .args(["tests/fixtures/scan_basic.xml"])
        .output()
        .expect("failed to execute portreaper");
    let stdout = String::from_utf8_lossy(&output.stdout);
    // ANSI escape codes start with ESC [ (0x1b 0x5b)
    assert!(
        !stdout.contains('\x1b'),
        "stdout contains ANSI escape codes when output is piped (not a TTY):\n{}", stdout
    );
}

#[test]
fn test_multiple_files() {
    let (stdout, _stderr, code) = run(&[
        "tests/fixtures/scan_basic.xml",
        "tests/fixtures/scan_multi_host.xml",
    ]);
    assert_eq!(code, 0, "expected exit 0");
    // Both files' hosts should appear
    assert!(stdout.contains("192.168.1.1"), "stdout missing 192.168.1.1 from scan_basic.xml:\n{}", stdout);
    assert!(stdout.contains("192.168.1.2"), "stdout missing 192.168.1.2 from scan_multi_host.xml:\n{}", stdout);
    assert!(stdout.contains("192.168.1.3"), "stdout missing 192.168.1.3 from scan_multi_host.xml:\n{}", stdout);
}

#[test]
fn test_text_format() {
    let (stdout, _stderr, code) = run(&["tests/fixtures/scan_basic.txt"]);
    assert_eq!(code, 0, "expected exit 0 for text format");
    assert!(stdout.contains("192.168.1.1"), "stdout missing 192.168.1.1 from text file:\n{}", stdout);
}

#[test]
fn test_greppable_format() {
    let (stdout, _stderr, code) = run(&["tests/fixtures/scan_basic.grep"]);
    assert_eq!(code, 0, "expected exit 0 for greppable format");
    assert!(stdout.contains("192.168.1.1"), "stdout missing 192.168.1.1 from greppable file:\n{}", stdout);
}

#[test]
fn test_empty_stdin_nonzero() {
    // Pipe empty input to portreaper -- should exit non-zero
    let output = portreaper()
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .expect("failed to spawn portreaper");

    // Close stdin immediately (simulate echo "" | portreaper)
    let result = output.wait_with_output().expect("wait failed");
    let code = result.status.code().unwrap_or(-1);
    assert_ne!(code, 0, "expected non-zero exit for empty stdin");
}

#[test]
fn test_summary_counts() {
    // scan_basic.xml has 1 host, 3 open ports, 3 unique services
    let (stdout, _stderr, code) = run(&["tests/fixtures/scan_basic.xml", "--no-enrich"]);
    assert_eq!(code, 0);
    assert!(
        stdout.contains("1 hosts") || stdout.contains("1 host"),
        "Summary missing host count:\n{}", stdout
    );
    assert!(
        stdout.contains("3 open ports"),
        "Summary missing port count:\n{}", stdout
    );
}

#[test]
fn test_no_enrich_flag() {
    let output = Command::new(env!("CARGO_BIN_EXE_portreaper"))
        .arg("--no-enrich")
        .arg("tests/fixtures/scan_basic.xml")
        .output()
        .expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show tree without CVEs (same as Phase 1 behavior)
    assert!(stdout.contains("Summary:"), "stdout missing Summary:\n{}", stdout);
    assert!(stdout.contains("hosts"), "stdout missing hosts:\n{}", stdout);
    // Should NOT contain CVE lines
    assert!(!stdout.contains("CVE-"), "stdout should not contain CVE- with --no-enrich:\n{}", stdout);
}

#[test]
fn test_quiet_with_no_enrich() {
    let output = Command::new(env!("CARGO_BIN_EXE_portreaper"))
        .arg("-q")
        .arg("--no-enrich")
        .arg("tests/fixtures/scan_basic.xml")
        .output()
        .expect("failed to run");
    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Summary:"), "stdout missing Summary:\n{}", stdout);
    // Quiet mode: only summary line, no tree
    assert!(!stdout.contains("Scan:"), "stdout has 'Scan:' header in quiet mode:\n{}", stdout);
}
