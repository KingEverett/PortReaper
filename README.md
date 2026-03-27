# PortReaper

A Rust CLI tool that parses nmap scan results, auto-researches every discovered service against vulnerability databases (NVD, CVE.org, OSV.dev, SearchSploit), and generates an interconnected Obsidian vault — color-coded by severity.

## Install

```bash
cargo install --path .
```

Or build from source:

```bash
cargo build --release
# Binary at target/release/portreaper
```

## Usage

```bash
# Parse nmap XML and enrich with vulnerability data
portreaper scan.xml

# Pipe nmap output directly
nmap -sV 192.168.1.0/24 | portreaper

# Multiple scan files
portreaper scan1.xml scan2.xml

# Generate an Obsidian vault
portreaper scan.xml --vault ./my-vault

# Skip vulnerability lookups (parse only)
portreaper scan.xml --no-enrich

# Disable specific sources
portreaper scan.xml --disable-source nvd --disable-source osv

# Bypass cache and re-fetch all data
portreaper scan.xml --fresh

# Verbose output (CPE strings, OS detection)
portreaper scan.xml -v

# Quiet mode (summary line only)
portreaper scan.xml -q
```

### CLI Flags

| Flag | Description |
|------|-------------|
| `-v`, `--verbose` | Show CPE strings, OS detection, extra service fields |
| `-q`, `--quiet` | Summary line only |
| `--no-enrich` | Skip vulnerability lookups |
| `--vault <DIR>` | Generate Obsidian vault at directory |
| `--fresh` | Bypass cache, re-fetch everything |
| `--disable-source <NAME>` | Disable a source: `nvd`, `cveorg`, `osv`, `searchsploit` (repeatable) |

### Supported Input Formats

- nmap XML (`-oX`)
- nmap text output (piped or saved)
- nmap greppable (`-oG`)

Formats are auto-detected. When no files are given, PortReaper reads from stdin.

## Configuration

PortReaper reads an optional TOML config file at the OS-appropriate path:

- **Linux:** `~/.config/portreaper/config.toml`
- **macOS:** `~/Library/Application Support/portreaper/config.toml`

If the file is missing or malformed, PortReaper runs with defaults. CLI flags always override config values.

### Example Config

```toml
[sources]
nvd = true
cveorg = true
osv = true
searchsploit = false    # disable SearchSploit by default

[api_keys]
nvd_key = "your-nvd-api-key"   # or use PORTREAPER_NVD_KEY env var

[output]
vault = "/home/user/vaults/recon"   # default vault output path

[enrichment]
concurrency = 5         # max parallel API requests
cache_ttl_days = 7      # cache expiry in days
```

### Priority Order

For values that can be set in multiple places:

1. CLI flags (highest)
2. Environment variables (`PORTREAPER_NVD_KEY`)
3. Config file
4. Built-in defaults (lowest)

## Obsidian Vault

When using `--vault`, PortReaper generates a structured vault:

```
my-vault/
  scans/
    nmap-20260324/
      _index.md
      hosts/
        192.168.1.1.md
      services/
        192-168-1-1-22-tcp-ssh.md
        192-168-1-1-80-tcp-http.md
      cves/
        CVE-2021-41773.md
      technologies/
        OpenSSH-8.2p1.md
  .obsidian/
    snippets/
      portreaper-severity.css
```

Notes include YAML frontmatter, severity tags (`#critical`, `#high`, `#medium`, `#low`), and `[[wikilinks]]` for Obsidian's graph view.

### Incremental Merging

Re-running PortReaper against the same target merges new findings into the existing vault:

- User-written Notes sections are preserved
- Services no longer seen get a `not-seen-in-latest` tag
- CVE notes track CVSS score changes in a Score History table
- Scan overlap is detected by IP address — no duplicate scan folders

## Data Sources

| Source | Data | Requires |
|--------|------|----------|
| [NVD](https://nvd.nist.gov/) | CVEs, CVSS scores | Optional API key (rate limited without) |
| [CVE.org](https://www.cve.org/) | CVE descriptions, references | Nothing |
| [OSV.dev](https://osv.dev/) | Ecosystem vulnerabilities | Nothing |
| [SearchSploit](https://gitlab.com/exploit-database/exploitdb) | Local exploit references | `searchsploit` binary on PATH |

Results are cached locally for 7 days (configurable via `cache_ttl_days`).

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | Success |
| 1 | Parse or runtime error |
| 2 | No input provided |

## License

MIT
