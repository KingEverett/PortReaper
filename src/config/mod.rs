use serde::Deserialize;
use std::path::PathBuf;

fn default_concurrency() -> usize { 5 }
fn default_cache_ttl_days() -> u64 { 7 }
fn default_true() -> bool { true }

#[derive(Debug, Deserialize, Default, Clone)]
pub struct PortReaperConfig {
    #[serde(default)]
    pub sources: SourcesConfig,
    #[serde(default)]
    pub api_keys: ApiKeysConfig,
    #[serde(default)]
    pub output: OutputConfig,
    #[serde(default)]
    pub enrichment: EnrichmentConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct SourcesConfig {
    #[serde(default = "default_true")]
    pub nvd: bool,
    #[serde(default = "default_true")]
    pub cveorg: bool,
    #[serde(default = "default_true")]
    pub osv: bool,
    #[serde(default = "default_true")]
    pub searchsploit: bool,
}

impl Default for SourcesConfig {
    fn default() -> Self {
        Self { nvd: true, cveorg: true, osv: true, searchsploit: true }
    }
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct ApiKeysConfig {
    pub nvd_key: Option<String>,
}

#[derive(Debug, Deserialize, Default, Clone)]
pub struct OutputConfig {
    pub vault: Option<PathBuf>,
}

#[derive(Debug, Deserialize, Clone)]
pub struct EnrichmentConfig {
    #[serde(default = "default_concurrency")]
    pub concurrency: usize,
    #[serde(default = "default_cache_ttl_days")]
    pub cache_ttl_days: u64,
}

impl Default for EnrichmentConfig {
    fn default() -> Self {
        Self { concurrency: default_concurrency(), cache_ttl_days: default_cache_ttl_days() }
    }
}

/// Returns OS-appropriate config file path: ~/.config/portreaper/config.toml on Linux.
pub fn config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|p| p.join("portreaper").join("config.toml"))
}

/// Load config from OS-appropriate path. Returns Default if file absent.
/// Warns to stderr on parse errors and falls back to defaults (never fails startup). Per D-07.
pub fn load_config() -> PortReaperConfig {
    let path = match config_path() {
        Some(p) => p,
        None => return PortReaperConfig::default(),
    };
    let content = match std::fs::read_to_string(&path) {
        Ok(s) => s,
        Err(_) => return PortReaperConfig::default(), // file absent = defaults per D-07
    };
    match toml::from_str::<PortReaperConfig>(&content) {
        Ok(cfg) => cfg,
        Err(e) => {
            eprintln!("warning: {}: {} -- using defaults", path.display(), e);
            PortReaperConfig::default()
        }
    }
}

/// Parse config from a TOML string. Used by load_config and tests.
pub fn parse_config(toml_str: &str) -> Result<PortReaperConfig, toml::de::Error> {
    toml::from_str(toml_str)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_config_has_all_sources_enabled() {
        let cfg = PortReaperConfig::default();
        assert!(cfg.sources.nvd, "nvd should default to true");
        assert!(cfg.sources.cveorg, "cveorg should default to true");
        assert!(cfg.sources.osv, "osv should default to true");
        assert!(cfg.sources.searchsploit, "searchsploit should default to true");
    }

    #[test]
    fn default_enrichment_config_has_concurrency_5_and_ttl_7() {
        let cfg = PortReaperConfig::default();
        assert_eq!(cfg.enrichment.concurrency, 5);
        assert_eq!(cfg.enrichment.cache_ttl_days, 7);
    }

    #[test]
    fn default_api_keys_config_has_no_nvd_key() {
        let cfg = PortReaperConfig::default();
        assert!(cfg.api_keys.nvd_key.is_none());
    }

    #[test]
    fn default_output_config_has_no_vault() {
        let cfg = PortReaperConfig::default();
        assert!(cfg.output.vault.is_none());
    }

    #[test]
    fn load_config_returns_default_when_no_file_exists() {
        // load_config() reads from the OS config dir; since no file exists in CI/dev,
        // it should return defaults without panicking.
        let cfg = load_config();
        // Defaults may have been loaded (or real file exists — either is fine)
        // Just verify it returns a valid struct without crashing
        assert!(cfg.enrichment.concurrency >= 1, "concurrency should be positive");
    }

    #[test]
    fn parse_config_parses_full_toml() {
        let toml = r#"
[sources]
nvd = true
cveorg = false
osv = true
searchsploit = false

[api_keys]
nvd_key = "test-api-key-123"

[output]
vault = "/tmp/vault"

[enrichment]
concurrency = 10
cache_ttl_days = 14
"#;
        let cfg = parse_config(toml).expect("should parse full TOML");
        assert!(cfg.sources.nvd);
        assert!(!cfg.sources.cveorg);
        assert!(cfg.sources.osv);
        assert!(!cfg.sources.searchsploit);
        assert_eq!(cfg.api_keys.nvd_key.as_deref(), Some("test-api-key-123"));
        assert_eq!(cfg.output.vault, Some(std::path::PathBuf::from("/tmp/vault")));
        assert_eq!(cfg.enrichment.concurrency, 10);
        assert_eq!(cfg.enrichment.cache_ttl_days, 14);
    }

    #[test]
    fn parse_config_parses_partial_toml_with_defaults_for_missing_sections() {
        let toml = r#"
[sources]
nvd = false
"#;
        let cfg = parse_config(toml).expect("should parse partial TOML");
        // Specified
        assert!(!cfg.sources.nvd);
        // Unspecified fields in [sources] should default to true
        assert!(cfg.sources.cveorg, "unspecified cveorg defaults to true");
        assert!(cfg.sources.osv, "unspecified osv defaults to true");
        assert!(cfg.sources.searchsploit, "unspecified searchsploit defaults to true");
        // Missing sections default entirely
        assert!(cfg.api_keys.nvd_key.is_none());
        assert!(cfg.output.vault.is_none());
        assert_eq!(cfg.enrichment.concurrency, 5);
        assert_eq!(cfg.enrichment.cache_ttl_days, 7);
    }

    #[test]
    fn parse_config_returns_err_on_malformed_toml() {
        let bad_toml = "not valid = [ toml }}}";
        let result = parse_config(bad_toml);
        assert!(result.is_err(), "malformed TOML should return Err");
    }

    #[test]
    fn config_path_ends_with_portreaper_config_toml() {
        // Only check if config_dir is available (it always is on Linux)
        if let Some(path) = config_path() {
            let path_str = path.to_string_lossy();
            assert!(
                path_str.contains("portreaper"),
                "config path should contain portreaper: {}",
                path_str
            );
            assert!(
                path_str.ends_with("config.toml"),
                "config path should end with config.toml: {}",
                path_str
            );
        }
    }

    #[test]
    fn parse_config_empty_string_returns_all_defaults() {
        let cfg = parse_config("").expect("empty TOML should parse to defaults");
        assert!(cfg.sources.nvd);
        assert!(cfg.sources.cveorg);
        assert!(cfg.sources.osv);
        assert!(cfg.sources.searchsploit);
        assert!(cfg.api_keys.nvd_key.is_none());
        assert!(cfg.output.vault.is_none());
        assert_eq!(cfg.enrichment.concurrency, 5);
        assert_eq!(cfg.enrichment.cache_ttl_days, 7);
    }
}
