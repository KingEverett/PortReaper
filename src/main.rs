mod cli;
mod render;

use portreaper::parser;
use std::io::Read;
use std::process::ExitCode;
use std::sync::Arc;
use clap::Parser;
use is_terminal::IsTerminal;

#[tokio::main]
async fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    match run(&cli).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            let code = if is_no_input_error(&e) { 2 } else { 1 };
            eprintln!("error: {}", e);

            // Per locked decision: contextual error messages with suggestions
            if code == 2 {
                eprintln!("hint: provide nmap scan file(s) as arguments, or pipe nmap output via stdin");
                eprintln!("  portreaper scan.xml");
                eprintln!("  nmap -sV target | portreaper");
            } else {
                eprintln!("hint: expected nmap XML (-oX), text, or greppable (-oG) format");
                eprintln!("  try: nmap -oX scan.xml target");
            }

            ExitCode::from(code)
        }
    }
}

async fn run(cli: &cli::Cli) -> anyhow::Result<()> {
    let start = std::time::Instant::now(); // D-12: elapsed time

    let cfg = portreaper::config::load_config();

    // D-06: one-time hint if config has API key
    if cfg.api_keys.nvd_key.is_some() {
        eprintln!("Tip: API keys can also be set via env vars (PORTREAPER_NVD_KEY) to avoid storing in plaintext.");
    }

    let inputs = get_inputs(cli)?;
    let mut result = parser::parse_and_merge(inputs)?;

    if !cli.no_enrich {
        let opts = portreaper::enrichment::EnrichmentOptions {
            concurrency: cfg.enrichment.concurrency, // was hardcoded 5
            quiet: cli.quiet,
            fresh: cli.fresh,
            disabled_sources: {
                // D-09: merge config-disabled and CLI-disabled sources
                let mut disabled: Vec<String> = cli.disable_sources.iter().map(|s| s.to_lowercase()).collect();
                if !cfg.sources.nvd { disabled.push("nvd".to_string()); }
                if !cfg.sources.cveorg { disabled.push("cveorg".to_string()); }
                if !cfg.sources.osv { disabled.push("osv".to_string()); }
                if !cfg.sources.searchsploit { disabled.push("searchsploit".to_string()); }
                disabled
            },
            cache_ttl_secs: (cfg.enrichment.cache_ttl_days as i64) * 86400, // days -> seconds
        };

        // D-05 priority: env var > config > none
        let nvd_key = std::env::var("PORTREAPER_NVD_KEY").ok()
            .or_else(|| cfg.api_keys.nvd_key.clone());

        let nvd = if opts.source_enabled("nvd") {
            Some(Arc::new(portreaper::sources::nvd::NvdSource::new(nvd_key)))
        } else {
            None
        };

        let cve_org = if opts.source_enabled("cveorg") {
            Some(Arc::new(portreaper::sources::cve_org::CveOrgSource::new()))
        } else {
            None
        };

        let osv = if opts.source_enabled("osv") {
            Some(Arc::new(portreaper::sources::osv::OsvSource::new()))
        } else {
            None
        };

        let searchsploit = if opts.source_enabled("searchsploit") {
            match portreaper::sources::searchsploit::SearchSploitSource::try_new() {
                Some(s) => Some(Arc::new(s)),
                None => {
                    if !cli.quiet {
                        eprintln!("searchsploit not found — skipping exploit lookup");
                    }
                    None
                }
            }
        } else {
            None
        };

        let stats = portreaper::enrichment::enrich_scan(
            &mut result, nvd, cve_org, osv, searchsploit, &opts
        ).await;

        // Print source failure warnings to stderr per D-05
        for failure in &stats.source_failures {
            eprintln!("Warning: {}", failure);
        }

        // Print source status summary per D-16
        if !cli.quiet && !stats.source_status.is_empty() {
            let status_line: Vec<String> = stats.source_status.iter()
                .map(|(name, ok)| if *ok { format!("{} OK", name) } else { format!("{} FAIL", name) })
                .collect();
            eprintln!("Sources: {}", status_line.join(", "));
        }
    }

    // D-09: CLI vault path overrides config vault path
    let vault_path = cli.vault.as_ref().or(cfg.output.vault.as_ref());
    if let Some(vault_path) = vault_path {
        // D-03: detect existing scan subfolder by IP overlap before falling back to derive_scan_label
        let scan_label = portreaper::vault::find_merge_target(vault_path, &result)
            .unwrap_or_else(|| portreaper::vault::derive_scan_label(&result.source));
        let stats = portreaper::vault::generate_vault(&result, vault_path, &scan_label)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        eprintln!(
            "Vault generated: {} hosts, {} services, {} CVEs, {} technologies",
            stats.hosts, stats.services, stats.cves, stats.technologies
        );
        eprintln!("Output: {}", vault_path.display());
        eprintln!("Completed in {:.1}s", start.elapsed().as_secs_f64()); // D-12
        return Ok(());
    }

    let use_color = std::io::stdout().is_terminal();
    let opts = render::tree::RenderOptions {
        verbose: cli.verbose,
        quiet: cli.quiet,
        use_color,
    };

    render::tree::render_tree(&result, &opts);
    eprintln!("Completed in {:.1}s", start.elapsed().as_secs_f64()); // D-12
    Ok(())
}

/// Read input from files or stdin.
/// Per locked decision: when stdin is a TTY with no file args, show error and exit 2.
fn get_inputs(cli: &cli::Cli) -> anyhow::Result<Vec<(String, String)>> {
    if cli.files.is_empty() {
        if std::io::stdin().is_terminal() {
            // No files, stdin is interactive -- error (exit 2)
            anyhow::bail!("no input provided");
        }
        // stdin is piped -- read it
        let mut buf = String::new();
        std::io::stdin().read_to_string(&mut buf)?;
        if buf.trim().is_empty() {
            anyhow::bail!("no input provided (stdin was empty)");
        }
        Ok(vec![("stdin".to_string(), buf)])
    } else {
        let mut inputs = Vec::new();
        for path in &cli.files {
            if !path.exists() {
                anyhow::bail!("file not found: {}", path.display());
            }
            let content = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("could not read {}: {}", path.display(), e))?;
            inputs.push((path.display().to_string(), content));
        }
        Ok(inputs)
    }
}

/// Check if error is a "no input" type (for exit code 2 vs 1 distinction).
fn is_no_input_error(e: &anyhow::Error) -> bool {
    let msg = e.to_string();
    msg.contains("no input") || msg.contains("file not found")
}
