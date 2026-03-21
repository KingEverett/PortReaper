use clap::Parser;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "portreaper")]
#[command(version)]
#[command(about = "Parse nmap scans into structured, enriched results")]
#[command(long_about = "PortReaper parses nmap scan output (XML, text, or greppable format) and displays a structured tree view of discovered hosts, ports, services, and versions.\n\nExamples:\n  portreaper scan.xml\n  portreaper scan1.xml scan2.xml\n  nmap -sV target | portreaper\n  cat scan.xml | portreaper")]
pub struct Cli {
    /// nmap scan file(s) -- XML (-oX), text, or greppable (-oG). Reads stdin if omitted and stdin is piped.
    pub files: Vec<PathBuf>,

    /// Verbose: show CPE strings, OS detection, extra service fields
    #[arg(short = 'v', long)]
    pub verbose: bool,

    /// Quiet: show summary line only
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Enrich results with vulnerability lookups (Phase 2)
    #[arg(long, hide = true)]
    pub enrich: bool,

    /// Output Obsidian vault to directory (Phase 3)
    #[arg(long, hide = true)]
    pub vault: Option<PathBuf>,
}
