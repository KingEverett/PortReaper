mod cli;
mod render;

use portreaper::parser;
use std::io::Read;
use std::process::ExitCode;
use clap::Parser;
use is_terminal::IsTerminal;

fn main() -> ExitCode {
    let cli = cli::Cli::parse();

    match run(&cli) {
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

fn run(cli: &cli::Cli) -> anyhow::Result<()> {
    let inputs = get_inputs(cli)?;
    let result = parser::parse_and_merge(inputs)?;

    let use_color = std::io::stdout().is_terminal();
    let opts = render::tree::RenderOptions {
        verbose: cli.verbose,
        quiet: cli.quiet,
        use_color,
    };

    render::tree::render_tree(&result, &opts);
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
