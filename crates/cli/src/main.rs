//! The `mergelatch` command.

mod render;

use std::io::Write;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand, ValueEnum};
use mergelatch_core::{ErrorReport, ScanLimits, builtin_rules, scan_directory};

const EXIT_HELP: &str = "\
Exit codes:
  0  Scan completed, nothing detected
  1  Scan completed, one or more findings
  2  Scan incomplete: some inspections could not finish (not a pass)
  3  Error: invalid target or usage, scan did not run

The scanner reads files as data. It does not execute scanned content, run Git,
or use the network.";

#[derive(Parser)]
#[command(name = "mergelatch", version, about = "Scan a repository directory for security-sensitive misconfigurations", after_help = EXIT_HELP)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Scan a directory, such as a local checkout
    Scan {
        /// Directory to scan
        path: PathBuf,
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
    /// List the rules in the built-in ruleset
    Rules {
        /// Output format
        #[arg(long, value_enum, default_value_t = Format::Human)]
        format: Format,
    },
}

#[derive(Clone, Copy, PartialEq, Eq, ValueEnum)]
enum Format {
    Human,
    Json,
}

fn emit(text: &str) {
    // Ignore write errors such as a closed pipe; the exit code still reports the result.
    let _ = std::io::stdout().write_all(text.as_bytes());
}

fn main() -> ExitCode {
    let cli = match Cli::try_parse() {
        Ok(cli) => cli,
        Err(err) => {
            let code = if err.use_stderr() {
                render::EXIT_ERROR
            } else {
                render::EXIT_CLEAN
            };
            let _ = err.print();
            return ExitCode::from(code as u8);
        }
    };

    let code = match cli.command {
        Command::Scan { path, format } => match scan_directory(&path, &ScanLimits::default()) {
            Ok(report) => {
                match format {
                    Format::Human => emit(&render::human_report(&report)),
                    Format::Json => emit(&format!("{}\n", report.to_json())),
                }
                render::exit_code(report.status)
            }
            Err(err) => {
                match format {
                    Format::Human => eprintln!("error: {err}"),
                    Format::Json => emit(&format!(
                        "{}\n",
                        ErrorReport::new(err.to_string()).to_json()
                    )),
                }
                render::EXIT_ERROR
            }
        },
        Command::Rules { format } => {
            let rules = builtin_rules();
            match format {
                Format::Human => emit(&render::human_rules(&rules)),
                Format::Json => emit(&format!(
                    "{}\n",
                    serde_json::to_string_pretty(&rules).expect("rules serialize")
                )),
            }
            render::EXIT_CLEAN
        }
    };
    ExitCode::from(code as u8)
}
