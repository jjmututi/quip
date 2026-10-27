//! The QUIP headless node binary.
//!
//! Runs a QUIC node without Flutter. See `docs/M9.7-design.md` for the
//! configuration schema and the two modes.

mod config;
mod log;
mod mode;
mod shutdown;

use std::path::PathBuf;

use clap::Parser;

use crate::config::Config;

#[derive(Debug, Parser)]
#[command(name = "quip-node-headless", version, about)]
struct Args {
    /// Path to the TOML config file.
    #[arg(long, default_value = "quip-node.toml")]
    config: PathBuf,

    /// Parse and validate the config file without binding a node.
    #[arg(long)]
    check_config: bool,

    /// Config path to validate. Requires `--check-config`; defaults to
    /// the `--config` path when absent.
    #[arg(value_name = "PATH")]
    path: Option<PathBuf>,
}

#[tokio::main]
async fn main() -> std::process::ExitCode {
    let args = Args::parse();

    if args.path.is_some() && !args.check_config {
        eprintln!("a config path argument requires --check-config");
        return std::process::ExitCode::from(2);
    }

    let path = args.path.clone().unwrap_or_else(|| args.config.clone());

    // `Config::load` runs before `log::init`, so a load error is printed
    // with `eprintln!` rather than through `tracing`. The config error is
    // human-facing and the subscriber is not yet installed; installing it
    // first would require knowing the mode, which is what failed to load.
    let config = match Config::load(&path) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("config error: {e}");
            return std::process::ExitCode::from(2);
        }
    };

    if args.check_config {
        println!("config OK: mode = {:?}", config.mode);
        return std::process::ExitCode::SUCCESS;
    }

    log::init(config.mode);

    match mode::run(config).await {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            tracing::error!(error = %e, "node exited with error");
            std::process::ExitCode::FAILURE
        }
    }
}
