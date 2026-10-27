//! Logging initialisation.
//!
//! Production logs JSON (a VPS log shipper wants it); Development logs
//! human-readable (a contributor's terminal does not). One `if mode`
//! is the whole difference.

use tracing_subscriber::{fmt, EnvFilter};

use crate::config::Mode;

pub fn init(mode: Mode) {
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info"));
    match mode {
        Mode::Development => {
            fmt().with_env_filter(filter).with_target(true).init();
        }
        Mode::Production => {
            fmt()
                .json()
                .with_env_filter(filter)
                .with_target(true)
                .init();
        }
    }
}
