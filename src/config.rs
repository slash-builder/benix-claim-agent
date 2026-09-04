//! Env-var configuration, all optional, all with a documented default — no
//! config file, matching `benix-mdns-advertiser`'s convention.

use std::env;
use std::path::PathBuf;

/// Shared with `benix-mdns-advertiser` **on purpose** — its SRV record and
/// this endpoint's actual listen port must always agree, and reusing the
/// identical env var name is the cheapest way to keep them from silently
/// drifting apart if someone overrides one binary's port and not the
/// other's. This is a real, named integration risk (finalized contract,
/// `context/projects/benixos.md` §9j): there is no single shared
/// environment source yet for the two binaries, so a `meta-benixos`
/// dinit-unit pass (out of scope for this repo) needs to land one rather
/// than let each binary default independently. Flagged again in README.md.
const PORT_ENV_VAR: &str = "BENIX_MDNS_PORT";
const DEFAULT_PORT: u16 = 8420;

const STATE_DIR_ENV_VAR: &str = "BENIX_CLAIM_STATE_DIR";
const DEFAULT_STATE_DIR: &str = "/var/lib/benixos";

const RATE_LIMIT_ENV_VAR: &str = "BENIX_CLAIM_RATE_LIMIT_PER_MIN";
const DEFAULT_RATE_LIMIT_PER_MIN: u32 = 10;

const DEVICE_NAME_ENV_VAR: &str = "BENIX_CLAIM_DEVICE_NAME";

/// §9rr tty1-visibility follow-up: how long to wait after startup, before
/// writing the claim screen, so it lands after (not racing/before) the
/// `agetty` login prompt dinit's own `tty1` unit already puts on the same
/// device (see `render.rs`'s module doc for the full reasoning and why
/// this is deliberately pragmatic coexistence, not the clean dinit-level
/// "claim screen owns tty1 while unclaimed" redesign named as a follow-up
/// in `context/projects/benixos.md` §9rr, task #64). `0` disables the
/// delay entirely — used by this crate's own tests so they don't pay a
/// real sleep, and available for any environment where the ordering
/// doesn't matter (e.g. a bare stdout fallback with no getty at all).
const CLAIM_SCREEN_DELAY_MS_ENV_VAR: &str = "BENIX_CLAIM_SCREEN_DELAY_MS";
const DEFAULT_CLAIM_SCREEN_DELAY_MS: u64 = 1500;

#[derive(Debug, Clone)]
pub struct Config {
    pub port: u16,
    pub state_dir: PathBuf,
    pub rate_limit_per_min: u32,
    pub device_name: String,
    pub claim_screen_delay_ms: u64,
}

impl Config {
    pub fn from_env() -> Self {
        let port = env::var(PORT_ENV_VAR)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_PORT);

        let state_dir = PathBuf::from(
            env::var(STATE_DIR_ENV_VAR).unwrap_or_else(|_| DEFAULT_STATE_DIR.to_string()),
        );

        let rate_limit_per_min = env::var(RATE_LIMIT_ENV_VAR)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_RATE_LIMIT_PER_MIN);

        let device_name = env::var(DEVICE_NAME_ENV_VAR).unwrap_or_else(|_| default_device_name());

        let claim_screen_delay_ms = env::var(CLAIM_SCREEN_DELAY_MS_ENV_VAR)
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(DEFAULT_CLAIM_SCREEN_DELAY_MS);

        Self {
            port,
            state_dir,
            rate_limit_per_min,
            device_name,
            claim_screen_delay_ms,
        }
    }
}

fn default_device_name() -> String {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "benixos".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_match_the_finalized_contract() {
        // Isolated from the process's real environment on purpose — a
        // stray BENIX_* var set on the CI runner or a developer's shell
        // must not silently change what this test asserts.
        for var in [
            PORT_ENV_VAR,
            STATE_DIR_ENV_VAR,
            RATE_LIMIT_ENV_VAR,
            DEVICE_NAME_ENV_VAR,
            CLAIM_SCREEN_DELAY_MS_ENV_VAR,
        ] {
            env::remove_var(var);
        }
        let config = Config::from_env();
        assert_eq!(config.port, 8420);
        assert_eq!(config.state_dir, PathBuf::from("/var/lib/benixos"));
        assert_eq!(config.rate_limit_per_min, 10);
        assert!(!config.device_name.is_empty());
        assert_eq!(config.claim_screen_delay_ms, 1500);
    }
}
