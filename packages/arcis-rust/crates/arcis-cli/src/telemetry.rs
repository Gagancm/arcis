//! Anonymous, opt-out usage telemetry for the Arcis CLI.
//!
//! Why this exists: we need to know how many people actually run the free CLI
//! and which commands they use, so the product is steered by real usage instead
//! of guesses. Every early open-source security tool hits the same wall (Snyk
//! famously had a thousand users it could not identify); this is the fix.
//!
//! What we DO NOT collect: source code, scanned paths, scan targets/URLs,
//! findings, request contents, IP addresses, usernames, or anything that could
//! identify a person or a codebase. The full payload is: a random install id,
//! the CLI version, the command name, OS, CPU arch, and whether it ran in CI.
//!
//! Posture: opt-out, on by default for the CLI only (the same posture used by
//! Next.js, Astro, and Homebrew for interactive developer tools). The Arcis
//! SDKs stay opt-in. Disable with `ARCIS_TELEMETRY=0` or the cross-tool
//! `DO_NOT_TRACK` standard (https://consoledonottrack.com).
//!
//! Transport: one fire-and-forget POST on a detached thread with a 2s timeout.
//! It never blocks the command, never changes its exit code, and swallows every
//! error. If the collector is unreachable, the command behaves exactly as if
//! telemetry were off.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::time::Duration;

/// Collector endpoint. Override with `ARCIS_TELEMETRY_ENDPOINT` (used by the
/// collector's own tests and if the URL moves without a CLI rebuild).
///
/// TODO(publish): replace this default with the deployed collector URL (the
/// Cloudflare Worker in `arcis-telemetry/`) before the next `@arcis/cli`
/// publish. Until then the POST fails open and no data is collected.
const DEFAULT_ENDPOINT: &str = "https://telemetry.arcis.dev/v1/cli";

/// Where the one-time notice points users to read more / opt out.
const DOC_URL: &str =
    "https://github.com/getarcis/arcis/blob/main/packages/arcis-rust/TELEMETRY.md";

/// Decide opt-out purely from the two env values, so the privacy logic is
/// unit-testable without mutating the process environment.
fn opted_out(arcis_telemetry: Option<&str>, do_not_track: Option<&str>) -> bool {
    // Explicit kill switch wins: ARCIS_TELEMETRY=0/false/off/no disables.
    if let Some(v) = arcis_telemetry {
        let v = v.trim().to_ascii_lowercase();
        if matches!(v.as_str(), "0" | "false" | "off" | "no") {
            return true;
        }
    }
    // Cross-tool standard: any value that is not empty / "0" / "false" opts out.
    if let Some(v) = do_not_track {
        let v = v.trim();
        if !v.is_empty() && v != "0" && !v.eq_ignore_ascii_case("false") {
            return true;
        }
    }
    false
}

/// True unless the user opted out via `ARCIS_TELEMETRY` or `DO_NOT_TRACK`.
pub fn enabled() -> bool {
    let a = std::env::var("ARCIS_TELEMETRY").ok();
    let d = std::env::var("DO_NOT_TRACK").ok();
    !opted_out(a.as_deref(), d.as_deref())
}

/// `~/.arcis` (or `%USERPROFILE%\.arcis`), matching the history + OSV-cache
/// convention the rest of the CLI already uses.
fn arcis_home() -> Option<PathBuf> {
    let home = std::env::var("HOME")
        .ok()
        .or_else(|| std::env::var("USERPROFILE").ok())?;
    Some(PathBuf::from(home).join(".arcis"))
}

/// Stable anonymous install id, persisted at `~/.arcis/install-id` and generated
/// once with a v4 UUID. If the home dir cannot be read or written (read-only
/// home, locked-down CI), fall back to an ephemeral id so a single run still
/// reports without accumulating a persistent identity.
fn install_id() -> String {
    if let Some(dir) = arcis_home() {
        let path = dir.join("install-id");
        if let Ok(existing) = std::fs::read_to_string(&path) {
            let id = existing.trim().to_string();
            if !id.is_empty() {
                return id;
            }
        }
        let id = uuid::Uuid::new_v4().to_string();
        let _ = std::fs::create_dir_all(&dir);
        let _ = std::fs::write(&path, &id);
        return id;
    }
    uuid::Uuid::new_v4().to_string()
}

/// Print the one-time telemetry notice to stderr, then drop a marker so it is
/// never shown again. Only on an interactive stderr, so it never appears in
/// piped output, CI logs, or the byte-for-byte parity harness (which reads
/// stdout on non-TTY paths). If stderr is not a TTY we skip without writing the
/// marker, so the next real terminal session still gets the notice once.
fn maybe_print_notice() {
    let Some(dir) = arcis_home() else { return };
    let marker = dir.join(".telemetry-notified");
    if marker.exists() {
        return;
    }
    if !std::io::stderr().is_terminal() {
        return;
    }
    let _ = std::fs::create_dir_all(&dir);
    let mut err = std::io::stderr();
    let _ = writeln!(
        err,
        "arcis collects anonymous usage stats (CLI version, command, OS) to guide \
         development. No code, findings, paths, or personal data. Opt out any time \
         with ARCIS_TELEMETRY=0. Details: {DOC_URL}"
    );
    let _ = std::fs::write(&marker, b"1");
}

fn endpoint() -> String {
    std::env::var("ARCIS_TELEMETRY_ENDPOINT")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_ENDPOINT.to_string())
}

/// Record one anonymous event for `command`. Fire-and-forget: spawns a detached
/// thread that does a short-timeout POST and returns immediately. Never blocks
/// the command, never affects its exit code, swallows every error.
pub fn record(command: &str) {
    if !enabled() {
        return;
    }
    maybe_print_notice();

    let body = serde_json::json!({
        "install_id": install_id(),
        "cli_version": env!("CARGO_PKG_VERSION"),
        "command": command,
        "os": std::env::consts::OS,
        "arch": std::env::consts::ARCH,
        "ci": std::env::var("CI").is_ok(),
    })
    .to_string();
    let url = endpoint();

    std::thread::spawn(move || {
        if let Ok(client) = reqwest::blocking::Client::builder()
            .timeout(Duration::from_secs(2))
            .build()
        {
            let _ = client
                .post(&url)
                .header("content-type", "application/json")
                .body(body)
                .send();
        }
    });
}

#[cfg(test)]
mod tests {
    use super::opted_out;

    #[test]
    fn default_is_enabled() {
        assert!(!opted_out(None, None));
    }

    #[test]
    fn arcis_telemetry_kill_switch() {
        for off in ["0", "false", "FALSE", "off", "No", " 0 "] {
            assert!(opted_out(Some(off), None), "ARCIS_TELEMETRY={off:?} should opt out");
        }
        // A truthy / unrelated value does NOT opt out (only explicit off values).
        assert!(!opted_out(Some("1"), None));
        assert!(!opted_out(Some("on"), None));
    }

    #[test]
    fn do_not_track_standard() {
        for on in ["1", "true", "yes", "anything"] {
            assert!(opted_out(None, Some(on)), "DO_NOT_TRACK={on:?} should opt out");
        }
        // The documented "tracking allowed" values do NOT opt out.
        assert!(!opted_out(None, Some("0")));
        assert!(!opted_out(None, Some("false")));
        assert!(!opted_out(None, Some("")));
    }
}
