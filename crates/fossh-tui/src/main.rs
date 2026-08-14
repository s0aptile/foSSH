//! foSSH local admin console (chapter §3.9) and first-run setup wizard
//! interface (§3.11). Never *listens* on a network socket — the
//! dashboard's live watchdog/tamper-detection status (`ui.rs`'s
//! `draw_dashboard`, `watchdog_status.rs`) is a client of §3.4's
//! existing QUIC/mTLS command channel, the same one
//! `fossh-fcgi`/`fossh-watchdog` already speak, dialed out on demand.
//! The wizard screen (`wizard.rs`) is likewise a real client of
//! `operator_auth_client`'s SETUP flow against the watchdog's own
//! `Operator_auth_server` socket — not a standalone/demo mode; see
//! `wizard.rs`'s own module doc for the full protocol and DECISIONS.md's
//! ADR-0057 for the server side this closes the client-side gap for.
//!
//! Bracketed paste is enabled explicitly (`EnableBracketedPaste`, not
//! part of `ratatui::init`'s own defaults) purely for the wizard's key-
//! paste step: an armored PGP public key block is always pasted, never
//! typed character by character, and without this a paste containing
//! embedded newlines would otherwise arrive as a flood of individual
//! `Enter`-coded key events indistinguishable from the operator
//! actually pressing Enter partway through.

#![forbid(unsafe_code)]

mod app;
mod data;
mod operator_auth;
mod operator_auth_client;
mod theme;
mod ui;
mod watchdog_status;
mod wizard;

use std::path::PathBuf;

use app::App;

fn main() -> std::io::Result<()> {
    let data_dir = std::env::var_os("FOSSH_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/fossh"));
    // `.filter(|&k| k >= 1)`: P6/S-equivalent invariant this project
    // already enforces elsewhere (`fossh-cli`'s `doctor` names this
    // exact check) — `k_anonymity = 0` would fold nothing into
    // `(other)` at all, silently defeating the k-anonymity this
    // screen's own header claims ("k-anonymized"). An unset or
    // unparseable value already fell back to the safe default; an
    // explicit but invalid `0` must too, not sail through unchecked.
    let k_anonymity: u32 = std::env::var("FOSSH_K_ANONYMITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&k| k >= 1)
        .unwrap_or(5);
    // §2.6's fixed path is /etc/fossh/setup-token; overridable so this
    // can be exercised end to end without root in a dev environment.
    let setup_token_path = std::env::var_os("FOSSH_SETUP_TOKEN_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/fossh/setup-token"));

    let mut app = App::new(data_dir, k_anonymity, setup_token_path);

    let mut terminal = ratatui::init();
    // Best-effort: a terminal that doesn't understand bracketed paste
    // just ignores the escape sequence, so a failure here (e.g.
    // `stdout` genuinely not a TTY) degrades to character-by-character
    // paste input rather than being fatal — matching this crate's own
    // established `ratatui::restore()` idiom below of not treating
    // terminal-capability plumbing as something to `unwrap`.
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::EnableBracketedPaste);
    let result = run(&mut terminal, &mut app);
    let _ = crossterm::execute!(std::io::stdout(), crossterm::event::DisableBracketedPaste);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;
        if crossterm::event::poll(std::time::Duration::from_millis(100))? {
            match crossterm::event::read()? {
                crossterm::event::Event::Key(key) => app.on_key(key),
                crossterm::event::Event::Paste(text) => app.on_paste(&text),
                _ => {}
            }
        }
    }
    Ok(())
}
