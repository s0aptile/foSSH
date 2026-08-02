//! foSSH local admin console (chapter §3.9) and first-run setup wizard
//! interface (§3.11). Local-only by design: this binary never opens a
//! network socket of its own — see `app.rs`'s dashboard screen for
//! what that means today (the watchdog it will eventually talk to over
//! a local QUIC/Unix-socket channel, per §3.4, doesn't exist yet; see
//! DURUM.md).

mod app;
mod data;
mod ui;
mod wizard;

use std::path::PathBuf;

use app::App;

fn main() -> std::io::Result<()> {
    let data_dir = std::env::var_os("FOSSH_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/fossh"));
    let k_anonymity: u32 = std::env::var("FOSSH_K_ANONYMITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(5);
    // §2.6's fixed path is /etc/fossh/setup-token; overridable so this
    // can be exercised end to end without root in a dev environment.
    let setup_token_path = std::env::var_os("FOSSH_SETUP_TOKEN_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/fossh/setup-token"));

    let mut app = App::new(data_dir, k_anonymity, setup_token_path);

    let mut terminal = ratatui::init();
    let result = run(&mut terminal, &mut app);
    ratatui::restore();
    result
}

fn run(terminal: &mut ratatui::DefaultTerminal, app: &mut App) -> std::io::Result<()> {
    while !app.should_quit {
        terminal.draw(|frame| ui::draw(frame, app))?;
        if crossterm::event::poll(std::time::Duration::from_millis(100))?
            && let crossterm::event::Event::Key(key) = crossterm::event::read()?
        {
            app.on_key(key);
        }
    }
    Ok(())
}
