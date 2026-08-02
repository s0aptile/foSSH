use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};

use crate::data::{self, SiteSummary};
use crate::wizard::Wizard;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Telemetry,
    Wizard,
}

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub data_dir: PathBuf,
    pub k_anonymity: u32,
    pub sites: Result<Vec<SiteSummary>, String>,
    pub wizard: Wizard,
}

impl App {
    pub fn new(data_dir: PathBuf, k_anonymity: u32, setup_token_path: PathBuf) -> Self {
        let sites = data::load_summary(&data_dir, unix_now(), k_anonymity);
        Self {
            screen: Screen::Dashboard,
            should_quit: false,
            data_dir,
            k_anonymity,
            sites,
            wizard: Wizard::new(setup_token_path),
        }
    }

    pub fn refresh_sites(&mut self) {
        self.sites = data::load_summary(&self.data_dir, unix_now(), self.k_anonymity);
    }

    pub fn on_key(&mut self, key: KeyEvent) {
        // The wizard screen owns text input (the token itself) while
        // it's actively awaiting one, so its own key handling takes
        // priority over the global nav keys below whenever that's the
        // active step — otherwise typing a digit into the token field
        // would also switch screens.
        if self.screen == Screen::Wizard && self.wizard_wants_raw_input() {
            self.on_wizard_key(key);
            return;
        }

        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.should_quit = true,
            KeyCode::Char('1') => self.screen = Screen::Dashboard,
            KeyCode::Char('2') => {
                self.screen = Screen::Telemetry;
                self.refresh_sites();
            }
            KeyCode::Char('3') => self.screen = Screen::Wizard,
            KeyCode::Char('r') if self.screen == Screen::Telemetry => self.refresh_sites(),
            _ => self.on_wizard_key(key),
        }
    }

    fn wizard_wants_raw_input(&self) -> bool {
        matches!(self.wizard.step, crate::wizard::Step::AwaitingInput)
    }

    fn on_wizard_key(&mut self, key: KeyEvent) {
        if self.screen != Screen::Wizard {
            return;
        }
        use crate::wizard::Step;
        match &self.wizard.step {
            Step::NoTokenFound => {
                if key.code == KeyCode::Char('g') {
                    self.wizard.generate();
                }
            }
            Step::TokenJustGenerated { .. } => {
                if key.code == KeyCode::Enter {
                    self.wizard.acknowledge_generated();
                }
            }
            Step::AwaitingInput => match key.code {
                KeyCode::Enter => self.wizard.submit(),
                KeyCode::Backspace => self.wizard.backspace(),
                KeyCode::Char(c) => self.wizard.push_char(c),
                // Esc backs out of token entry back to the dashboard —
                // it must not quit the whole app here. The raw-input
                // priority gate above (`wizard_wants_raw_input`) routes
                // *every* key through this arm while typing, including
                // 'q'/'1'/'2'/'3', so — unlike every other screen —
                // Esc was the operator's only working key at all while
                // here; quitting on it (the pre-fix behavior) was a
                // trap with no way to just cancel back to a menu.
                KeyCode::Esc => {
                    self.wizard.cancel_input();
                    self.screen = Screen::Dashboard;
                }
                _ => {}
            },
            Step::Verified => {}
            Step::Failed(_) => {
                if key.code == KeyCode::Enter {
                    self.wizard.step = Step::AwaitingInput;
                }
            }
        }
    }
}

pub fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crossterm::event::KeyModifiers;
    use fossh_admin::setup_token;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("fossh-tui-app-test-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn key(code: KeyCode) -> KeyEvent {
        KeyEvent::new(code, KeyModifiers::NONE)
    }

    /// An `App` already on the Wizard screen, awaiting token input
    /// against a real pre-existing token file — the raw-input-capture
    /// state every test below actually cares about.
    fn app_awaiting_token_input(data_dir: PathBuf, token_path: PathBuf) -> App {
        setup_token::write_token_file(&token_path, "the-real-token").unwrap();
        let mut app = App::new(data_dir, 5, token_path);
        app.screen = Screen::Wizard;
        assert!(matches!(
            app.wizard.step,
            crate::wizard::Step::AwaitingInput
        ));
        app
    }

    #[test]
    fn esc_during_token_entry_cancels_back_to_dashboard_instead_of_quitting() {
        // Regression test: before the fix, Esc was hard-wired to quit
        // the whole app even from inside raw token-input capture — the
        // *only* global key that did anything at all in that state,
        // since every other nav/quit key is swallowed into the token
        // buffer instead (see the test below). That left no way to
        // just back out of typing without exiting entirely.
        let dir = scratch_dir("esc-cancel");
        let token_path = dir.join("setup-token");
        let mut app = app_awaiting_token_input(dir.clone(), token_path);

        app.on_key(key(KeyCode::Char('a')));
        app.on_key(key(KeyCode::Char('b')));
        assert_eq!(app.wizard.input.as_str(), "ab");

        app.on_key(key(KeyCode::Esc));

        assert!(!app.should_quit, "Esc must cancel input, not quit the app");
        assert!(matches!(app.screen, Screen::Dashboard));
        assert_eq!(
            app.wizard.input.as_str(),
            "",
            "canceling must clear whatever had been typed"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nav_and_quit_keys_are_captured_as_token_text_during_input() {
        let dir = scratch_dir("nav-swallowed");
        let token_path = dir.join("setup-token");
        let mut app = app_awaiting_token_input(dir.clone(), token_path);

        for c in ['q', '1', '2', '3'] {
            app.on_key(key(KeyCode::Char(c)));
        }

        assert_eq!(
            app.wizard.input.as_str(),
            "q123",
            "every ordinary character must reach the token buffer while \
             awaiting input, never be treated as navigation"
        );
        assert!(!app.should_quit);
        assert!(matches!(app.screen, Screen::Wizard));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn q_quits_from_the_dashboard() {
        let dir = scratch_dir("q-quits");
        let mut app = App::new(dir.clone(), 5, dir.join("setup-token"));
        assert!(matches!(app.screen, Screen::Dashboard));

        app.on_key(key(KeyCode::Char('q')));

        assert!(app.should_quit);
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn digit_keys_switch_screens_from_the_dashboard() {
        let dir = scratch_dir("digit-nav");
        let mut app = App::new(dir.clone(), 5, dir.join("setup-token"));

        app.on_key(key(KeyCode::Char('2')));
        assert!(matches!(app.screen, Screen::Telemetry));

        app.on_key(key(KeyCode::Char('3')));
        assert!(matches!(app.screen, Screen::Wizard));

        app.on_key(key(KeyCode::Char('1')));
        assert!(matches!(app.screen, Screen::Dashboard));
        std::fs::remove_dir_all(&dir).ok();
    }
}
