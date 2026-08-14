use std::path::PathBuf;

use crossterm::event::{KeyCode, KeyEvent};

use crate::data::{self, SiteSummary};
use crate::operator_auth::OperatorAuth;
use crate::watchdog_status::{self, WatchdogStatus};
use crate::wizard::Wizard;

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    Telemetry,
    Wizard,
    OperatorAuth,
}

pub struct App {
    pub screen: Screen,
    pub should_quit: bool,
    pub data_dir: PathBuf,
    pub k_anonymity: u32,
    pub sites: Result<Vec<SiteSummary>, String>,
    pub watchdog_status: Result<WatchdogStatus, String>,
    pub wizard: Wizard,
    pub operator_auth: OperatorAuth,
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
            // Not queried eagerly here — see watchdog_status.rs's own
            // module doc for why: unlike `sites` (fast local sqlite
            // I/O), this is a network call with no fast-fail path when
            // nothing is listening, and blocking every app launch on
            // that would be a bad default. `r` on the dashboard
            // triggers the real first check.
            watchdog_status: Err("not checked yet — press r on the dashboard to check".to_string()),
            wizard: Wizard::new(setup_token_path),
            operator_auth: OperatorAuth::new(),
        }
    }

    pub fn refresh_sites(&mut self) {
        self.sites = data::load_summary(&self.data_dir, unix_now(), self.k_anonymity);
    }

    pub fn refresh_watchdog_status(&mut self) {
        self.watchdog_status = watchdog_status::query();
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
            KeyCode::Char('1') => {
                self.screen = Screen::Dashboard;
                self.refresh_watchdog_status();
            }
            KeyCode::Char('2') => {
                self.screen = Screen::Telemetry;
                self.refresh_sites();
            }
            KeyCode::Char('3') => self.screen = Screen::Wizard,
            KeyCode::Char('4') => self.screen = Screen::OperatorAuth,
            KeyCode::Char('r') if self.screen == Screen::Telemetry => self.refresh_sites(),
            KeyCode::Char('r') if self.screen == Screen::Dashboard => {
                self.refresh_watchdog_status()
            }
            KeyCode::Char('a') if self.screen == Screen::OperatorAuth => {
                self.operator_auth.attempt()
            }
            _ => self.on_wizard_key(key),
        }
    }

    /// Only `PastingKey` owns raw text input the way the old single
    /// `AwaitingInput` step did — every other step advances on
    /// dedicated single-key presses (`g`/`p`/Enter), so global nav
    /// keys stay live there.
    fn wizard_wants_raw_input(&self) -> bool {
        matches!(self.wizard.step, crate::wizard::Step::PastingKey { .. })
    }

    fn on_wizard_key(&mut self, key: KeyEvent) {
        if self.screen != Screen::Wizard {
            return;
        }
        use crate::wizard::Step;
        match &self.wizard.step {
            Step::NoTokenFound => {
                if key.code == KeyCode::Enter {
                    self.wizard.reset();
                }
            }
            Step::ReadyToSubmit { .. } => {
                if key.code == KeyCode::Enter {
                    self.wizard.proceed_to_key_source();
                }
            }
            Step::ChoosingKeySource { .. } => match key.code {
                KeyCode::Char('p') => self.wizard.start_paste(),
                KeyCode::Char('g') => self.wizard.generate_fresh_key(),
                _ => {}
            },
            Step::PastingKey { .. } => match key.code {
                KeyCode::Enter => self.wizard.submit_pasted_key(),
                KeyCode::Backspace => self.wizard.backspace_paste(),
                KeyCode::Char(c) => self.wizard.push_paste_char(c),
                // Esc backs out of key entry to choosing a key source,
                // not the whole app — same reasoning the old
                // AwaitingInput step already established here: the
                // raw-input priority gate above routes *every* key
                // through this arm while typing, including
                // 'q'/'1'/'2'/'3', so Esc must stay a working way out.
                KeyCode::Esc => self.wizard.cancel_paste(),
                _ => {}
            },
            Step::KeyGenerated { .. } => {
                if key.code == KeyCode::Enter {
                    self.wizard.acknowledge_generated_key();
                }
            }
            Step::Enrolled { .. } => {}
            Step::TokenDenied => {
                if key.code == KeyCode::Enter {
                    self.wizard.reset();
                }
            }
            Step::EnrollFailed { .. } => {
                if key.code == KeyCode::Enter {
                    self.wizard.retry_after_enroll_failure();
                }
            }
            Step::Failed(_) => {
                if key.code == KeyCode::Enter {
                    self.wizard.reset();
                }
            }
        }
    }

    /// Bracketed-paste text, routed here only while the wizard is
    /// actively collecting an armored key block — every other screen
    /// has nothing that accepts free text, so a paste anywhere else is
    /// simply dropped rather than leaking into some unrelated field.
    pub fn on_paste(&mut self, text: &str) {
        if self.screen == Screen::Wizard
            && matches!(self.wizard.step, crate::wizard::Step::PastingKey { .. })
        {
            self.wizard.push_paste_str(text);
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

    /// An `App` already on the Wizard screen, pasting key text against
    /// a real pre-existing token file — the raw-input-capture state
    /// every test below actually cares about.
    fn app_pasting_key(data_dir: PathBuf, token_path: PathBuf) -> App {
        setup_token::write_token_file(&token_path, "the-real-token").unwrap();
        let mut app = App::new(data_dir, 5, token_path);
        app.screen = Screen::Wizard;
        app.wizard.proceed_to_key_source();
        app.wizard.start_paste();
        assert!(matches!(
            app.wizard.step,
            crate::wizard::Step::PastingKey { .. }
        ));
        app
    }

    fn pasted_input(app: &App) -> &str {
        match &app.wizard.step {
            crate::wizard::Step::PastingKey { input, .. } => input.as_str(),
            _ => panic!("expected PastingKey"),
        }
    }

    #[test]
    fn esc_during_key_paste_cancels_back_to_choosing_key_source_instead_of_quitting() {
        // Regression test: before the fix (back when this was the
        // demo-mode token-entry step, not key-paste), Esc was
        // hard-wired to quit the whole app even from inside raw
        // input capture — the *only* global key that did anything at
        // all in that state, since every other nav/quit key is
        // swallowed into the input buffer instead (see the test
        // below). That left no way to just back out of typing without
        // exiting entirely. Still true for the current PastingKey step.
        let dir = scratch_dir("esc-cancel");
        let token_path = dir.join("setup-token");
        let mut app = app_pasting_key(dir.clone(), token_path);

        app.on_key(key(KeyCode::Char('a')));
        app.on_key(key(KeyCode::Char('b')));
        assert_eq!(pasted_input(&app), "ab");

        app.on_key(key(KeyCode::Esc));

        assert!(!app.should_quit, "Esc must cancel input, not quit the app");
        assert!(
            matches!(app.screen, Screen::Wizard),
            "Esc from key-paste backs out to choosing a key source, still on the wizard screen \
             — unlike the old token-entry step, this isn't the first step, so there's no reason \
             to leave the wizard screen entirely"
        );
        assert!(matches!(
            app.wizard.step,
            crate::wizard::Step::ChoosingKeySource { .. }
        ));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn nav_and_quit_keys_are_captured_as_key_text_during_paste() {
        let dir = scratch_dir("nav-swallowed");
        let token_path = dir.join("setup-token");
        let mut app = app_pasting_key(dir.clone(), token_path);

        for c in ['q', '1', '2', '3'] {
            app.on_key(key(KeyCode::Char(c)));
        }

        assert_eq!(
            pasted_input(&app),
            "q123",
            "every ordinary character must reach the key-paste buffer while \
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

        app.on_key(key(KeyCode::Char('4')));
        assert!(matches!(app.screen, Screen::OperatorAuth));

        app.on_key(key(KeyCode::Char('1')));
        assert!(matches!(app.screen, Screen::Dashboard));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_on_the_operator_auth_screen_triggers_an_attempt() {
        // No env override here -- this crate is `#![forbid(unsafe_code)]`,
        // and `std::env::set_var`/`remove_var` are `unsafe` as of this
        // toolchain, so a test can't safely override
        // FOSSH_OPERATOR_AUTH_SOCKET at all (nor would that be safe
        // against `cargo test`'s parallelism: it's a process-global
        // var). Relies instead on the real default path
        // (`/var/lib/fossh-watchdog/operator-auth.sock`) genuinely not
        // existing in a test environment -- the point of this test is
        // only that pressing 'a' actually calls into
        // `OperatorAuth::attempt` (an `Unreachable` failure, not
        // `NotAttempted` still), not that the attempt succeeds.
        let dir = scratch_dir("operator-auth-attempt");
        let mut app = App::new(dir.clone(), 5, dir.join("setup-token"));
        app.on_key(key(KeyCode::Char('4')));
        assert!(matches!(app.screen, Screen::OperatorAuth));

        app.on_key(key(KeyCode::Char('a')));

        assert!(!matches!(
            app.operator_auth.step,
            crate::operator_auth::Step::NotAttempted
        ));
        std::fs::remove_dir_all(&dir).ok();
    }
}
