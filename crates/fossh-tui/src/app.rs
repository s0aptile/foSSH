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
                KeyCode::Esc => self.should_quit = true,
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
