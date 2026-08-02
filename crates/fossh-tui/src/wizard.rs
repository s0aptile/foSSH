//! First-run setup wizard (§2.6/§3.11's wizard flow), driven by this
//! TUI as its own interface — not a new one.
//!
//! **Standalone/demo mode note**: in the finished architecture, the
//! watchdog generates the setup token on first start and is the only
//! thing that ever holds the live hash (chapter §3.3, not yet built —
//! see DURUM.md). Until that exists, this screen can drive the whole
//! flow itself for testing: generate a token, write it to disk once,
//! hold the hash in memory standing in for "the watchdog's stored
//! state", and verify/burn against that. Once §3.3 lands, the
//! "generate" step moves to the watchdog and this screen only ever
//! verifies against a hash it reads from the watchdog over the local
//! IPC channel — the verify/burn half below is written to already
//! match that eventual shape (`fossh_admin::setup_token` is the same
//! call either way).

use std::path::PathBuf;

use fossh_admin::setup_token::{self, TokenHash};

pub enum Step {
    NoTokenFound,
    TokenJustGenerated { plaintext: String },
    AwaitingInput,
    Verified,
    Failed(String),
}

pub struct Wizard {
    pub step: Step,
    pub token_path: PathBuf,
    pub input: String,
    /// Stands in for "the watchdog's stored hash" — see module doc.
    pending_hash: Option<TokenHash>,
}

impl Wizard {
    pub fn new(token_path: PathBuf) -> Self {
        let step = if token_path.exists() {
            Step::AwaitingInput
        } else {
            Step::NoTokenFound
        };
        Self {
            step,
            token_path,
            input: String::new(),
            pending_hash: None,
        }
    }

    pub fn generate(&mut self) {
        match setup_token::generate() {
            Ok(generated) => {
                match setup_token::write_token_file(&self.token_path, &generated.plaintext) {
                    Ok(()) => {
                        self.pending_hash = Some(generated.hash);
                        self.step = Step::TokenJustGenerated {
                            plaintext: generated.plaintext.to_string(),
                        };
                    }
                    Err(e) => self.step = Step::Failed(format!("writing token file: {e}")),
                }
            }
            Err(e) => self.step = Step::Failed(format!("generating token: {e}")),
        }
    }

    pub fn acknowledge_generated(&mut self) {
        self.step = Step::AwaitingInput;
    }

    pub fn push_char(&mut self, c: char) {
        self.input.push(c);
    }

    pub fn backspace(&mut self) {
        self.input.pop();
    }

    pub fn submit(&mut self) {
        let Some(hash) = self.pending_hash else {
            self.step = Step::Failed(
                "no stored hash to verify against yet — press 'g' to generate a token first \
                 (standalone/demo mode; a real install's watchdog holds this instead)"
                    .to_string(),
            );
            return;
        };

        if !setup_token::verify(&self.input, hash) {
            self.step = Step::Failed("token did not match".to_string());
            self.input.clear();
            return;
        }

        let path = self.token_path.clone();
        let result = setup_token::burn(&path, || {
            self.pending_hash = None;
            Ok(())
        });
        match result {
            Ok(()) => self.step = Step::Verified,
            Err(e) => self.step = Step::Failed(format!("verified, but burn failed: {e}")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_path(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "fossh-tui-wizard-test-{name}-{}",
            std::process::id()
        ))
    }

    #[test]
    fn no_token_file_starts_at_no_token_found() {
        let path = scratch_path("fresh");
        let _ = std::fs::remove_file(&path);
        let wizard = Wizard::new(path);
        assert!(matches!(wizard.step, Step::NoTokenFound));
    }

    #[test]
    fn existing_token_file_starts_at_awaiting_input() {
        let path = scratch_path("preexisting");
        let _ = std::fs::remove_file(&path);
        setup_token::write_token_file(&path, "whatever").unwrap();
        let wizard = Wizard::new(path.clone());
        assert!(matches!(wizard.step, Step::AwaitingInput));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn full_flow_generate_then_correct_input_verifies_and_burns() {
        let path = scratch_path("full-flow-happy");
        let _ = std::fs::remove_file(&path);
        let mut wizard = Wizard::new(path.clone());

        wizard.generate();
        let Step::TokenJustGenerated { plaintext } = &wizard.step else {
            panic!("expected TokenJustGenerated, got a different step");
        };
        let plaintext = plaintext.clone();
        assert!(path.exists(), "generate() must write the token file");

        wizard.acknowledge_generated();
        assert!(matches!(wizard.step, Step::AwaitingInput));

        for c in plaintext.chars() {
            wizard.push_char(c);
        }
        wizard.submit();

        assert!(matches!(wizard.step, Step::Verified));
        assert!(
            !path.exists(),
            "a successful verify must burn (delete) the token file"
        );
    }

    #[test]
    fn wrong_input_fails_without_burning() {
        let path = scratch_path("full-flow-wrong");
        let _ = std::fs::remove_file(&path);
        let mut wizard = Wizard::new(path.clone());

        wizard.generate();
        wizard.acknowledge_generated();
        for c in "definitely-the-wrong-token".chars() {
            wizard.push_char(c);
        }
        wizard.submit();

        assert!(matches!(wizard.step, Step::Failed(_)));
        assert!(
            path.exists(),
            "a failed verify must not delete the still-valid token file"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn submit_before_generating_fails_cleanly_instead_of_panicking() {
        let path = scratch_path("submit-before-generate");
        let _ = std::fs::remove_file(&path);
        setup_token::write_token_file(&path, "sometoken").unwrap();
        let mut wizard = Wizard::new(path.clone());
        assert!(matches!(wizard.step, Step::AwaitingInput));

        wizard.push_char('x');
        wizard.submit();

        assert!(matches!(wizard.step, Step::Failed(_)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn backspace_removes_the_last_character() {
        let path = scratch_path("backspace");
        let mut wizard = Wizard::new(path);
        wizard.push_char('a');
        wizard.push_char('b');
        wizard.backspace();
        assert_eq!(wizard.input, "a");
    }
}
