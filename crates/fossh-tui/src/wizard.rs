//! First-run setup wizard (§2.6/§3.11's wizard flow), driven by this
//! TUI as its own interface — not a new one.
//!
//! **Standalone/demo mode note**: in the finished architecture, the
//! watchdog generates the setup token on first start and is the only
//! thing that ever holds the live hash (chapter §3.3, not yet built —
//! see dev/DURUM.md). Until that exists, this screen can drive the whole
//! flow itself for testing: generate a token, write it to disk once,
//! hold the hash in memory standing in for "the watchdog's stored
//! state", and verify/burn against that. Once §3.3 lands, the
//! "generate" step moves to the watchdog and this screen only ever
//! verifies against a hash it reads from the watchdog over the local
//! IPC channel — the verify/burn half below is written to already
//! match that eventual shape (`fossh_admin::setup_token` is the same
//! call either way).

use std::fs;
use std::path::PathBuf;

use zeroize::{Zeroize, Zeroizing};

use fossh_admin::setup_token::{self, TokenHash};

pub enum Step {
    NoTokenFound,
    TokenJustGenerated { plaintext: Zeroizing<String> },
    AwaitingInput,
    Verified,
    Failed(String),
}

pub struct Wizard {
    pub step: Step,
    pub token_path: PathBuf,
    pub input: Zeroizing<String>,
    /// Stands in for "the watchdog's stored hash" — see module doc.
    pending_hash: Option<TokenHash>,
}

impl Wizard {
    pub fn new(token_path: PathBuf) -> Self {
        // Reading the file (not just `Path::exists()`) does two things
        // at once: distinguishes "genuinely absent" from "exists but
        // this process can't read it" (a bare `exists()` check reports
        // `false` for both, silently misreporting a real permission
        // problem as "no token yet"), and — the more important reason —
        // recovers `pending_hash` for a token file this process didn't
        // just generate itself. Without this, reopening the TUI between
        // generating a token and verifying it (exactly the shape this
        // becomes once §3.3's watchdog exists and always writes the
        // file in a separate process from this one) left `pending_hash`
        // permanently `None`, so `submit()` could never succeed no
        // matter what was typed — caught by adversarial review, not
        // exercised by the original test suite, which only asserted the
        // starting `Step`, never a full generate-restart-verify cycle.
        let (step, pending_hash) = match fs::read_to_string(&token_path) {
            Ok(plaintext) => (
                Step::AwaitingInput,
                Some(setup_token::hash_of(plaintext.trim())),
            ),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Step::NoTokenFound, None),
            Err(e) => (
                Step::Failed(format!("reading the setup token file: {e}")),
                None,
            ),
        };
        Self {
            step,
            token_path,
            input: Zeroizing::new(String::new()),
            pending_hash,
        }
    }

    pub fn generate(&mut self) {
        match setup_token::generate() {
            Ok(generated) => {
                match setup_token::write_token_file(&self.token_path, &generated.plaintext) {
                    Ok(()) => {
                        self.pending_hash = Some(generated.hash);
                        self.step = Step::TokenJustGenerated {
                            plaintext: generated.plaintext,
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

    /// Discards whatever has been typed so far without attempting to
    /// verify it — used both by a failed guess and by canceling out of
    /// input entirely (`app.rs`'s Esc handling). `String::clear()` only
    /// resets length, it does not overwrite the freed heap bytes;
    /// `Zeroize::zeroize()` actually does, and does so proactively
    /// rather than waiting for this `Wizard` to eventually drop — the
    /// workspace's release profile sets `panic = "abort"` (root
    /// `Cargo.toml`), which skips unwinding entirely, so a `Drop` impl
    /// (what a bare `Zeroizing<String>` would otherwise rely on) is not
    /// guaranteed to run if the process panics while this is still
    /// live. Clearing it the moment it's no longer needed closes that
    /// window instead of hoping a clean shutdown always happens.
    fn clear_input(&mut self) {
        self.input.zeroize();
    }

    pub fn cancel_input(&mut self) {
        self.clear_input();
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
            self.clear_input();
            return;
        }

        let path = self.token_path.clone();
        let result = setup_token::burn(&path, || {
            self.pending_hash = None;
            Ok(())
        });
        self.clear_input();
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
    fn submit_with_no_token_ever_generated_fails_cleanly_instead_of_panicking() {
        // Genuinely no `pending_hash` anywhere: no file on disk at all,
        // so `Wizard::new` starts at `NoTokenFound` and never recovers a
        // hash from anything. Distinct from the pre-existing-file case
        // below, which does now recover one — see that test.
        let path = scratch_path("submit-before-generate");
        let _ = std::fs::remove_file(&path);
        let mut wizard = Wizard::new(path.clone());
        assert!(matches!(wizard.step, Step::NoTokenFound));

        wizard.push_char('x');
        wizard.submit();

        assert!(matches!(wizard.step, Step::Failed(_)));
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn verifying_a_preexisting_token_file_succeeds_without_generating_in_this_process() {
        // Regression test for the adversarial-review finding: a token
        // file written by an *earlier* process (simulating a TUI
        // restart between generate and verify, or — the shape this
        // becomes once §3.3 lands — the watchdog always being the one
        // that wrote it) must still be verifiable. Before the fix,
        // `Wizard::new` always started with `pending_hash: None`
        // regardless of an existing file, so `submit()` could never
        // succeed here no matter what was typed.
        let path = scratch_path("preexisting-verify");
        let _ = std::fs::remove_file(&path);
        setup_token::write_token_file(&path, "the-real-token").unwrap();

        let mut wizard = Wizard::new(path.clone());
        assert!(matches!(wizard.step, Step::AwaitingInput));

        for c in "the-real-token".chars() {
            wizard.push_char(c);
        }
        wizard.submit();

        assert!(
            matches!(wizard.step, Step::Verified),
            "a pre-existing file's real token must verify"
        );
        assert!(
            !path.exists(),
            "a successful verify must still burn the file"
        );
    }

    #[test]
    fn wrong_input_against_a_preexisting_token_file_fails_without_burning() {
        let path = scratch_path("preexisting-wrong");
        let _ = std::fs::remove_file(&path);
        setup_token::write_token_file(&path, "the-real-token").unwrap();

        let mut wizard = Wizard::new(path.clone());
        for c in "not-the-real-token".chars() {
            wizard.push_char(c);
        }
        wizard.submit();

        assert!(matches!(wizard.step, Step::Failed(_)));
        assert!(
            path.exists(),
            "a failed verify must not burn a still-valid file"
        );
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn unreadable_token_file_fails_cleanly_instead_of_being_mistaken_for_absent() {
        use std::os::unix::fs::PermissionsExt;

        let path = scratch_path("unreadable");
        let _ = std::fs::remove_file(&path);
        setup_token::write_token_file(&path, "irrelevant").unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();

        // Root (or a test runner with CAP_DAC_OVERRIDE) can read a
        // 0-permission file anyway — skip rather than false-fail there.
        if fs::read_to_string(&path).is_ok() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
            std::fs::remove_file(&path).ok();
            return;
        }

        let wizard = Wizard::new(path.clone());
        assert!(
            matches!(wizard.step, Step::Failed(_)),
            "a real read error must not be mistaken for 'no token file yet'"
        );

        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn backspace_removes_the_last_character() {
        let path = scratch_path("backspace");
        let mut wizard = Wizard::new(path);
        wizard.push_char('a');
        wizard.push_char('b');
        wizard.backspace();
        assert_eq!(wizard.input.as_str(), "a");
    }

    #[test]
    fn cancel_input_clears_whatever_was_typed() {
        let path = scratch_path("cancel");
        let mut wizard = Wizard::new(path);
        wizard.push_char('a');
        wizard.push_char('b');
        wizard.cancel_input();
        assert_eq!(wizard.input.as_str(), "");
    }
}
