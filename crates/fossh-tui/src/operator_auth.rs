//! §2.1 auth-gate screen state. Thin wrapper around
//! `operator_auth_client::authenticate` — see that module for the wire
//! protocol and gpg subprocess details.

use zeroize::Zeroizing;

use crate::operator_auth_client::{self, AuthError};

pub enum Step {
    NotAttempted,
    Authenticated { token: Zeroizing<String> },
    NotEnrolled,
    Denied,
    Failed(String),
}

pub struct OperatorAuth {
    pub step: Step,
}

impl Default for OperatorAuth {
    fn default() -> Self {
        Self::new()
    }
}

impl OperatorAuth {
    pub fn new() -> Self {
        Self {
            step: Step::NotAttempted,
        }
    }

    /// Blocking, on an explicit key press only — same shape as
    /// `App::refresh_watchdog_status` (see `watchdog_status.rs`'s own
    /// module doc for why an eager call on every launch/redraw is the
    /// wrong default for a network client with no fast-fail path).
    /// This one blocks on `gpg` too, on top of the socket round trip.
    pub fn attempt(&mut self) {
        self.step = match operator_auth_client::authenticate() {
            Ok(token) => Step::Authenticated {
                token: Zeroizing::new(token),
            },
            Err(AuthError::NotEnrolled) => Step::NotEnrolled,
            Err(AuthError::Denied) => Step::Denied,
            Err(e) => Step::Failed(e.to_string()),
        };
    }
}
