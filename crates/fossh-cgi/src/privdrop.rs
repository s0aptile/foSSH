//! §3.2: "Drop privileges immediately if invoked as root." Runs as the
//! very first thing in `main()` — before reading any CGI env var, before
//! touching the data/salt directories — so nothing else in this process
//! ever executes with root privileges even transiently.
//!
//! Uses `nix`'s safe wrappers over the underlying POSIX calls rather
//! than raw `libc` FFI, keeping this crate's `#![forbid(unsafe_code)]`
//! intact (S1: `fossh-ffi` is the only crate permitted `unsafe`) — the
//! same pattern already relied on for `rusqlite`'s bundled C SQLite:
//! depending on a crate that contains `unsafe` internally is fine,
//! writing `unsafe` in *this* crate's own source is not.

use nix::unistd::{Gid, Uid, User, geteuid, initgroups, setgid, setuid};

const TARGET_USER: &str = "fossh-svc";

#[derive(Debug, PartialEq, Eq)]
pub enum PrivDropError {
    /// Not actually root — nothing to do. Not an error condition by
    /// itself; kept as a variant so callers/tests can distinguish "ran
    /// the no-op path" from "ran the real path", see `outcome()`.
    NotRoot,
    LookupFailed(String),
    UserNotFound,
    InitGroupsFailed(String),
    SetGidFailed(String),
    SetUidFailed(String),
    /// The single most important check in this module: after dropping,
    /// attempting to reclaim root must fail. If it doesn't, the drop
    /// didn't actually take effect (e.g. only one of the real/effective/
    /// saved IDs changed) and continuing to run would be worse than
    /// refusing outright.
    DropDidNotStick,
}

impl std::fmt::Display for PrivDropError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotRoot => write!(f, "not root"),
            Self::LookupFailed(e) => write!(f, "looking up '{TARGET_USER}' user: {e}"),
            Self::UserNotFound => write!(
                f,
                "user '{TARGET_USER}' does not exist — create it per §2.3 \
                 (the RPM's %post scriptlet does this automatically)"
            ),
            Self::InitGroupsFailed(e) => write!(f, "initgroups({TARGET_USER}): {e}"),
            Self::SetGidFailed(e) => write!(f, "setgid: {e}"),
            Self::SetUidFailed(e) => write!(f, "setuid: {e}"),
            Self::DropDidNotStick => write!(
                f,
                "privilege drop did not take effect — reclaiming root succeeded after dropping"
            ),
        }
    }
}

/// If running as root, drops to `fossh-svc` (§2.3) — real, effective,
/// and saved UID/GID all at once (`setuid`/`setgid` set all three on
/// Linux, unlike `seteuid`/`setegid`, which is exactly why those are
/// used here instead) — and verifies the drop actually stuck. If not
/// running as root, this is a no-op: `Err(PrivDropError::NotRoot)` is
/// the "nothing to do" signal, not a failure; see `main()`'s call site
/// for how it's treated.
pub fn drop_to_service_user() -> Result<(), PrivDropError> {
    if !geteuid().is_root() {
        return Err(PrivDropError::NotRoot);
    }

    let user = User::from_name(TARGET_USER)
        .map_err(|e| PrivDropError::LookupFailed(e.to_string()))?
        .ok_or(PrivDropError::UserNotFound)?;

    // Group first: initgroups (supplementary groups) and setgid both
    // still need CAP_SETGID, which we only still have pre-setuid.
    initgroups(
        &std::ffi::CString::new(TARGET_USER).expect("TARGET_USER has no interior NUL"),
        user.gid,
    )
    .map_err(|e| PrivDropError::InitGroupsFailed(e.to_string()))?;
    setgid(user.gid).map_err(|e| PrivDropError::SetGidFailed(e.to_string()))?;
    setuid(user.uid).map_err(|e| PrivDropError::SetUidFailed(e.to_string()))?;

    if setuid(Uid::from_raw(0)).is_ok() || setgid(Gid::from_raw(0)).is_ok() {
        return Err(PrivDropError::DropDidNotStick);
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_op_when_not_root() {
        // This test suite never runs as root (nor should it try to) —
        // exercising the actual-drop path needs a real root process,
        // which is exactly the path this environment can't safely set
        // up for a test run. See DURUM.md's retrospective for §3.2.
        assert_eq!(drop_to_service_user(), Err(PrivDropError::NotRoot));
    }

    #[test]
    fn error_messages_do_not_leak_a_bare_errno_with_no_context() {
        let msg = PrivDropError::UserNotFound.to_string();
        assert!(msg.contains(TARGET_USER));
        let msg = PrivDropError::DropDidNotStick.to_string();
        assert!(msg.contains("did not take effect"));
    }
}
