use nix::unistd::{Gid, Uid, User, geteuid, initgroups, setgid, setuid};

const TARGET_USER: &str = "fossh-svc";

#[derive(Debug, PartialEq, Eq)]
pub enum PrivDropError {

    NotRoot,
    LookupFailed(String),
    UserNotFound,
    InitGroupsFailed(String),
    SetGidFailed(String),
    SetUidFailed(String),

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

pub fn drop_to_service_user() -> Result<(), PrivDropError> {
    if !geteuid().is_root() {
        return Err(PrivDropError::NotRoot);
    }

    let user = User::from_name(TARGET_USER)
        .map_err(|e| PrivDropError::LookupFailed(e.to_string()))?
        .ok_or(PrivDropError::UserNotFound)?;

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
