use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use zeroize::Zeroizing;

const READ_WRITE_TIMEOUT: Duration = Duration::from_secs(15);

const READ_DEADLINE_BUDGET: Duration = Duration::from_secs(20);

const MAX_LINE_LEN: usize = 8192;

fn read_line_bounded(
    reader: &mut impl std::io::Read,
    deadline: std::time::Instant,
    max_len: usize,
) -> Result<String, String> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        if std::time::Instant::now() > deadline {
            return Err("timed out waiting for a full line".to_string());
        }
        if buf.len() >= max_len {
            return Err(format!(
                "line exceeded {max_len} bytes without a '\\n' terminator"
            ));
        }
        match reader.read(&mut byte) {
            Ok(0) => {
                return if buf.is_empty() {
                    Ok(String::new())
                } else {
                    Err("connection closed mid-line".to_string())
                };
            }
            Ok(_) => {
                buf.push(byte[0]);
                if byte[0] == b'\n' {
                    return String::from_utf8(buf)
                        .map_err(|e| format!("line was not valid UTF-8: {e}"));
                }
            }

            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => return Err(format!("reading: {e}")),
        }
    }
}

fn env_path(key: &str, default: &str) -> PathBuf {
    std::env::var_os(key)
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(default))
}

pub fn socket_path() -> PathBuf {
    env_path(
        "FOSSH_OPERATOR_AUTH_SOCKET",
        "/var/lib/fossh-watchdog/operator-auth.sock",
    )
}

#[derive(Debug, PartialEq, Eq)]
pub enum AuthError {
    Unreachable(String),
    NotEnrolled,
    GpgNotAvailable(String),
    SigningFailed(String),
    Protocol(String),
    Denied,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(e) => {
                write!(
                    f,
                    "could not reach the watchdog's operator auth socket: {e}"
                )
            }
            Self::NotEnrolled => write!(f, "no operator key is enrolled with the watchdog yet"),
            Self::GpgNotAvailable(e) => write!(f, "could not run gpg to sign the challenge: {e}"),
            Self::SigningFailed(e) => write!(f, "gpg could not sign the challenge: {e}"),
            Self::Protocol(e) => write!(f, "operator auth protocol error: {e}"),
            Self::Denied => write!(f, "the watchdog rejected the signature"),
        }
    }
}

impl std::error::Error for AuthError {}

fn describe_connect_error(path: &Path, e: &std::io::Error) -> String {
    match e.kind() {
        std::io::ErrorKind::NotFound => format!(
            "{} does not exist — the watchdog is not running, or its auth-gate socket isn't up yet",
            path.display()
        ),
        std::io::ErrorKind::ConnectionRefused => format!(
            "{} exists but refused the connection — the watchdog may have exited without cleaning up its socket",
            path.display()
        ),
        std::io::ErrorKind::PermissionDenied => format!(
            "permission denied connecting to {} — this account cannot reach the watchdog's operator-auth socket",
            path.display()
        ),
        _ => format!("connecting to {}: {e}", path.display()),
    }
}

fn looks_like_a_nonce(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

enum FirstLine {
    NotEnrolled,
    Nonce(String),
}

fn parse_first_line(line: &str) -> Result<FirstLine, AuthError> {
    if line == "NOT_ENROLLED\n" {
        return Ok(FirstLine::NotEnrolled);
    }
    match line
        .strip_prefix("NONCE ")
        .and_then(|rest| rest.strip_suffix('\n'))
    {
        Some(hex) if looks_like_a_nonce(hex) => Ok(FirstLine::Nonce(hex.to_string())),
        _ => Err(AuthError::Protocol(format!(
            "expected NOT_ENROLLED or NONCE <64 hex chars>, got: {line:?}"
        ))),
    }
}

fn parse_final_line(line: &str) -> Result<String, AuthError> {
    if line == "DENIED\n" {
        return Err(AuthError::Denied);
    }
    match line
        .strip_prefix("OK ")
        .and_then(|rest| rest.strip_suffix('\n'))
    {
        Some(token) if !token.is_empty() => Ok(token.to_string()),
        _ => Err(AuthError::Protocol(format!(
            "expected OK <token> or DENIED, got: {line:?}"
        ))),
    }
}

fn sign_with_gpg(data: &str, gnupghome_override: Option<&Path>) -> Result<Vec<u8>, AuthError> {
    let mut cmd = Command::new("gpg");
    cmd.args(["--batch", "--armor", "--detach-sign"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if let Some(home) = gnupghome_override {
        cmd.env("GNUPGHOME", home);
    }
    let mut child = cmd
        .spawn()
        .map_err(|e| AuthError::GpgNotAvailable(e.to_string()))?;

    child
        .stdin
        .take()
        .expect("stdin was requested as piped")
        .write_all(data.as_bytes())
        .map_err(|e| AuthError::SigningFailed(format!("writing the nonce to gpg's stdin: {e}")))?;

    let output = child
        .wait_with_output()
        .map_err(|e| AuthError::SigningFailed(format!("waiting for gpg: {e}")))?;

    if !output.status.success() {
        return Err(AuthError::SigningFailed(format!(
            "gpg --armor --detach-sign exited {}: {}",
            output
                .status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string()),
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(output.stdout)
}

pub(crate) fn authenticate_at(
    socket_path: &Path,
    gnupghome_override: Option<&Path>,
) -> Result<String, AuthError> {
    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| AuthError::Unreachable(describe_connect_error(socket_path, &e)))?;
    stream
        .set_read_timeout(Some(READ_WRITE_TIMEOUT))
        .map_err(|e| AuthError::Protocol(format!("setting read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(READ_WRITE_TIMEOUT))
        .map_err(|e| AuthError::Protocol(format!("setting write timeout: {e}")))?;

    let mut reader = stream
        .try_clone()
        .map_err(|e| AuthError::Protocol(format!("cloning the socket for reading: {e}")))?;

    let first_line = read_line_bounded(
        &mut reader,
        std::time::Instant::now() + READ_DEADLINE_BUDGET,
        MAX_LINE_LEN,
    )
    .map_err(|e| AuthError::Protocol(format!("reading the first line: {e}")))?;
    if first_line.is_empty() {
        return Err(AuthError::Protocol(
            "connection closed before sending anything".to_string(),
        ));
    }

    let nonce = match parse_first_line(&first_line)? {
        FirstLine::NotEnrolled => return Err(AuthError::NotEnrolled),
        FirstLine::Nonce(hex) => hex,
    };

    let signature = sign_with_gpg(&nonce, gnupghome_override)?;

    stream
        .write_all(&signature)
        .map_err(|e| AuthError::Protocol(format!("sending the signature: {e}")))?;

    let final_line = read_line_bounded(
        &mut reader,
        std::time::Instant::now() + READ_DEADLINE_BUDGET,
        MAX_LINE_LEN,
    )
    .map_err(|e| AuthError::Protocol(format!("reading the final reply: {e}")))?;
    if final_line.is_empty() {
        return Err(AuthError::Protocol(
            "connection closed before a final reply".to_string(),
        ));
    }
    parse_final_line(&final_line)
}

pub fn authenticate() -> Result<String, AuthError> {
    authenticate_at(&socket_path(), None)
}

#[derive(Debug, PartialEq, Eq)]
pub enum SetupError {
    Unreachable(String),

    AlreadyEnrolled,

    TokenDenied,

    MalformedKey(String),

    EnrollFailed(String),
    GpgNotAvailable(String),
    GpgFailed(String),
    Protocol(String),
}

impl std::fmt::Display for SetupError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unreachable(e) => {
                write!(
                    f,
                    "could not reach the watchdog's operator auth socket: {e}"
                )
            }
            Self::AlreadyEnrolled => write!(
                f,
                "an operator key is already enrolled with the watchdog — setup is already complete"
            ),
            Self::TokenDenied => write!(
                f,
                "the watchdog rejected the setup token — wrong token, or nothing is currently \
                 awaiting setup"
            ),
            Self::MalformedKey(e) => write!(f, "that doesn't look like a valid key: {e}"),
            Self::EnrollFailed(code) => {
                write!(f, "the watchdog refused to enroll this key: {code}")
            }
            Self::GpgNotAvailable(e) => write!(f, "could not run gpg: {e}"),
            Self::GpgFailed(e) => write!(f, "gpg failed: {e}"),
            Self::Protocol(e) => write!(f, "operator setup protocol error: {e}"),
        }
    }
}

impl std::error::Error for SetupError {}

const PUBLIC_KEY_BEGIN_MARKER: &str = "-----BEGIN PGP PUBLIC KEY BLOCK-----";

const PUBLIC_KEY_END_MARKER: &str = "-----END PGP PUBLIC KEY BLOCK-----";

fn looks_like_armored_public_key(s: &str) -> bool {
    s.contains(PUBLIC_KEY_BEGIN_MARKER) && s.contains(PUBLIC_KEY_END_MARKER)
}

fn parse_setup_reply(line: &str) -> Result<(), SetupError> {
    match line {
        "SETUP_OK\n" => Ok(()),
        "SETUP_DENIED\n" => Err(SetupError::TokenDenied),
        other => Err(SetupError::Protocol(format!(
            "expected SETUP_OK or SETUP_DENIED, got: {other:?}"
        ))),
    }
}

fn parse_enroll_reply(line: &str) -> Result<String, SetupError> {
    if let Some(fpr) = line
        .strip_prefix("ENROLLED ")
        .and_then(|r| r.strip_suffix('\n'))
    {
        if fpr.is_empty() {
            return Err(SetupError::Protocol(format!(
                "ENROLLED with no fingerprint: {line:?}"
            )));
        }
        return Ok(fpr.to_string());
    }
    if let Some(code) = line
        .strip_prefix("ENROLL_FAILED ")
        .and_then(|r| r.strip_suffix('\n'))
    {
        return Err(SetupError::EnrollFailed(code.to_string()));
    }
    Err(SetupError::Protocol(format!(
        "expected ENROLLED <fingerprint> or ENROLL_FAILED <code>, got: {line:?}"
    )))
}

pub(crate) fn setup_at(
    socket_path: &Path,
    token: &str,
    public_key_armored: &str,
) -> Result<String, SetupError> {
    if token.is_empty() || token.contains('\n') {
        return Err(SetupError::Protocol(
            "the setup token must be a single non-empty line".to_string(),
        ));
    }
    if !looks_like_armored_public_key(public_key_armored) {
        return Err(SetupError::MalformedKey(
            "missing a -----BEGIN/END PGP PUBLIC KEY BLOCK----- pair".to_string(),
        ));
    }

    let mut stream = UnixStream::connect(socket_path)
        .map_err(|e| SetupError::Unreachable(describe_connect_error(socket_path, &e)))?;
    stream
        .set_read_timeout(Some(READ_WRITE_TIMEOUT))
        .map_err(|e| SetupError::Protocol(format!("setting read timeout: {e}")))?;
    stream
        .set_write_timeout(Some(READ_WRITE_TIMEOUT))
        .map_err(|e| SetupError::Protocol(format!("setting write timeout: {e}")))?;

    let mut reader = stream
        .try_clone()
        .map_err(|e| SetupError::Protocol(format!("cloning the socket for reading: {e}")))?;

    let first_line = read_line_bounded(
        &mut reader,
        std::time::Instant::now() + READ_DEADLINE_BUDGET,
        MAX_LINE_LEN,
    )
    .map_err(|e| SetupError::Protocol(format!("reading the first line: {e}")))?;
    if first_line.is_empty() {
        return Err(SetupError::Protocol(
            "connection closed before sending anything".to_string(),
        ));
    }
    match parse_first_line(&first_line) {
        Ok(FirstLine::NotEnrolled) => {}
        Ok(FirstLine::Nonce(_)) => return Err(SetupError::AlreadyEnrolled),
        Err(_) => {
            return Err(SetupError::Protocol(format!(
                "expected NOT_ENROLLED, got: {first_line:?}"
            )));
        }
    }

    stream
        .write_all(format!("SETUP {token}\n").as_bytes())
        .map_err(|e| SetupError::Protocol(format!("sending the setup token: {e}")))?;

    let setup_reply = read_line_bounded(
        &mut reader,
        std::time::Instant::now() + READ_DEADLINE_BUDGET,
        MAX_LINE_LEN,
    )
    .map_err(|e| SetupError::Protocol(format!("reading the SETUP reply: {e}")))?;
    if setup_reply.is_empty() {
        return Err(SetupError::Protocol(
            "connection closed before SETUP_OK/SETUP_DENIED".to_string(),
        ));
    }
    parse_setup_reply(&setup_reply)?;

    stream
        .write_all(public_key_armored.as_bytes())
        .map_err(|e| SetupError::Protocol(format!("sending the public key: {e}")))?;

    let final_line = read_line_bounded(
        &mut reader,
        std::time::Instant::now() + READ_DEADLINE_BUDGET,
        MAX_LINE_LEN,
    )
    .map_err(|e| SetupError::Protocol(format!("reading the enrollment reply: {e}")))?;
    if final_line.is_empty() {
        return Err(SetupError::Protocol(
            "connection closed before ENROLLED/ENROLL_FAILED".to_string(),
        ));
    }
    parse_enroll_reply(&final_line)
}

pub fn setup(token: &str, public_key_armored: &str) -> Result<String, SetupError> {
    setup_at(&socket_path(), token, public_key_armored)
}

pub struct GeneratedOperatorKey {
    pub fingerprint: String,
    pub public_key_armored: String,
    pub private_key_armored: Zeroizing<String>,
}

fn resolve_gnupghome(gnupghome_override: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = gnupghome_override {
        return Some(p.to_path_buf());
    }
    if let Some(v) = std::env::var_os("GNUPGHOME")
        && !v.is_empty()
    {
        return Some(PathBuf::from(v));
    }
    std::env::var_os("HOME")
        .filter(|h| !h.is_empty())
        .map(|h| PathBuf::from(h).join(".gnupg"))
}

fn ensure_gnupghome_exists(gnupghome_override: Option<&Path>) -> Result<(), SetupError> {
    let Some(dir) = resolve_gnupghome(gnupghome_override) else {
        return Ok(());
    };
    if dir.exists() {
        return Ok(());
    }
    std::fs::create_dir_all(&dir)
        .map_err(|e| SetupError::GpgFailed(format!("creating {}: {e}", dir.display())))?;
    std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).map_err(|e| {
        SetupError::GpgFailed(format!("setting permissions on {}: {e}", dir.display()))
    })?;
    Ok(())
}

fn list_secret_key_fingerprints(
    gnupghome_override: Option<&Path>,
) -> Result<std::collections::HashSet<String>, SetupError> {
    let mut cmd = Command::new("gpg");
    cmd.args(["--batch", "--list-secret-keys", "--with-colons"]);
    if let Some(home) = gnupghome_override {
        cmd.env("GNUPGHOME", home);
    }
    let output = cmd
        .output()
        .map_err(|e| SetupError::GpgNotAvailable(e.to_string()))?;
    if !output.status.success() {
        return Err(SetupError::GpgFailed(format!(
            "gpg --list-secret-keys failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout
        .lines()
        .filter(|line| line.starts_with("fpr:"))
        .filter_map(|line| line.split(':').nth(9))
        .map(String::from)
        .collect())
}

fn gpg_export_armored(
    args: &[&str],
    gnupghome_override: Option<&Path>,
) -> Result<String, SetupError> {
    let mut cmd = Command::new("gpg");
    cmd.arg("--batch").args(args);
    if let Some(home) = gnupghome_override {
        cmd.env("GNUPGHOME", home);
    }
    let output = cmd
        .output()
        .map_err(|e| SetupError::GpgNotAvailable(e.to_string()))?;
    if !output.status.success() {
        return Err(SetupError::GpgFailed(format!(
            "gpg export failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

fn generate_fresh_operator_key_at(
    uid: &str,
    gnupghome_override: Option<&Path>,
) -> Result<GeneratedOperatorKey, SetupError> {
    generate_fresh_operator_key_at_inner(uid, gnupghome_override, false)
}

fn generate_fresh_operator_key_at_inner(
    uid: &str,
    gnupghome_override: Option<&Path>,
    forced_empty_passphrase_for_tests: bool,
) -> Result<GeneratedOperatorKey, SetupError> {
    ensure_gnupghome_exists(gnupghome_override)?;
    let before = list_secret_key_fingerprints(gnupghome_override)?;

    let mut cmd = Command::new("gpg");
    cmd.arg("--batch");
    if forced_empty_passphrase_for_tests {
        cmd.args(["--pinentry-mode", "loopback", "--passphrase", ""]);
    }
    cmd.args(["--quick-generate-key", uid, "ed25519", "sign", "never"]);
    if let Some(home) = gnupghome_override {
        cmd.env("GNUPGHOME", home);
    }
    let status = cmd
        .status()
        .map_err(|e| SetupError::GpgNotAvailable(e.to_string()))?;
    if !status.success() {
        return Err(SetupError::GpgFailed(format!(
            "gpg --quick-generate-key exited {}",
            status
                .code()
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".to_string())
        )));
    }

    let after = list_secret_key_fingerprints(gnupghome_override)?;
    let mut new_fingerprints: Vec<&String> = after.difference(&before).collect();
    let fingerprint = match new_fingerprints.len() {
        1 => new_fingerprints.remove(0).clone(),
        0 => {
            return Err(SetupError::GpgFailed(
                "gpg reported success but no new secret key appeared in the keyring".to_string(),
            ));
        }
        _ => {
            return Err(SetupError::GpgFailed(
                "more than one new secret key appeared at once — refusing to guess which one \
                 this call produced"
                    .to_string(),
            ));
        }
    };

    let public_key_armored =
        gpg_export_armored(&["--armor", "--export", &fingerprint], gnupghome_override)?;
    let private_key_armored = Zeroizing::new(gpg_export_armored(
        &["--armor", "--export-secret-keys", &fingerprint],
        gnupghome_override,
    )?);

    Ok(GeneratedOperatorKey {
        fingerprint,
        public_key_armored,
        private_key_armored,
    })
}

pub fn generate_fresh_operator_key(uid: &str) -> Result<GeneratedOperatorKey, SetupError> {
    generate_fresh_operator_key_at(uid, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::net::UnixListener;

    fn scratch_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "fossh-tui-operator-auth-test-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn not_enrolled_line_parses_cleanly() {
        assert!(matches!(
            parse_first_line("NOT_ENROLLED\n"),
            Ok(FirstLine::NotEnrolled)
        ));
    }

    #[test]
    fn a_well_formed_nonce_line_yields_exactly_the_hex_chars() {
        let hex = "ab".repeat(32);
        let line = format!("NONCE {hex}\n");
        match parse_first_line(&line) {
            Ok(FirstLine::Nonce(got)) => assert_eq!(got, hex),
            other => panic!("expected Nonce, got {other:?}"),
        }
    }

    impl std::fmt::Debug for FirstLine {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            match self {
                Self::NotEnrolled => write!(f, "NotEnrolled"),
                Self::Nonce(h) => write!(f, "Nonce({h})"),
            }
        }
    }

    #[test]
    fn uppercase_hex_is_rejected_the_mli_promises_lowercase_only() {
        let hex = "AB".repeat(32);
        assert!(parse_first_line(&format!("NONCE {hex}\n")).is_err());
    }

    #[test]
    fn a_short_nonce_is_rejected() {
        assert!(parse_first_line("NONCE deadbeef\n").is_err());
    }

    #[test]
    fn read_line_bounded_reads_a_normal_line_fine() {
        let dir = scratch_dir("read-line-bounded-normal");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(b"hello\n").unwrap();
        });
        let mut conn = UnixStream::connect(&socket_path).unwrap();
        let result = read_line_bounded(
            &mut conn,
            std::time::Instant::now() + Duration::from_secs(5),
            MAX_LINE_LEN,
        );
        server.join().unwrap();
        assert_eq!(result, Ok("hello\n".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_line_bounded_times_out_a_slow_drip_that_never_completes_a_line() {

        let dir = scratch_dir("read-line-bounded-drip");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            for _ in 0..50 {
                let _ = conn.write_all(b"x");
                std::thread::sleep(Duration::from_millis(20));
            }

        });
        let mut conn = UnixStream::connect(&socket_path).unwrap();
        let start = std::time::Instant::now();
        let result = read_line_bounded(
            &mut conn,
            std::time::Instant::now() + Duration::from_millis(200),
            MAX_LINE_LEN,
        );
        let elapsed = start.elapsed();
        let _ = server.join();
        assert!(
            result.is_err(),
            "a line that never completes must time out, not hang forever"
        );
        assert!(
            elapsed < Duration::from_millis(800),
            "must give up close to the 200ms deadline, not wait out the full drip (elapsed: {elapsed:?})"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_line_bounded_rejects_a_line_that_exceeds_max_len_without_a_terminator() {
        let dir = scratch_dir("read-line-bounded-maxlen");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            let _ = conn.write_all(&[b'x'; 100]);
            std::thread::sleep(Duration::from_millis(300));
        });
        let mut conn = UnixStream::connect(&socket_path).unwrap();
        let result = read_line_bounded(
            &mut conn,
            std::time::Instant::now() + Duration::from_secs(5),
            10,
        );
        let _ = server.join();
        assert!(
            result.is_err(),
            "a line longer than max_len with no terminator must be rejected, not grow unbounded"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn garbage_first_line_is_a_protocol_error() {
        assert!(parse_first_line("garbage\n").is_err());
    }

    #[test]
    fn ok_line_yields_exactly_the_token() {
        assert_eq!(parse_final_line("OK abc123\n"), Ok("abc123".to_string()));
    }

    #[test]
    fn denied_line_is_the_denied_error() {
        assert_eq!(parse_final_line("DENIED\n"), Err(AuthError::Denied));
    }

    #[test]
    fn garbage_final_line_is_a_protocol_error_not_a_panic() {
        assert!(matches!(
            parse_final_line("nope\n"),
            Err(AuthError::Protocol(_))
        ));
    }

    fn generate_test_key(gnupghome: &Path, uid: &str) -> String {
        std::fs::create_dir_all(gnupghome).unwrap();
        std::fs::set_permissions(
            gnupghome,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let status = Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(gnupghome)
            .args([
                "--pinentry-mode",
                "loopback",
                "--passphrase",
                "",
                "--quick-generate-key",
                uid,
                "ed25519",
                "sign",
                "never",
            ])
            .status()
            .expect("failed to run gpg --quick-generate-key");
        assert!(status.success(), "gpg --quick-generate-key failed");

        let output = Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(gnupghome)
            .args(["--list-secret-keys", "--with-colons"])
            .output()
            .expect("failed to run gpg --list-secret-keys");
        assert!(output.status.success());
        let stdout = String::from_utf8(output.stdout).unwrap();
        stdout
            .lines()
            .find(|line| line.starts_with("fpr:"))
            .expect("no fpr: line")
            .split(':')
            .nth(9)
            .expect("malformed fpr: line")
            .to_string()
    }

    fn export_pubkey_armored(gnupghome: &Path, fingerprint: &str) -> String {
        let output = Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(gnupghome)
            .args(["--armor", "--export", fingerprint])
            .output()
            .expect("failed to run gpg --export");
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }

    fn import_pubkey(gnupghome: &Path, armored: &str) {
        std::fs::create_dir_all(gnupghome).unwrap();
        std::fs::set_permissions(
            gnupghome,
            std::os::unix::fs::PermissionsExt::from_mode(0o700),
        )
        .unwrap();
        let key_path = gnupghome.join("import.asc");
        std::fs::write(&key_path, armored).unwrap();
        let status = Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(gnupghome)
            .args(["--import"])
            .arg(&key_path)
            .status()
            .expect("failed to run gpg --import");
        assert!(status.success());
    }

    fn gpg_verify_detached(verify_gnupghome: &Path, data: &str, sig: &[u8]) -> bool {
        let data_path = verify_gnupghome.join("data");
        let sig_path = verify_gnupghome.join("sig.asc");
        std::fs::write(&data_path, data).unwrap();
        std::fs::write(&sig_path, sig).unwrap();
        Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(verify_gnupghome)
            .args(["--verify"])
            .arg(&sig_path)
            .arg(&data_path)
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
    }

    fn read_signature_block(conn: &mut UnixStream) -> Vec<u8> {
        let marker = b"-----END PGP SIGNATURE-----";
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let n = conn.read(&mut chunk).expect("reading signature block");
            assert_ne!(n, 0, "peer closed before sending a full signature block");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(marker.len()).any(|w| w == marker.as_slice()) {
                return buf;
            }
        }
    }

    #[test]
    fn authenticate_signs_exactly_the_nonce_hex_and_accepts_a_real_ok_reply() {
        let dir = scratch_dir("ok");
        let operator_home = dir.join("operator-gnupghome");
        let fpr = generate_test_key(&operator_home, "operator <op@example.invalid>");
        let verify_home = dir.join("verify-gnupghome");
        import_pubkey(&verify_home, &export_pubkey_armored(&operator_home, &fpr));

        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let nonce = "cd".repeat(32);
        let nonce_for_server = nonce.clone();
        let verify_home_for_server = verify_home.clone();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            conn.write_all(format!("NONCE {nonce_for_server}\n").as_bytes())
                .unwrap();
            let sig = read_signature_block(&mut conn);
            let verified = gpg_verify_detached(&verify_home_for_server, &nonce_for_server, &sig);
            let reply = if verified {
                "OK realtoken123\n"
            } else {
                "DENIED\n"
            };
            conn.write_all(reply.as_bytes()).unwrap();
        });

        let result = authenticate_at(&socket_path, Some(&operator_home));
        server.join().unwrap();

        assert_eq!(
            result,
            Ok("realtoken123".to_string()),
            "a real signature over exactly the nonce hex chars, verified with a real gpg \
             --verify against the exported public key, must be accepted"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authenticate_reports_denied_from_a_real_denied_reply() {
        let dir = scratch_dir("denied");
        let operator_home = dir.join("operator-gnupghome");
        generate_test_key(&operator_home, "operator <op@example.invalid>");

        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let nonce = "ef".repeat(32);

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            conn.write_all(format!("NONCE {nonce}\n").as_bytes())
                .unwrap();
            let _sig = read_signature_block(&mut conn);
            conn.write_all(b"DENIED\n").unwrap();
        });

        let result = authenticate_at(&socket_path, Some(&operator_home));
        server.join().unwrap();

        assert_eq!(result, Err(AuthError::Denied));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authenticate_reports_not_enrolled() {
        let dir = scratch_dir("not-enrolled");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(b"NOT_ENROLLED\n").unwrap();
        });

        let result = authenticate_at(&socket_path, None);
        server.join().unwrap();

        assert_eq!(result, Err(AuthError::NotEnrolled));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn authenticate_reports_unreachable_for_a_missing_socket() {
        let dir = scratch_dir("missing-socket");
        let socket_path = dir.join("does-not-exist.sock");

        let result = authenticate_at(&socket_path, None);

        assert!(matches!(result, Err(AuthError::Unreachable(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn watchdog_binary_path() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../watchdog/_build/default/bin/main.exe")
    }

    fn watchdog_stderr(path: &Path) -> String {
        match std::fs::read_to_string(path) {
            Ok(s) if s.trim().is_empty() => "(the watchdog wrote nothing to stderr)".to_string(),
            Ok(s) => format!("\n--- watchdog stderr ---\n{}", s.trim_end()),
            Err(e) => format!("(could not read the watchdog's stderr: {e})"),
        }
    }

    fn watchdog_quic_vendor_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../watchdog/quic/vendor")
    }

    fn find_free_loopback_port() -> u16 {
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind an ephemeral UDP port");
        socket.local_addr().expect("local_addr").port()
    }

    fn sha256_hex(path: &Path) -> String {
        let output = Command::new("sha256sum")
            .arg(path)
            .output()
            .expect("failed to run sha256sum");
        assert!(output.status.success(), "sha256sum {path:?} failed");
        String::from_utf8(output.stdout).unwrap()[..64].to_string()
    }

    fn sign_manifest(gnupghome: &Path, fingerprint: &str, covered_paths: &[&str]) -> String {
        let body: String = covered_paths
            .iter()
            .map(|p| format!("{}  {p}\n", sha256_hex(Path::new(p))))
            .collect();
        let mut child = Command::new("gpg")
            .arg("--batch")
            .arg("--homedir")
            .arg(gnupghome)
            .args(["--local-user", fingerprint, "--clearsign"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn gpg --clearsign");
        child
            .stdin
            .take()
            .unwrap()
            .write_all(body.as_bytes())
            .unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "gpg --clearsign failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        String::from_utf8(output.stdout).unwrap()
    }

    #[test]
    fn authenticate_interops_with_the_real_compiled_watchdog_binary() {
        let binary = watchdog_binary_path();
        if !binary.exists() {
            eprintln!(
                "SKIPPED: {} not found — build the OCaml watchdog first (cd watchdog && eval $(opam env) && dune build)",
                binary.display()
            );
            return;
        }

        let dir = scratch_dir("real-interop");

        let watchdog_gnupghome = dir.join("watchdog-gnupghome");
        let watchdog_fpr = generate_test_key(&watchdog_gnupghome, "fossh-watchdog-interop-test");

        let supervised_program = "/bin/sleep";
        let manifest = sign_manifest(&watchdog_gnupghome, &watchdog_fpr, &[supervised_program]);
        let manifest_path = dir.join("manifest.clearsigned");
        std::fs::write(&manifest_path, &manifest).unwrap();

        let operator_gnupghome = dir.join("operator-gnupghome");
        let operator_fpr = generate_test_key(&operator_gnupghome, "operator <op@example.invalid>");
        let operator_pubkey = export_pubkey_armored(&operator_gnupghome, &operator_fpr);

        let impostor_gnupghome = dir.join("impostor-gnupghome");
        generate_test_key(&impostor_gnupghome, "impostor <impostor@example.invalid>");

        let key_dir = dir.join("operator-key-dir");
        std::fs::create_dir_all(&key_dir).unwrap();
        std::fs::write(key_dir.join("operator-fingerprint.pin"), &operator_fpr).unwrap();
        import_pubkey(&key_dir.join("operator-gnupghome"), &operator_pubkey);

        let auth_socket = dir.join("operator-auth.sock");

        let watchdog_log = dir.join("watchdog.stderr");
        let port = find_free_loopback_port();

        let mut watchdog_process = Command::new(&binary)
            .arg(supervised_program)
            .arg(&watchdog_gnupghome)
            .arg(&manifest_path)
            .arg("30")
            .env("FOSSH_OPERATOR_AUTH_SOCKET", &auth_socket)
            .env("FOSSH_OPERATOR_KEY_DIR", &key_dir)
            .env("FOSSH_QUIC_LISTEN_ADDR", format!("127.0.0.1:{port}"))
            .env("FOSSH_WATCHDOG_TLS_DIR", dir.join("watchdog-tls"))
            .env("FOSSH_CORE_CERT_PIN", dir.join("core-cert.pin"))
            .env("LD_LIBRARY_PATH", watchdog_quic_vendor_dir())
            .env("FOSSH_WATCHDOG_ALLOW_NO_PRIVDROP", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(&watchdog_log)
                    .expect("could not create the watchdog log file"),
            ))
            .spawn()
            .expect("failed to spawn the real fossh-watchdog binary");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !auth_socket.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            auth_socket.exists(),
            "the real watchdog never bound its operator-auth socket{}",
            watchdog_stderr(&watchdog_log)
        );

        match authenticate_at(&auth_socket, Some(&operator_gnupghome)) {
            Ok(token) => {
                assert_eq!(
                    token.len(),
                    64,
                    "session token should be Nonce.generate's own 64-hex-char shape"
                );
                assert!(
                    token
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
                    "session token should be lowercase hex"
                );
            }
            Err(e) => {
                let _ = watchdog_process.kill();
                panic!(
                    "expected the real watchdog to accept the enrolled operator's real \
                     signature, got: {e}"
                );
            }
        }

        let denied_result = authenticate_at(&auth_socket, Some(&impostor_gnupghome));
        assert_eq!(
            denied_result,
            Err(AuthError::Denied),
            "a real signature from a key that was never enrolled must be denied by the real \
             watchdog, not accepted"
        );

        let _ = watchdog_process.kill();
        let _ = watchdog_process.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_ok_line_parses_cleanly() {
        assert_eq!(parse_setup_reply("SETUP_OK\n"), Ok(()));
    }

    #[test]
    fn setup_denied_line_is_the_token_denied_error() {
        assert_eq!(
            parse_setup_reply("SETUP_DENIED\n"),
            Err(SetupError::TokenDenied)
        );
    }

    #[test]
    fn garbage_setup_reply_is_a_protocol_error_not_a_panic() {
        assert!(matches!(
            parse_setup_reply("nope\n"),
            Err(SetupError::Protocol(_))
        ));
    }

    #[test]
    fn enrolled_line_yields_exactly_the_fingerprint() {
        assert_eq!(
            parse_enroll_reply("ENROLLED ABCD1234\n"),
            Ok("ABCD1234".to_string())
        );
    }

    #[test]
    fn enroll_failed_line_carries_the_reason_code() {
        assert_eq!(
            parse_enroll_reply("ENROLL_FAILED invalid_key\n"),
            Err(SetupError::EnrollFailed("invalid_key".to_string()))
        );
    }

    #[test]
    fn garbage_enroll_reply_is_a_protocol_error() {
        assert!(matches!(
            parse_enroll_reply("what\n"),
            Err(SetupError::Protocol(_))
        ));
    }

    #[test]
    fn a_key_block_with_both_markers_looks_like_an_armored_public_key() {
        assert!(looks_like_armored_public_key(
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\n\
             mQGNBGAAAAA=\n\
             -----END PGP PUBLIC KEY BLOCK-----\n"
        ));
    }

    #[test]
    fn plain_text_does_not_look_like_an_armored_public_key() {
        assert!(!looks_like_armored_public_key("just some text, not a key"));
    }

    #[test]
    fn a_private_key_block_does_not_look_like_a_public_one() {

        assert!(!looks_like_armored_public_key(
            "-----BEGIN PGP PRIVATE KEY BLOCK-----\nsomething\n-----END PGP PRIVATE KEY BLOCK-----\n"
        ));
    }

    #[test]
    fn setup_at_rejects_a_malformed_key_before_ever_connecting() {
        let dir = scratch_dir("setup-malformed-key");
        let socket_path = dir.join("does-not-exist.sock");

        let result = setup_at(&socket_path, "sometoken", "not a real armored key block");

        assert!(matches!(result, Err(SetupError::MalformedKey(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_at_rejects_a_multiline_token_before_ever_connecting() {
        let dir = scratch_dir("setup-multiline-token");
        let socket_path = dir.join("does-not-exist.sock");
        let valid_key =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n";

        let result = setup_at(&socket_path, "line-one\nline-two", valid_key);

        assert!(matches!(result, Err(SetupError::Protocol(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_at_rejects_an_empty_token_before_ever_connecting() {
        let dir = scratch_dir("setup-empty-token");
        let socket_path = dir.join("does-not-exist.sock");
        let valid_key =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n";

        let result = setup_at(&socket_path, "", valid_key);

        assert!(matches!(result, Err(SetupError::Protocol(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_at_reports_unreachable_for_a_missing_socket() {
        let dir = scratch_dir("setup-missing-socket");
        let socket_path = dir.join("does-not-exist.sock");
        let valid_key =
            "-----BEGIN PGP PUBLIC KEY BLOCK-----\nx\n-----END PGP PUBLIC KEY BLOCK-----\n";

        let result = setup_at(&socket_path, "sometoken", valid_key);

        assert!(matches!(result, Err(SetupError::Unreachable(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn read_setup_line(conn: &mut UnixStream) -> String {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = conn.read(&mut byte).expect("reading the SETUP line");
            assert_ne!(n, 0, "peer closed before sending a full SETUP line");
            buf.push(byte[0]);
            if byte[0] == b'\n' {
                return String::from_utf8(buf).expect("SETUP line was not valid UTF-8");
            }
        }
    }

    fn read_key_block(conn: &mut UnixStream) -> Vec<u8> {
        let marker = PUBLIC_KEY_END_MARKER.as_bytes();
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            let n = conn.read(&mut chunk).expect("reading the key block");
            assert_ne!(n, 0, "peer closed before sending a full key block");
            buf.extend_from_slice(&chunk[..n]);
            if buf.windows(marker.len()).any(|w| w == marker) {
                return buf;
            }
        }
    }

    const A_VALID_LOOKING_KEY: &str =
        "-----BEGIN PGP PUBLIC KEY BLOCK-----\nmQGNBGAAAAA=\n-----END PGP PUBLIC KEY BLOCK-----\n";

    #[test]
    fn setup_at_happy_path_against_a_mock_listener() {
        let dir = scratch_dir("setup-mock-happy");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            conn.write_all(b"NOT_ENROLLED\n").unwrap();
            let line = read_setup_line(&mut conn);
            assert_eq!(line, "SETUP the-real-token\n");
            conn.write_all(b"SETUP_OK\n").unwrap();
            let key = read_key_block(&mut conn);
            assert_eq!(String::from_utf8(key).unwrap(), A_VALID_LOOKING_KEY);
            conn.write_all(b"ENROLLED DEADBEEFCAFE\n").unwrap();
        });

        let result = setup_at(&socket_path, "the-real-token", A_VALID_LOOKING_KEY);
        server.join().unwrap();

        assert_eq!(result, Ok("DEADBEEFCAFE".to_string()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_at_reports_token_denied_from_a_real_setup_denied_reply() {
        let dir = scratch_dir("setup-mock-denied");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            conn.write_all(b"NOT_ENROLLED\n").unwrap();
            let _line = read_setup_line(&mut conn);
            conn.write_all(b"SETUP_DENIED\n").unwrap();
        });

        let result = setup_at(&socket_path, "wrong-token", A_VALID_LOOKING_KEY);
        server.join().unwrap();

        assert_eq!(result, Err(SetupError::TokenDenied));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_at_reports_already_enrolled_when_the_server_sends_a_nonce_instead() {
        let dir = scratch_dir("setup-mock-already-enrolled");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();
        let nonce = "ab".repeat(32);

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.write_all(format!("NONCE {nonce}\n").as_bytes())
                .unwrap();

        });

        let result = setup_at(&socket_path, "the-real-token", A_VALID_LOOKING_KEY);
        server.join().unwrap();

        assert_eq!(result, Err(SetupError::AlreadyEnrolled));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_at_reports_enroll_failed_with_the_real_reason_code() {
        let dir = scratch_dir("setup-mock-enroll-failed");
        let socket_path = dir.join("mock.sock");
        let listener = UnixListener::bind(&socket_path).unwrap();

        let server = std::thread::spawn(move || {
            let (mut conn, _) = listener.accept().unwrap();
            conn.set_read_timeout(Some(Duration::from_secs(10)))
                .unwrap();
            conn.write_all(b"NOT_ENROLLED\n").unwrap();
            let _line = read_setup_line(&mut conn);
            conn.write_all(b"SETUP_OK\n").unwrap();
            let _key = read_key_block(&mut conn);
            conn.write_all(b"ENROLL_FAILED invalid_key\n").unwrap();
        });

        let result = setup_at(&socket_path, "the-real-token", A_VALID_LOOKING_KEY);
        server.join().unwrap();

        assert_eq!(
            result,
            Err(SetupError::EnrollFailed("invalid_key".to_string())),
            "the .mli promises the token is NOT burned on this path — a retry with the same \
             token must still be possible, which is only meaningful if the caller actually \
             learns this was an ENROLL_FAILED, not some other error"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_fresh_operator_key_produces_a_real_usable_keypair() {
        let dir = scratch_dir("generate-fresh-key");
        let gnupghome = dir.join("gnupghome");

        let generated = generate_fresh_operator_key_at_inner(
            "wizard-generated <wizard@example.invalid>",
            Some(&gnupghome),
            true,
        )
        .expect("key generation should succeed with a real gpg");

        assert_eq!(
            generated.fingerprint.len(),
            40,
            "OpenPGP v4 fingerprints are 40 hex chars regardless of the key algorithm"
        );
        assert!(
            generated
                .public_key_armored
                .contains(PUBLIC_KEY_BEGIN_MARKER)
        );
        assert!(
            generated
                .private_key_armored
                .contains("-----BEGIN PGP PRIVATE KEY BLOCK-----"),
            "the private half must actually be exported, not left empty"
        );

        let data = "cd".repeat(32);
        let sig = sign_with_gpg(&data, Some(&gnupghome)).expect("signing with the fresh key");
        let verify_home = dir.join("verify-gnupghome");
        import_pubkey(&verify_home, &generated.public_key_armored);
        assert!(
            gpg_verify_detached(&verify_home, &data, &sig),
            "a signature from the freshly generated key must verify against its own exported \
             public key"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_fresh_operator_key_finds_the_new_key_not_an_earlier_one_already_in_the_keyring() {

        let dir = scratch_dir("generate-fresh-key-diff");
        let gnupghome = dir.join("gnupghome");
        let earlier_fpr = generate_test_key(&gnupghome, "abandoned-attempt <old@example.invalid>");

        let generated = generate_fresh_operator_key_at_inner(
            "second-attempt <new@example.invalid>",
            Some(&gnupghome),
            true,
        )
        .expect("key generation should succeed with a real gpg");

        assert_ne!(
            generated.fingerprint, earlier_fpr,
            "must report the key this call actually just made, not a pre-existing one"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn generate_fresh_operator_key_reports_gpg_not_available_cleanly() {

        let dir = scratch_dir("generate-fresh-key-no-gpg");
        let empty_path_dir = dir.join("empty-path");
        std::fs::create_dir_all(&empty_path_dir).unwrap();

        let mut cmd = Command::new("gpg");
        cmd.args(["--batch", "--list-secret-keys", "--with-colons"]);
        cmd.env("PATH", &empty_path_dir);
        cmd.env("GNUPGHOME", dir.join("gnupghome"));
        let result = cmd.status();

        assert!(
            result.is_err(),
            "sanity check: gpg must actually be unreachable with an empty PATH for this test \
             to mean anything"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn setup_interops_with_the_real_compiled_watchdog_binary() {
        let binary = watchdog_binary_path();
        if !binary.exists() {
            eprintln!(
                "SKIPPED: {} not found — build the OCaml watchdog first (cd watchdog && eval $(opam env) && dune build)",
                binary.display()
            );
            return;
        }

        let dir = scratch_dir("setup-real-interop");

        let watchdog_gnupghome = dir.join("watchdog-gnupghome");
        let watchdog_fpr =
            generate_test_key(&watchdog_gnupghome, "fossh-watchdog-setup-interop-test");
        let supervised_program = "/bin/sleep";
        let manifest = sign_manifest(&watchdog_gnupghome, &watchdog_fpr, &[supervised_program]);
        let manifest_path = dir.join("manifest.clearsigned");
        std::fs::write(&manifest_path, &manifest).unwrap();

        let key_dir = dir.join("operator-key-dir-fresh");
        let token_path = dir.join("setup-token");
        std::fs::write(&token_path, "the-real-setup-token-for-this-test").unwrap();

        let auth_socket = dir.join("operator-auth.sock");

        let watchdog_log = dir.join("watchdog.stderr");
        let port = find_free_loopback_port();

        let mut watchdog_process = Command::new(&binary)
            .arg(supervised_program)
            .arg(&watchdog_gnupghome)
            .arg(&manifest_path)
            .arg("30")
            .env("FOSSH_OPERATOR_AUTH_SOCKET", &auth_socket)
            .env("FOSSH_OPERATOR_KEY_DIR", &key_dir)
            .env("FOSSH_SETUP_TOKEN_PATH", &token_path)
            .env("FOSSH_QUIC_LISTEN_ADDR", format!("127.0.0.1:{port}"))
            .env("FOSSH_WATCHDOG_TLS_DIR", dir.join("watchdog-tls"))
            .env("FOSSH_CORE_CERT_PIN", dir.join("core-cert.pin"))
            .env("LD_LIBRARY_PATH", watchdog_quic_vendor_dir())
            .env("FOSSH_WATCHDOG_ALLOW_NO_PRIVDROP", "1")
            .stdout(Stdio::null())
            .stderr(Stdio::from(
                std::fs::File::create(&watchdog_log)
                    .expect("could not create the watchdog log file"),
            ))
            .spawn()
            .expect("failed to spawn the real fossh-watchdog binary");

        let deadline = std::time::Instant::now() + Duration::from_secs(10);
        while !auth_socket.exists() && std::time::Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(20));
        }
        assert!(
            auth_socket.exists(),
            "the real watchdog never bound its operator-auth socket{}",
            watchdog_stderr(&watchdog_log)
        );

        let operator_gnupghome = dir.join("operator-gnupghome");
        let operator_fpr = generate_test_key(&operator_gnupghome, "operator <op@example.invalid>");
        let operator_pubkey = export_pubkey_armored(&operator_gnupghome, &operator_fpr);

        let wrong_token_result =
            setup_at(&auth_socket, "definitely-not-the-token", &operator_pubkey);
        assert_eq!(
            wrong_token_result,
            Err(SetupError::TokenDenied),
            "a wrong token must be denied by the real watchdog"
        );
        assert!(
            token_path.exists(),
            "a denied SETUP attempt must not burn the still-valid token file"
        );

        let enrolled_fpr = match setup_at(
            &auth_socket,
            "the-real-setup-token-for-this-test",
            &operator_pubkey,
        ) {
            Ok(fpr) => fpr,
            Err(e) => {
                let _ = watchdog_process.kill();
                panic!(
                    "expected the real watchdog to enroll a valid key with the real token, got: {e}"
                );
            }
        };
        assert_eq!(
            enrolled_fpr, operator_fpr,
            "the fingerprint the real watchdog reports must be the operator key that was just \
             sent, not something else"
        );
        assert!(
            !token_path.exists(),
            "a successful enrollment must burn (delete) the setup token file"
        );

        let replay_result = setup_at(
            &auth_socket,
            "the-real-setup-token-for-this-test",
            &operator_pubkey,
        );
        assert_eq!(
            replay_result,
            Err(SetupError::AlreadyEnrolled),
            "once enrolled, the SETUP path must be permanently unreachable, not just denied \
             this one token -- a stronger guarantee than 'the token is burned' alone"
        );

        match authenticate_at(&auth_socket, Some(&operator_gnupghome)) {
            Ok(token) => assert_eq!(token.len(), 64),
            Err(e) => {
                let _ = watchdog_process.kill();
                panic!("expected the just-enrolled key to authenticate for real, got: {e}");
            }
        }

        let _ = watchdog_process.kill();
        let _ = watchdog_process.wait();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
