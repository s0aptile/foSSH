//! §2.4/§3.4: core's (`fossh-svc`'s) own per-install X.509 identity
//! for the QUIC/mTLS channel to the watchdog. §3.4 is explicit that
//! this channel is verified in *both* directions — the watchdog's own
//! identity has a Rust-side sibling to this module, `watchdog/lib/
//! tls_identity.ml` on the OCaml side, deliberately mirroring this
//! one's design (same EC P-256 curve, same 10-year validity, same
//! "check real openssl-verified validity, not mere file presence"
//! idempotency check, same `common_name` character allowlist) — see
//! ADR-0048 for the full background on why this module exists at all
//! (nothing in this project generated a real X.509 certificate for
//! either side before it; the bootstrap handoff pins a completely
//! different, OpenPGP key, on the watchdog's side).
//!
//! Concurrency safety here does *not* use the OCaml sibling's `Mutex`
//! approach (same-process only, deliberately not attempting to cover
//! a second `fossh-svc` instance racing the first — see that module's
//! own comment for why). This module instead generalizes the exact
//! pattern this crate's own `data_key` module already uses for the
//! identical class of problem (many processes racing to establish one
//! per-install secret): `data_key::write_via_temp_then_link` gets its
//! atomicity from `fs::hard_link`'s "fails if the destination already
//! exists" guarantee, enforced by the kernel, not by any
//! application-level lock — which is why it is safe across *processes*,
//! not just threads. `hard_link` only moves a single file, though, and
//! this module needs two (`cert.pem` and `key.pem`) to land together
//! as a matched pair or not at all — so this module generates both
//! into a fresh temp *directory* and atomically `rename`s the whole
//! directory into place instead of hard-linking each file separately
//! (which would reopen exactly the two-separate-atomic-operations gap
//! an adversarial review found and fixed with a `Mutex` on the OCaml
//! side — this module closes the same gap at the filesystem level
//! instead, and gets cross-process safety as a consequence, not just
//! same-process safety).

use std::fs;
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;

use fossh_ingest::random::read_random_bytes;

const OPENSSL_PATH: &str = "/usr/bin/openssl";

/// 10 years, matching the OCaml sibling module exactly — see its own
/// doc comment for why a short-lived, test-fixture-style validity
/// would silently defeat §2.4's "regeneration requires a full
/// re-bootstrap, not a silent rotation" model on a real install.
const VALIDITY_DAYS: u32 = 3650;

#[derive(Debug)]
pub enum TlsIdentityError {
    InvalidCommonName(String),
    Generate(String),
    Io(std::io::Error),
    Random(String),
}

impl std::fmt::Display for TlsIdentityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidCommonName(cn) => write!(f, "invalid common name {cn:?}"),
            Self::Generate(e) => write!(f, "generating TLS identity: {e}"),
            Self::Io(e) => write!(f, "TLS identity I/O error: {e}"),
            Self::Random(e) => write!(f, "TLS identity: {e}"),
        }
    }
}

impl std::error::Error for TlsIdentityError {}

impl From<std::io::Error> for TlsIdentityError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}

pub struct TlsIdentity {
    pub cert_pem_path: PathBuf,
    pub key_pem_path: PathBuf,
}

/// Same allowlist as the OCaml sibling module, same reason: rejects
/// (rather than tries to escape) any `common_name` outside a small
/// safe character set, closing a real, reproduced `-subj` Subject-DN
/// injection footgun (`"innocuous/O=Evil Corp/OU=Fake Unit"` — one
/// string argument, three injected RDN fields) found on that side and
/// ported here proactively rather than needing to be rediscovered.
fn validate_common_name(common_name: &str) -> Result<(), TlsIdentityError> {
    let ok = !common_name.is_empty()
        && common_name.len() <= 64
        && common_name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.');
    if ok {
        Ok(())
    } else {
        Err(TlsIdentityError::InvalidCommonName(common_name.to_string()))
    }
}

/// Real validity, not merely "the file exists" — asks openssl's own
/// parser, the same authority that will actually load this file
/// later, and (via `-checkend 0`) whether it has expired, which a
/// bare structural parse does not check at all. See the OCaml sibling
/// module's identical function for the empirical confirmation this
/// distinction is load-bearing (a bare `-noout` parse exits 0 on a
/// certificate years past its own expiry).
fn cert_is_valid(path: &Path) -> bool {
    path.is_file()
        && Command::new(OPENSSL_PATH)
            .args(["x509", "-in"])
            .arg(path)
            .args(["-noout", "-checkend", "0"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

fn key_is_valid(path: &Path) -> bool {
    path.is_file()
        && Command::new(OPENSSL_PATH)
            .args(["pkey", "-in"])
            .arg(path)
            .arg("-noout")
            .status()
            .map(|s| s.success())
            .unwrap_or(false)
}

fn random_hex_suffix(n: usize) -> Result<String, TlsIdentityError> {
    let bytes = read_random_bytes(n).map_err(|e| TlsIdentityError::Random(e.to_string()))?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}

/// Generates a fresh EC P-256 keypair + self-signed certificate into
/// `tmp_dir/cert.pem` and `tmp_dir/key.pem` — `tmp_dir` must already
/// exist and be empty. Does not touch anything outside `tmp_dir`;
/// making the result visible under its final name is the caller's
/// job (`ensure_identity`'s atomic rename), matching this crate's own
/// `data_key::write_via_temp_then_link` — generate somewhere private
/// first, publish atomically second, never the reverse.
fn generate_into(tmp_dir: &Path, common_name: &str) -> Result<(), TlsIdentityError> {
    let cert_path = tmp_dir.join("cert.pem");
    let key_path = tmp_dir.join("key.pem");

    let status = Command::new(OPENSSL_PATH)
        .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1"])
        .args(["-days", &VALIDITY_DAYS.to_string(), "-nodes"])
        .arg("-keyout")
        .arg(&key_path)
        .arg("-out")
        .arg(&cert_path)
        .args(["-subj", &format!("/CN={common_name}")])
        .status()
        .map_err(|e| TlsIdentityError::Generate(e.to_string()))?;

    if !status.success() {
        return Err(TlsIdentityError::Generate(format!(
            "openssl req exited {status}"
        )));
    }

    // Explicit, not left to openssl's own default — this project's
    // OCaml sibling module separately confirmed empirically that
    // openssl already creates -keyout output at mode 600 by default
    // (checked directly with `stat`, even under umask 000), so this
    // is deliberate defense-in-depth against a different/older
    // openssl build behaving less carefully, not compensation for a
    // confirmed gap.
    fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600))?;

    for path in [&cert_path, &key_path] {
        let f = fs::File::open(path)?;
        f.sync_all()?;
    }
    Ok(())
}

/// Idempotent and safe under concurrent first-callers, in *both*
/// senses that matter for a real deployment: many threads in one
/// process, and — unlike the OCaml sibling module's `Mutex`-only
/// guard — many separate `fossh-svc` processes racing to establish
/// this identity for the first time (e.g. started concurrently right
/// after install, before any identity exists). Reuses the existing
/// certificate and key at `dir/current/{cert,key}.pem` if both are
/// already present *and* independently verified valid (see
/// `cert_is_valid`/`key_is_valid` — stronger than mere presence).
///
/// Otherwise generates a fresh pair into its own uniquely-named
/// generation directory (`dir/gen-<pid>-<random>/`, never reused, never
/// mutated again once written) and publishes it by atomically renaming
/// a symlink — not the directory itself — onto `dir/current`. This
/// specific design is not the first one tried: an earlier version
/// renamed the generation *directory* directly onto `dir/current`,
/// relying on the same "fails if the destination already exists" idea
/// `data_key::write_via_temp_then_link` already uses via `hard_link`.
/// That works for `hard_link` because a file's identity is
/// unambiguous, but `rename` of a *directory* onto an existing
/// *non-empty* directory always fails with `ENOTEMPTY` — including
/// when the existing content is stale, corrupt, or expired garbage
/// that plainly needs replacing, not a legitimate concurrent winner's
/// fresh publish. A fix that re-checked validity and pre-emptively
/// removed genuinely-invalid existing content closed the simple
/// two-caller case, but a real, reproduced test failure under heavier
/// concurrent load (12 threads racing on one fresh directory, roughly
/// 1 run in 10) showed a subtler problem: with more than two racers,
/// one caller's own remove-then-rename sequence is not atomic as a
/// pair, and a *third* caller's fallback validity re-check could
/// observe another caller's directory transiently torn down
/// mid-removal and wrongly conclude no valid identity existed
/// anywhere, surfacing a spurious `ENOTEMPTY` all the way out to the
/// caller. Swapping a symlink instead sidesteps the whole write-side
/// problem category: renaming a symlink (or any non-directory) onto an
/// existing path *atomically replaces* it unconditionally, with no
/// "must be empty" restriction and no multi-step tear-down for
/// anything else to race against — whichever rename physically
/// happens last simply wins, for any number of concurrent racers, not
/// just two, and every racer was generating genuinely valid content in
/// the first place, so *whichever* one wins is correct.
///
/// That fixed every problem with *writing* `current`, but adversarial
/// review found a real, distinct problem on the *reading* side of the
/// exact same mutable pointer: an earlier version of this function
/// returned `dir/current/cert.pem` and `dir/current/key.pem` — two
/// *separate* paths both mediated by the one symlink. `rename`'s
/// atomicity covers only the single act of repointing that symlink; it
/// guarantees nothing about two *separate, later* resolutions of paths
/// that happen to traverse through it. If a different concurrent
/// caller's own successful publish lands in the gap between a reader
/// resolving `cert.pem` and separately resolving `key.pem` — completely
/// ordinary during the exact "many callers racing to establish this
/// identity for the first time" scenario this function exists to
/// handle — the reader ends up with a certificate from one generation
/// and a key from a *different* one. Each file is individually
/// well-formed, so `cert_is_valid`/`key_is_valid` cannot catch it —
/// this is the identical mismatched-keypair failure class the
/// directory-vs-symlink redesign above was built to prevent, just
/// reopened through a different door. Reproduced directly, both as an
/// external caller reading the returned paths with only a
/// microseconds-wide gap between the two reads, and even through this
/// function's own single, immediate return value under an active
/// establishment race. Fixed by never handing back a path mediated by
/// the mutable `current` symlink at all: `resolve_current` reads
/// `current`'s target *once* and returns paths rooted at that specific,
/// resolved `gen-*` directory — which, once created, is never mutated
/// or removed by anyone except the caller that made it, and only when
/// that caller's own publish attempt did *not* win (see `gen_dir`'s own
/// cleanup below) — so a path obtained this way stays valid and
/// internally consistent for as long as the caller holds it,
/// regardless of how many times `current` gets repointed afterward by
/// someone else. Freshly-generated identities return their own
/// `gen_dir`-rooted paths directly, for the same reason.
///
/// Verified against the exact 12-thread scenario that broke the
/// pre-symlink version, run 100+ consecutive times with zero failures
/// after both fixes (see this module's own tests).
pub fn ensure_identity(dir: &Path, common_name: &str) -> Result<TlsIdentity, TlsIdentityError> {
    validate_common_name(common_name)?;
    // 0700, not left to umask — matching the OCaml sibling module's
    // identical `Unix.mkdir dir 0o700`. Adversarial review found this
    // Rust version had drifted from that (plain `create_dir_all`, no
    // explicit mode — confirmed empirically to come out group/world-
    // readable under an ordinary umask): the RPM packaging already
    // creates this directory's own parent at 0700 (`packaging/rpm/
    // fossh.spec`), which masks the gap in the one deployment this
    // project currently ships, but this function should not depend on
    // always being called under an already-locked-down parent.
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)?;

    let current_link = dir.join("current");

    if let Some(resolved) = resolve_current(dir, &current_link) {
        let cert_pem_path = resolved.join("cert.pem");
        let key_pem_path = resolved.join("key.pem");
        if cert_is_valid(&cert_pem_path) && key_is_valid(&key_pem_path) {
            return Ok(TlsIdentity {
                cert_pem_path,
                key_pem_path,
            });
        }
    }

    let suffix = random_hex_suffix(8)?;
    let gen_dir_name = format!("gen-{}-{suffix}", std::process::id());
    let gen_dir = dir.join(&gen_dir_name);
    fs::DirBuilder::new().mode(0o700).create(&gen_dir)?;
    let cert_pem_path = gen_dir.join("cert.pem");
    let key_pem_path = gen_dir.join("key.pem");

    let tmp_link = dir.join(format!(".current-tmp-{}-{suffix}", std::process::id()));

    let result: Result<(), TlsIdentityError> = generate_into(&gen_dir, common_name).and_then(|()| {
        // Defensive, not expected on any path this function itself
        // ever produces (which always leaves `current` as a symlink,
        // never a real directory): a symlink rename can never replace
        // an existing *real* directory (EISDIR, POSIX — a rename can
        // only replace a same-kind destination, and a real directory
        // is not, kind-wise, replaceable by a symlink). Cheap to guard
        // against regardless — stray external state (a manual `mkdir`,
        // or output from some future, different version of this
        // function) — and safe even under a concurrent race: if
        // another caller's symlink has already replaced `current` by
        // the time this runs, `remove_dir_all` on a symlink removes
        // only the symlink itself, never recursing into its target
        // (documented `std::fs::remove_dir_all` behavior), so a
        // concurrent winner's real generation directory is never at
        // risk here even in the worst case — at most this caller's
        // own publish overwrites theirs a moment later with an
        // equally valid one.
        if fs::symlink_metadata(&current_link).is_ok_and(|m| m.is_dir()) {
            let _ = fs::remove_dir_all(&current_link);
        }
        let _ = fs::remove_file(&tmp_link);
        std::os::unix::fs::symlink(&gen_dir_name, &tmp_link)?;
        fs::rename(&tmp_link, &current_link).map_err(TlsIdentityError::Io)
    });

    match result {
        Ok(()) => Ok(TlsIdentity {
            cert_pem_path,
            key_pem_path,
        }),
        Err(e) => {
            // Our own generation directory only ever becomes
            // reachable via a successful rename above — on any
            // failure it is definitionally not referenced by
            // `current`, so it is always safe for us to discard,
            // never a concurrent winner's content. tmp_link needs the
            // same cleanup: adversarial review found it was
            // previously left behind — a dangling symlink pointing at
            // the gen_dir this branch just removed — whenever the
            // rename itself was what failed (confirmed reproducible,
            // not just theoretical, e.g. under a real EISDIR from the
            // defensive branch above only partially succeeding).
            let _ = fs::remove_dir_all(&gen_dir);
            let _ = fs::remove_file(&tmp_link);
            Err(e)
        }
    }
}

/// Resolves `dir/current` (a symlink to a specific `gen-*` directory)
/// to that directory's own path — or `None` if `current` doesn't exist
/// or isn't a symlink. `ensure_identity` uses this rather than ever
/// reading through `current` directly for anything it intends to
/// actually load cert/key content from — see that function's own doc
/// comment for the real, reproduced bug this specifically closes: two
/// separate reads through one mutable pointer are not atomic as a
/// pair, even though the pointer swap itself is.
fn resolve_current(dir: &Path, current_link: &Path) -> Option<PathBuf> {
    let target = fs::read_link(current_link).ok()?;
    Some(dir.join(target))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch_dir(name: &str) -> PathBuf {
        let p = std::env::temp_dir().join(format!(
            "fossh-admin-tls-identity-test-{name}-{}-{}",
            std::process::id(),
            random_hex_suffix(4).unwrap()
        ));
        let _ = fs::remove_dir_all(&p);
        p
    }

    fn read(path: &Path) -> String {
        fs::read_to_string(path).unwrap()
    }

    #[test]
    fn first_call_generates_a_real_certificate_and_key() {
        let dir = scratch_dir("fresh");
        let id = ensure_identity(&dir, "fossh-admin-test-fresh").unwrap();
        assert!(id.cert_pem_path.is_file());
        assert!(id.key_pem_path.is_file());
        let cert = read(&id.cert_pem_path);
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert!(cert.contains("-----END CERTIFICATE-----"));
        let mode = fs::metadata(&id.key_pem_path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
        // Regression check for an adversarial-review finding: an
        // earlier version created `dir` and each generation directory
        // with plain `fs::create_dir[_all]`, leaving their mode to
        // whatever the caller's umask produced (confirmed empirically
        // at the time to come out 0755 — world-readable/traversable —
        // under an ordinary umask 022), unlike the OCaml sibling
        // module's explicit `Unix.mkdir dir 0o700`. Now uses
        // `DirBuilder::mode(0o700)` explicitly for both.
        let dir_mode = fs::metadata(&dir).unwrap().permissions().mode() & 0o777;
        assert_eq!(dir_mode, 0o700, "dir itself must be 0700, not umask-dependent");
        let gen_dir_mode = fs::metadata(id.cert_pem_path.parent().unwrap())
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(gen_dir_mode, 0o700, "the generation directory must be 0700, not umask-dependent");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn second_call_returns_the_identical_certificate() {
        let dir = scratch_dir("stable");
        let first = ensure_identity(&dir, "fossh-admin-test-a").unwrap();
        let first_cert = read(&first.cert_pem_path);
        let second = ensure_identity(&dir, "a-different-cn-should-not-matter").unwrap();
        assert_eq!(first_cert, read(&second.cert_pem_path));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn two_different_directories_get_two_different_certificates() {
        let dir_a = scratch_dir("dir-a");
        let dir_b = scratch_dir("dir-b");
        let a = ensure_identity(&dir_a, "fossh-admin-test-a2").unwrap();
        let b = ensure_identity(&dir_b, "fossh-admin-test-b2").unwrap();
        assert_ne!(read(&a.cert_pem_path), read(&b.cert_pem_path));
        fs::remove_dir_all(&dir_a).ok();
        fs::remove_dir_all(&dir_b).ok();
    }

    /// Seeds `dir/current` as a symlink to a fake `gen-*` directory
    /// containing `cert.pem`/`key.pem` already written by the caller —
    /// matching the *actual* on-disk shape `ensure_identity` itself
    /// always produces (`current` is never a real directory, always a
    /// symlink to one — see that function's own doc comment for why),
    /// not the shape an earlier, since-replaced version of this
    /// function used. Simulating a leftover as a bare real directory
    /// instead (an earlier version of these two tests did exactly
    /// that) tests a state this code cannot actually produce, and
    /// silently stopped testing what it claimed to: it reliably
    /// failed with `EISDIR`, a real, distinct bug from the concurrency
    /// one this module's own tests already regression-test, caught
    /// only by actually running the suite many times, not by
    /// reasoning about the rename semantics alone.
    fn seed_leftover(dir: &Path, cert_bytes: &[u8], key_bytes: &[u8]) {
        let gen_dir = dir.join("gen-fake-leftover");
        fs::create_dir_all(&gen_dir).unwrap();
        fs::write(gen_dir.join("cert.pem"), cert_bytes).unwrap();
        fs::write(gen_dir.join("key.pem"), key_bytes).unwrap();
        std::os::unix::fs::symlink("gen-fake-leftover", dir.join("current")).unwrap();
    }

    #[test]
    fn a_corrupt_leftover_is_regenerated_not_trusted() {
        let dir = scratch_dir("corrupt");
        fs::create_dir_all(&dir).unwrap();
        seed_leftover(&dir, b"not a certificate", b"not a key");
        let id = ensure_identity(&dir, "fossh-admin-test-recovers").unwrap();
        let cert = read(&id.cert_pem_path);
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        assert_ne!(cert, "not a certificate");
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn an_expired_certificate_is_not_trusted() {
        let dir = scratch_dir("expired");
        fs::create_dir_all(&dir).unwrap();
        let gen_dir = dir.join("gen-fake-expired");
        fs::create_dir_all(&gen_dir).unwrap();
        let cert_path = gen_dir.join("cert.pem");
        let key_path = gen_dir.join("key.pem");
        let status = Command::new(OPENSSL_PATH)
            .args(["req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:prime256v1", "-nodes"])
            .args(["-not_before", "20200101000000Z", "-not_after", "20210101000000Z"])
            .arg("-keyout")
            .arg(&key_path)
            .arg("-out")
            .arg(&cert_path)
            .args(["-subj", "/CN=already-expired"])
            .status()
            .unwrap();
        assert!(status.success(), "test setup: generating an expired cert must itself succeed");
        let expired_bytes = read(&cert_path);
        std::os::unix::fs::symlink("gen-fake-expired", dir.join("current")).unwrap();

        let id = ensure_identity(&dir, "fossh-admin-test-replaces-expired").unwrap();
        assert_ne!(read(&id.cert_pem_path), expired_bytes);
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_leftover_real_directory_at_current_is_recovered_from() {
        // The one shape this function's own code defends against
        // defensively even though it never produces it itself (see
        // ensure_identity's own comment on the fs::symlink_metadata
        // check) -- exercised directly here since none of this
        // module's other tests otherwise construct it.
        let dir = scratch_dir("real-dir-leftover");
        let current = dir.join("current");
        fs::create_dir_all(&current).unwrap();
        fs::write(current.join("cert.pem"), b"not a certificate").unwrap();
        fs::write(current.join("key.pem"), b"not a key").unwrap();
        let id = ensure_identity(&dir, "fossh-admin-test-real-dir-leftover").unwrap();
        let cert = read(&id.cert_pem_path);
        assert!(cert.contains("-----BEGIN CERTIFICATE-----"));
        fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn common_name_with_dn_metacharacters_is_rejected() {
        for bad in ["innocuous/O=Evil Corp/OU=Fake Unit", "has=equals", "", &"a".repeat(65)] {
            let dir = scratch_dir("badcn");
            assert!(
                matches!(
                    ensure_identity(&dir, bad),
                    Err(TlsIdentityError::InvalidCommonName(_))
                ),
                "should reject common_name {bad:?}"
            );
            fs::remove_dir_all(&dir).ok();
        }
    }

    /// True if `cert_path`'s certificate and `key_path`'s private key
    /// are a genuinely matched pair (their public keys agree) — not
    /// just "each individually parses", which cert_is_valid/
    /// key_is_valid already establish on their own.
    fn is_matched_pair(cert_path: &Path, key_path: &Path) -> bool {
        let cert_pubkey = Command::new(OPENSSL_PATH)
            .args(["x509", "-in"])
            .arg(cert_path)
            .args(["-noout", "-pubkey"])
            .output()
            .unwrap();
        let key_pubkey = Command::new(OPENSSL_PATH)
            .args(["pkey", "-in"])
            .arg(key_path)
            .args(["-pubout"])
            .output()
            .unwrap();
        cert_pubkey.status.success() && key_pubkey.status.success() && cert_pubkey.stdout == key_pubkey.stdout
    }

    #[test]
    fn concurrent_first_callers_all_get_a_stable_matched_pair_each() {
        // Regression test for an adversarial-review finding: an
        // earlier version returned dir/current/{cert,key}.pem for
        // every caller — two separate reads mediated by one *mutable*
        // symlink that a *different* concurrent caller's own publish
        // could repoint in between them, producing a torn read (one
        // racer's cert paired with a different racer's key). The fix
        // means every racer gets a *stable* reference to whichever
        // specific generation it resolved or produced -- which is
        // *not* required to be the same generation every other racer
        // sees (that was the bug's own premise), only required to be
        // internally self-consistent for whoever holds it. This test
        // asserts exactly that: not that every racer converges on one
        // shared cert (the wrong property, tested by an earlier
        // version of this test, before the fix), but that every
        // single racer's own returned pair is a genuinely matched
        // certificate+key, no matter which generation it ended up
        // with.
        let dir = std::sync::Arc::new(scratch_dir("concurrent"));
        let handles: Vec<_> = (0..12)
            .map(|_| {
                let dir = std::sync::Arc::clone(&dir);
                std::thread::spawn(move || ensure_identity(&dir, "fossh-admin-test-race").unwrap())
            })
            .collect();
        let ids: Vec<_> = handles.into_iter().map(|h| h.join().unwrap()).collect();
        for (i, id) in ids.iter().enumerate() {
            assert!(cert_is_valid(&id.cert_pem_path), "racer {i}'s own cert must be valid");
            assert!(key_is_valid(&id.key_pem_path), "racer {i}'s own key must be valid");
            assert!(
                is_matched_pair(&id.cert_pem_path, &id.key_pem_path),
                "racer {i}'s own returned cert and key must be a genuinely matched pair, \
                 not torn from two different generations"
            );
        }
        // A fresh, non-racing caller afterward must also see a valid,
        // matched pair via the fast (already-established) path.
        let settled = ensure_identity(&dir, "fossh-admin-test-race-settled").unwrap();
        assert!(is_matched_pair(&settled.cert_pem_path, &settled.key_pem_path));
        fs::remove_dir_all(&*dir).ok();
    }

    #[test]
    fn a_reader_polling_across_a_republish_never_observes_a_torn_pair() {
        // A second angle on the same regression: rather than many
        // callers racing to *establish* an identity, this repeatedly
        // *re-resolves* dir/current while a background thread keeps
        // republishing fresh generations — modeling any real caller
        // that calls ensure_identity more than once over a process's
        // lifetime (e.g. after an earlier identity expired) while a
        // concurrent process is doing the same. Every single
        // observation must be an internally matched pair.
        let dir = std::sync::Arc::new(scratch_dir("torn-read"));
        ensure_identity(&dir, "fossh-admin-test-torn-read-seed").unwrap();

        let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let republisher = {
            let dir = std::sync::Arc::clone(&dir);
            let stop = std::sync::Arc::clone(&stop);
            std::thread::spawn(move || {
                while !stop.load(std::sync::atomic::Ordering::Relaxed) {
                    // Force a fresh generation every time by removing
                    // `current` first, so this genuinely republishes
                    // rather than hitting the fast path.
                    let _ = fs::remove_file(dir.join("current"));
                    let _ = ensure_identity(&dir, "fossh-admin-test-torn-read-republish");
                }
            })
        };

        let mut observed_any = false;
        for _ in 0..200 {
            if let Ok(id) = ensure_identity(&dir, "fossh-admin-test-torn-read-observer") {
                observed_any = true;
                assert!(
                    is_matched_pair(&id.cert_pem_path, &id.key_pem_path),
                    "an observer must never see a torn cert/key pair, even mid-republish"
                );
            }
        }
        stop.store(true, std::sync::atomic::Ordering::Relaxed);
        republisher.join().unwrap();
        assert!(observed_any, "test setup: the observer loop should have succeeded at least once");
        fs::remove_dir_all(&*dir).ok();
    }
}
