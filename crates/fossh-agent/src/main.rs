//! foSSH admin bridge — the local admin surfaces (§3.9's console,
//! §3.11's setup wizard, §2.1's operator auth, §3.4's watchdog status)
//! exposed as one JSON-lines protocol over this process's own stdin
//! and stdout, for `fossh-console` to drive.
//!
//! Never *listens* on anything. The console spawns this as a child and
//! holds both pipes; there is no socket, no port, and therefore nothing
//! for a second process to connect to. Every network client reached
//! from here — the watchdog's QUIC/mTLS channel
//! (`watchdog_status.rs`), its `Operator_auth_server` Unix socket
//! (`operator_auth_client.rs`), an operator-configured external
//! service (`integrations_net.rs`) — is dialled *out*, on demand,
//! from an explicit request.
//!
//! ## stdout belongs to the protocol
//!
//! Nothing in this binary may print to stdout except one complete
//! response frame per request. A stray `println!` anywhere — a debug
//! line, a library's own chatter — desynchronises the console's
//! parser. Diagnostics go to stderr, which the console forwards to the
//! journal and never parses.
//!
//! ## Framing
//!
//! One request object per line in, one response object per line out.
//! `serde_json`'s compact output contains no raw newline and escapes
//! every string it writes, so no field value can forge a frame
//! boundary (pinned by a test in `protocol.rs`).
//!
//! Input lines are capped at `MAX_LINE_LEN`. Crossing it is fatal to
//! the session rather than skipped: once a partial line has been read
//! there is no way to know where the next frame starts, and a parser
//! that tries to resynchronise on a stream it has lost track of is
//! exactly where frame-confusion bugs live. This project has already
//! paid once for an unbounded read loop that turned a large write into
//! a 65-second CPU burn (ADR-0057), so the cap is enforced while
//! reading rather than after.

#![forbid(unsafe_code)]

mod integrations_net;
mod modules;
mod operator_auth_client;
mod protocol;
mod setup;
mod telemetry;
mod watchdog_status;

use std::io::{BufWriter, Read, Write};
use std::path::PathBuf;

use fossh_admin::integrations::{self, Auth, Integrations, Method};
use protocol::{ErrorCode, MethodError, MethodResult, PROTOCOL_VERSION, Request, Response};
use serde_json::{Value, json};

/// Generous next to any real request (the largest is an armored public
/// key, itself capped at 256 KiB by `setup::MAX_KEY_LEN`) and small
/// enough that a runaway writer is bounded long before it matters.
const MAX_LINE_LEN: usize = 1024 * 1024;

fn main() -> std::process::ExitCode {
    let data_dir = std::env::var_os("FOSSH_DATA_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/var/lib/fossh"));
    // `.filter(|&k| k >= 1)`: the same P6 invariant `fossh doctor`
    // names — `k_anonymity = 0` would fold nothing into `(other)` at
    // all, silently defeating the k-anonymity the console's own header
    // claims. An unset or unparseable value already fell back to the
    // safe default; an explicit but invalid `0` must too.
    let k_anonymity: u32 = std::env::var("FOSSH_K_ANONYMITY")
        .ok()
        .and_then(|s| s.parse().ok())
        .filter(|&k| k >= 1)
        .unwrap_or(5);
    // §2.6's fixed path; overridable so this can be exercised end to
    // end without root in a development environment.
    let setup_token_path = std::env::var_os("FOSSH_SETUP_TOKEN_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/etc/fossh/setup-token"));

    let mut agent = Agent {
        data_dir,
        k_anonymity,
        setup: setup::Setup::new(setup_token_path),
        authenticated: false,
    };

    let stdin = std::io::stdin();
    let mut reader = stdin.lock();
    let stdout = std::io::stdout();
    let mut writer = BufWriter::new(stdout.lock());

    loop {
        match read_line(&mut reader) {
            Ok(None) => return std::process::ExitCode::SUCCESS,
            Ok(Some(line)) => {
                if line.trim().is_empty() {
                    continue;
                }
                let response = match serde_json::from_str::<Request>(&line) {
                    // `0` is this protocol's reserved id for a frame
                    // that could not be parsed, so a caller sending it
                    // on a well-formed request would produce a success
                    // frame indistinguishable from a parse failure.
                    // Refused rather than answered.
                    Ok(req) if req.id == 0 => Response::failure(
                        0,
                        MethodError::bad_request(
                            "id 0 is reserved for frames this agent could not parse; use any \
                             other id",
                        ),
                    ),
                    Ok(req) => {
                        let id = req.id;
                        match agent.dispatch(&req) {
                            Ok(result) => Response::success(id, result),
                            Err(e) => Response::failure(id, e),
                        }
                    }
                    // No `id` to echo — the frame it would have come
                    // from is the thing that failed to parse. `0` is
                    // reserved for exactly this, and the console
                    // treats an id it never sent as a protocol fault
                    // rather than matching it to an outstanding call.
                    Err(e) => Response::failure(
                        0,
                        MethodError::bad_request(format!("could not parse that request: {e}")),
                    ),
                };
                if write_frame(&mut writer, &response).is_err() {
                    // The console is gone. Nothing left to serve.
                    return std::process::ExitCode::SUCCESS;
                }
            }
            Err(LineError::TooLong) => {
                let _ = write_frame(
                    &mut writer,
                    &Response::failure(
                        0,
                        MethodError::bad_request(format!(
                            "a request line exceeded {MAX_LINE_LEN} bytes; the connection is now \
                             out of sync and this agent is exiting"
                        )),
                    ),
                );
                return std::process::ExitCode::FAILURE;
            }
            Err(LineError::Io(e)) => {
                eprintln!("fossh-agent: reading stdin: {e}");
                return std::process::ExitCode::FAILURE;
            }
        }
    }
}

#[derive(Debug)]
enum LineError {
    TooLong,
    Io(std::io::Error),
}

/// Reads one `\n`-terminated line, refusing to buffer more than
/// `MAX_LINE_LEN` bytes.
///
/// Byte-at-a-time on purpose. `BufRead::read_line` would grow its
/// destination without limit, and the alternative — `take(cap)` — makes
/// "the line ended" and "the cap was hit" indistinguishable, which is
/// precisely the distinction that decides between answering and
/// bailing out. The reader is a `StdinLock`, already buffered, so this
/// is not a syscall per byte.
fn read_line<R: Read>(reader: &mut R) -> Result<Option<String>, LineError> {
    let mut buf: Vec<u8> = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    loop {
        match reader.read(&mut byte) {
            Ok(0) => {
                if buf.is_empty() {
                    return Ok(None);
                }
                // A final line with no trailing newline is still a
                // complete frame; the console closing its pipe right
                // after a write is ordinary.
                break;
            }
            Ok(_) => {
                if byte[0] == b'\n' {
                    break;
                }
                if buf.len() >= MAX_LINE_LEN {
                    return Err(LineError::TooLong);
                }
                buf.push(byte[0]);
            }
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(LineError::Io(e)),
        }
    }
    Ok(Some(String::from_utf8_lossy(&buf).into_owned()))
}

fn write_frame<W: Write>(writer: &mut W, response: &Response) -> std::io::Result<()> {
    let line = serde_json::to_string(response).unwrap_or_else(|_| {
        // Unreachable for these types, and still not a reason to panic
        // inside a protocol writer.
        format!(
            r#"{{"id":{},"ok":false,"error":{{"code":"internal","message":"response could not be serialised"}}}}"#,
            response.id
        )
    });
    writer.write_all(line.as_bytes())?;
    writer.write_all(b"\n")?;
    // Flushed per frame: the console is a synchronous reader waiting on
    // this exact line, so a buffered response is a hang.
    writer.flush()
}

struct Agent {
    data_dir: PathBuf,
    k_anonymity: u32,
    setup: setup::Setup,
    /// Whether §2.1's challenge-response has succeeded in this session.
    /// Advisory: it records that the operator proved key possession to
    /// the watchdog, and the console uses it to gate its own
    /// presentation. It is deliberately *not* an access-control
    /// boundary for this process — everything reachable here is already
    /// reachable to whoever can run this binary, and pretending
    /// otherwise would be security theatre.
    authenticated: bool,
}

fn unix_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Parameter accessors that fail with a message naming the field, so a
/// console bug is legible in one line instead of "invalid params".
fn str_param<'a>(params: &'a Value, key: &str) -> Result<&'a str, MethodError> {
    params.get(key).and_then(Value::as_str).ok_or_else(|| {
        MethodError::bad_request(format!("\"{key}\" is required and must be a string"))
    })
}

fn i64_param(params: &Value, key: &str) -> Result<i64, MethodError> {
    params.get(key).and_then(Value::as_i64).ok_or_else(|| {
        MethodError::bad_request(format!("\"{key}\" is required and must be a number"))
    })
}

impl Agent {
    fn data_key(&self) -> Result<zeroize::Zeroizing<[u8; 32]>, MethodError> {
        fossh_admin::data_key::load_or_generate(&self.data_dir.join(".data_key"))
            .map_err(|e| MethodError::internal(format!("opening this install's data key: {e}")))
    }

    fn load_integrations(&self) -> Result<Integrations, MethodError> {
        let key = self.data_key()?;
        Integrations::load(&self.data_dir, &key).map_err(|e| match e {
            integrations::IntegrationError::Corrupt => {
                MethodError::new(ErrorCode::Internal, e.to_string())
            }
            other => MethodError::internal(other.to_string()),
        })
    }

    fn save_integrations(&self, set: &Integrations) -> Result<(), MethodError> {
        let key = self.data_key()?;
        set.save(&self.data_dir, &key)
            .map_err(|e| MethodError::internal(e.to_string()))
    }

    fn dispatch(&mut self, req: &Request) -> MethodResult {
        let p = &req.params;
        match req.method.as_str() {
            "agent.hello" => self.hello(),
            "telemetry.summary" => self.telemetry_summary(),
            "telemetry.query" => self.telemetry_query(p),
            "watchdog.status" => self.watchdog_status(),
            "setup.state" => Ok(self.setup_state()),
            "setup.reload" => {
                self.setup.reload();
                Ok(self.setup_state())
            }
            "setup.generate_key" => self.setup_generate_key(),
            "setup.enroll" => self.setup_enroll(p),
            "operator.authenticate" => self.operator_authenticate(),
            "integrations.list" => self.integrations_list(),
            "providers.list" => self.providers_list(),
            "modules.list" => self.modules_list(),
            "integrations.add" => self.integrations_add(p),
            "integrations.remove" => self.integrations_remove(p),
            "integrations.test" => self.integrations_test(p),
            other => {
                // A method in a namespace no module claims is a
                // different mistake from a typo'd verb, and saying so
                // saves a developer writing a module the obvious
                // first hour of confusion.
                let Some(ns) = modules::namespace_of(other) else {
                    return Err(MethodError::bad_request(format!(
                        "no such method: \"{other}\""
                    )));
                };
                let (mods, _) = modules::load();
                let Some(module) = mods.iter().find(|m| m.namespace == ns) else {
                    // A method in a namespace no module claims is a
                    // different mistake from a typo'd verb, and saying
                    // so saves a developer writing a module the
                    // obvious first hour of confusion.
                    return Err(MethodError::bad_request(format!(
                        "no module owns the namespace \"{ns}\" — install one that does, or \
                         check `modules.list`"
                    )));
                };
                if module.builtin {
                    // A built-in namespace reaching here means the
                    // verb does not exist, not that the module is
                    // missing.
                    return Err(MethodError::bad_request(format!(
                        "no such method: \"{other}\""
                    )));
                }
                self.dispatch_to_module(module, req)
            }
        }
    }

    /// Hands a request to the module that owns its namespace.
    ///
    /// The module's reply is re-parsed rather than forwarded verbatim:
    /// a module must not be able to put arbitrary bytes on the agent's
    /// stdout, which is the console's protocol stream. Whatever comes
    /// back is unwrapped and re-emitted by the agent's own writer,
    /// under the id the console actually sent.
    fn dispatch_to_module(&self, module: &modules::Manifest, req: &Request) -> MethodResult {
        let line = serde_json::to_string(&json!({
            "id": req.id,
            "method": req.method,
            "params": req.params,
        }))
        .map_err(|e| MethodError::internal(format!("serialising for the module: {e}")))?;

        let reply = modules::dispatch(module, &line)
            .map_err(|e| MethodError::new(ErrorCode::Unavailable, e.to_string()))?;

        let frame: Value = serde_json::from_str(&reply).map_err(|_| {
            MethodError::new(
                ErrorCode::Internal,
                format!(
                    "the module \"{}\" replied with something that is not a response frame",
                    module.namespace
                ),
            )
        })?;

        if frame.get("ok").and_then(Value::as_bool) == Some(true) {
            return Ok(frame.get("result").cloned().unwrap_or(json!({})));
        }
        let error = frame.get("error");
        let message = error
            .and_then(|e| e.get("message"))
            .and_then(Value::as_str)
            .unwrap_or("the module reported a failure with no detail")
            .to_string();
        // A module's error code is taken only if it is one of ours;
        // anything else becomes `internal` rather than letting a
        // module invent protocol vocabulary.
        let code = match error.and_then(|e| e.get("code")).and_then(Value::as_str) {
            Some("bad_request") => ErrorCode::BadRequest,
            Some("not_found") => ErrorCode::NotFound,
            Some("unavailable") => ErrorCode::Unavailable,
            Some("denied") => ErrorCode::Denied,
            Some("conflict") => ErrorCode::Conflict,
            _ => ErrorCode::Internal,
        };
        Err(MethodError::new(code, message))
    }

    fn hello(&self) -> MethodResult {
        Ok(json!({
            "protocol": PROTOCOL_VERSION,
            "version": env!("CARGO_PKG_VERSION"),
            "data_dir": self.data_dir.to_string_lossy(),
            "k_anonymity": self.k_anonymity,
            "features": {
                // The console renders the watchdog panel differently
                // when this is false, rather than showing a permanent
                // "unreachable" that is really "not compiled in".
                "quic": cfg!(feature = "quic"),
            },
        }))
    }

    fn telemetry_summary(&self) -> MethodResult {
        let sites = telemetry::load_summary(&self.data_dir, unix_now(), self.k_anonymity)
            .map_err(MethodError::unavailable)?;
        Ok(json!({
            "k_anonymity": self.k_anonymity,
            "sites": sites
                .into_iter()
                .map(|s| json!({
                    "slug": s.slug,
                    "public": s.public,
                    "disabled": s.disabled,
                    "allowlist": s.allowlist,
                    "created_at": s.created_at,
                    "hits_today": s.hits_today,
                    "uniques_today": s.uniques_today,
                }))
                .collect::<Vec<_>>(),
        }))
    }

    fn telemetry_query(&self, p: &Value) -> MethodResult {
        let slug = str_param(p, "site")?;
        let from = i64_param(p, "from")?;
        let to = i64_param(p, "to")?;
        if to < from {
            return Err(MethodError::bad_request(
                "\"to\" is earlier than \"from\"".to_string(),
            ));
        }
        let group_by_raw = p.get("group_by").and_then(Value::as_array).ok_or_else(|| {
            MethodError::bad_request("\"group_by\" is required and must be an array")
        })?;
        // Every dimension the store knows, at most once each — a
        // repeated field would produce duplicated columns for no
        // benefit and is far more likely a console bug than intent.
        if group_by_raw.len() > 7 {
            return Err(MethodError::bad_request(
                "\"group_by\" lists more fields than exist".to_string(),
            ));
        }
        let mut group_by = Vec::with_capacity(group_by_raw.len());
        for value in group_by_raw {
            let name = value
                .as_str()
                .ok_or_else(|| MethodError::bad_request("\"group_by\" entries must be strings"))?;
            let field = telemetry::parse_field(name).ok_or_else(|| {
                MethodError::bad_request(format!("\"{name}\" is not a groupable field"))
            })?;
            if group_by.contains(&field) {
                return Err(MethodError::bad_request(format!(
                    "\"{name}\" is listed twice in \"group_by\""
                )));
            }
            group_by.push(field);
        }

        let result = telemetry::query(&self.data_dir, slug, from, to, &group_by, self.k_anonymity)
            .map_err(|e| MethodError::new(ErrorCode::Unavailable, e))?;

        Ok(json!({
            "k_anonymity": self.k_anonymity,
            "entirely_folded": result.entirely_folded,
            "rows": result.rows
                .into_iter()
                .map(|r| json!({
                    "dims": r.dims,
                    "hits": r.hits,
                    "uniques": r.uniques,
                    "p50": r.p50,
                    "p95": r.p95,
                }))
                .collect::<Vec<_>>(),
        }))
    }

    fn watchdog_status(&self) -> MethodResult {
        match watchdog_status::query() {
            Ok(status) => Ok(json!({
                "child": match status.child {
                    fossh_admin::command_client::ChildState::Running => "running",
                    fossh_admin::command_client::ChildState::Stopped => "stopped",
                },
                "tamper": match status.tamper {
                    fossh_admin::command_client::TamperState::Clean => "clean",
                    fossh_admin::command_client::TamperState::Tampered => "tampered",
                    fossh_admin::command_client::TamperState::Unknown => "unknown",
                },
            })),
            // A watchdog that isn't running is an ordinary state on
            // EPEL/RHEL, where the subpackage doesn't exist at all —
            // reported as `unavailable` so the console can say so
            // calmly rather than as an error.
            Err(e) => Err(MethodError::unavailable(e)),
        }
    }

    fn setup_state(&self) -> Value {
        json!({
            "state": self.setup.state().as_str(),
            "detail": self.setup.detail(),
            "fingerprint": self.setup.enrolled_fingerprint(),
            "token_path": self.setup.token_path.to_string_lossy(),
        })
    }

    fn setup_generate_key(&self) -> MethodResult {
        let generated = self.setup.generate_key().map_err(MethodError::internal)?;
        // The private half crosses to the console exactly once, so the
        // operator can save it — §3.11's own wording. It is never
        // written to disk by this process and never logged.
        Ok(json!({
            "fingerprint": generated.fingerprint,
            "public_key_armored": generated.public_key_armored,
            "private_key_armored": generated.private_key_armored.as_str(),
        }))
    }

    fn setup_enroll(&mut self, p: &Value) -> MethodResult {
        let armored = str_param(p, "public_key_armored")?;
        match self.setup.enroll(armored) {
            Ok(fingerprint) => Ok(json!({ "fingerprint": fingerprint })),
            Err(setup::EnrollOutcome::Invalid(m)) => Err(MethodError::bad_request(m)),
            Err(setup::EnrollOutcome::Denied) => Err(MethodError::new(
                ErrorCode::Denied,
                "the watchdog refused that setup token — it is not the one currently live",
            )),
            Err(setup::EnrollOutcome::EnrollFailed(code)) => Err(MethodError::new(
                ErrorCode::Denied,
                format!(
                    "the watchdog rejected that key ({code}). The setup token was not used up, so \
                     a different key can be tried straight away."
                ),
            )),
            Err(setup::EnrollOutcome::Failed(m)) => Err(MethodError::unavailable(m)),
        }
    }

    fn operator_authenticate(&mut self) -> MethodResult {
        match operator_auth_client::authenticate() {
            Ok(_session_token) => {
                // The session token stays here. The console has no use
                // for it — nothing it can call takes one — and every
                // extra place a live credential exists is a place it
                // can leak from.
                self.authenticated = true;
                Ok(json!({ "authenticated": true }))
            }
            Err(e) => {
                self.authenticated = false;
                Err(MethodError::new(ErrorCode::Denied, e.to_string()))
            }
        }
    }

    fn integrations_list(&self) -> MethodResult {
        let set = self.load_integrations()?;
        Ok(json!({
            "integrations": set.items
                .iter()
                .map(|i| json!({
                    "name": i.name,
                    "endpoint": i.endpoint,
                    "method": i.method.as_str(),
                    "auth": match &i.auth {
                        Auth::Bearer => json!({"placement": "bearer"}),
                        Auth::Header { name } => json!({"placement": "header", "name": name}),
                    },
                    "created_at": i.created_at,
                    // Never the key itself — at most its last four
                    // characters, and only when it is long enough for
                    // that to be a hint rather than most of it.
                    "key_hint": i.key_hint(),
                }))
                .collect::<Vec<_>>(),
        }))
    }

    /// Every module on this install, built-in and external alike.
    ///
    /// The console renders this rather than a hardcoded page list, so
    /// a module a developer dropped in appears without the console
    /// knowing anything about it. Telemetry appears here too: it is
    /// the flagship, not a special case.
    fn modules_list(&self) -> MethodResult {
        let (mods, problems) = modules::load();
        Ok(json!({
            "modules": mods
                .iter()
                .map(|m| json!({
                    "namespace": m.namespace,
                    "name": m.name,
                    "description": m.description,
                    "icon": m.icon,
                    "builtin": m.builtin,
                }))
                .collect::<Vec<_>>(),
            "problems": problems.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        }))
    }

    /// The provider templates the console offers as starting points.
    ///
    /// Read-only, and read fresh on every call rather than cached at
    /// startup: an operator who drops a definition into
    /// `providers.d/` should see it by reopening the dialog, not by
    /// restarting the console.
    fn providers_list(&self) -> MethodResult {
        let (providers, problems) = fossh_admin::providers::load();
        Ok(json!({
            "providers": providers
                .iter()
                .map(|p| json!({
                    "id": p.id,
                    "name": p.name,
                    "docs": p.docs,
                    "endpoint": p.endpoint,
                    "method": p.method.as_str(),
                    "auth": match p.auth() {
                        Auth::Bearer => json!({"placement": "bearer"}),
                        Auth::Header { name } => json!({"placement": "header", "name": name}),
                    },
                    "key_hint": p.key_hint,
                    "fields": p.fields.iter().map(|f| json!({
                        "key": f.key,
                        "label": f.label,
                        "placeholder": f.placeholder,
                        "help": f.help,
                    })).collect::<Vec<_>>(),
                }))
                .collect::<Vec<_>>(),
            // Reported rather than swallowed: a definition an operator
            // added and that did not load is exactly the thing they
            // need told, and the console shows it as a note under the
            // list.
            "problems": problems.iter().map(|e| e.to_string()).collect::<Vec<_>>(),
        }))
    }

    fn integrations_add(&self, p: &Value) -> MethodResult {
        let name = str_param(p, "name")?;
        let endpoint = str_param(p, "endpoint")?;
        let api_key = str_param(p, "api_key")?;
        let method = match p.get("method").and_then(Value::as_str).unwrap_or("GET") {
            "GET" | "get" => Method::Get,
            "POST" | "post" => Method::Post,
            other => {
                return Err(MethodError::bad_request(format!(
                    "\"{other}\" is not a supported method — GET or POST"
                )));
            }
        };
        let auth = match p
            .get("auth")
            .and_then(|a| a.get("placement"))
            .and_then(Value::as_str)
            .unwrap_or("bearer")
        {
            "bearer" => Auth::Bearer,
            "header" => Auth::Header {
                name: p
                    .get("auth")
                    .and_then(|a| a.get("name"))
                    .and_then(Value::as_str)
                    .ok_or_else(|| {
                        MethodError::bad_request(
                            "a header-placement integration needs \"auth\".\"name\"",
                        )
                    })?
                    .to_string(),
            },
            other => {
                return Err(MethodError::bad_request(format!(
                    "\"{other}\" is not a supported credential placement — bearer or header"
                )));
            }
        };

        let key = self.data_key()?;
        integrations::modify(&self.data_dir, &key, |set| {
            set.add(name, endpoint, auth, method, api_key, unix_now())
        })
        .map_err(|e| match e {
            integrations::IntegrationError::Duplicate(_) => {
                MethodError::new(ErrorCode::Conflict, e.to_string())
            }
            integrations::IntegrationError::Invalid(_)
            | integrations::IntegrationError::TooMany => MethodError::bad_request(e.to_string()),
            other => MethodError::internal(other.to_string()),
        })?;
        Ok(json!({ "added": name }))
    }

    fn integrations_remove(&self, p: &Value) -> MethodResult {
        let name = str_param(p, "name")?;
        let key = self.data_key()?;
        integrations::modify(&self.data_dir, &key, |set| set.remove(name)).map_err(
            |e| match e {
                integrations::IntegrationError::NotFound(_) => {
                    MethodError::new(ErrorCode::NotFound, e.to_string())
                }
                other => MethodError::internal(other.to_string()),
            },
        )?;
        Ok(json!({ "removed": name }))
    }

    fn integrations_test(&self, p: &Value) -> MethodResult {
        let name = str_param(p, "name")?;
        let set = self.load_integrations()?;
        let integration = set.get(name).ok_or_else(|| {
            MethodError::new(
                ErrorCode::NotFound,
                format!("no integration named \"{name}\""),
            )
        })?;

        match integrations_net::test(integration) {
            Ok(outcome) => Ok(json!({
                "status": outcome.status,
                "reachable": outcome.transport_ok,
                "body": outcome.body_snippet,
            })),
            Err(integrations_net::NetError::CurlMissing) => Err(MethodError::new(
                ErrorCode::Unavailable,
                integrations_net::NetError::CurlMissing.to_string(),
            )),
            Err(e) => Err(MethodError::unavailable(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_all(input: &str) -> Vec<Result<Option<String>, &'static str>> {
        let mut cursor = std::io::Cursor::new(input.as_bytes().to_vec());
        let mut out = Vec::new();
        loop {
            match read_line(&mut cursor) {
                Ok(None) => {
                    out.push(Ok(None));
                    return out;
                }
                Ok(Some(l)) => out.push(Ok(Some(l))),
                Err(LineError::TooLong) => {
                    out.push(Err("too long"));
                    return out;
                }
                Err(LineError::Io(_)) => {
                    out.push(Err("io"));
                    return out;
                }
            }
        }
    }

    #[test]
    fn lines_are_split_on_newlines_and_eof_ends_the_stream() {
        let got = read_all("one\ntwo\n");
        assert_eq!(got[0].as_ref().unwrap().as_deref(), Some("one"));
        assert_eq!(got[1].as_ref().unwrap().as_deref(), Some("two"));
        assert_eq!(got[2].as_ref().unwrap().as_deref(), None);
    }

    #[test]
    fn a_final_line_without_a_trailing_newline_is_still_delivered() {
        // The console closing its pipe immediately after a write is
        // ordinary; dropping that last frame would lose a real request.
        let got = read_all("only");
        assert_eq!(got[0].as_ref().unwrap().as_deref(), Some("only"));
        assert_eq!(got[1].as_ref().unwrap().as_deref(), None);
    }

    #[test]
    fn an_empty_stream_ends_immediately_rather_than_yielding_an_empty_frame() {
        let got = read_all("");
        assert_eq!(got[0].as_ref().unwrap().as_deref(), None);
    }

    #[test]
    fn a_line_past_the_cap_is_fatal_rather_than_silently_truncated() {
        // Truncating would hand a *valid-looking* prefix to the JSON
        // parser and leave the remainder to be read as the next frame
        // — the frame-confusion case this cap exists to prevent.
        let huge = format!("{}\n", "a".repeat(MAX_LINE_LEN + 10));
        let got = read_all(&huge);
        assert_eq!(got[0], Err("too long"));
    }

    #[test]
    fn a_line_exactly_at_the_cap_is_still_accepted() {
        // Off-by-one on a limit that terminates the session is worth
        // pinning in both directions.
        let exact = format!("{}\n", "a".repeat(MAX_LINE_LEN));
        let got = read_all(&exact);
        assert_eq!(
            got[0].as_ref().unwrap().as_ref().unwrap().len(),
            MAX_LINE_LEN
        );
    }

    #[test]
    fn invalid_utf8_is_replaced_rather_than_killing_the_session() {
        // It will fail JSON parsing and come back as `bad_request`,
        // which is the right outcome — but it must not take the
        // process down on the way there.
        let mut cursor = std::io::Cursor::new(vec![0xff, 0xfe, b'\n']);
        assert!(read_line(&mut cursor).unwrap().is_some());
    }

    /// Each caller gets its own directory. These tests run in
    /// parallel by default, and an earlier revision shared one path
    /// derived from the pid alone — which meant one test's
    /// `remove_dir_all` deleted another's `.data_key` mid-write, and
    /// the resulting "could not be decrypted" looked exactly like a
    /// real sealing bug.
    fn agent_for_tests(name: &str) -> Agent {
        let dir = std::env::temp_dir().join(format!(
            "fossh-agent-dispatch-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Agent {
            data_dir: dir,
            k_anonymity: 5,
            setup: setup::Setup::new(PathBuf::from("/nonexistent/fossh/setup-token")),
            authenticated: false,
        }
    }

    fn call(agent: &mut Agent, method: &str, params: Value) -> MethodResult {
        agent.dispatch(&Request {
            id: 1,
            method: method.to_string(),
            params,
        })
    }

    #[test]
    fn an_unknown_method_is_a_bad_request_not_a_crash() {
        let mut agent = agent_for_tests("unknown-method");
        let err = call(&mut agent, "telemetry.deleteEverything", json!({})).unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("telemetry.deleteEverything"));
    }

    #[test]
    fn hello_reports_the_protocol_version_the_console_checks() {
        let mut agent = agent_for_tests("hello");
        let result = call(&mut agent, "agent.hello", json!({})).unwrap();
        assert_eq!(result["protocol"], PROTOCOL_VERSION);
        assert!(result["features"]["quic"].is_boolean());
    }

    #[test]
    fn setup_state_never_includes_the_token_value() {
        // The single most important property of this split. Asserted
        // against the serialised frame, not the struct, because the
        // frame is what actually leaves the process.
        let path = std::env::temp_dir().join(format!("fossh-agent-tok-{}", std::process::id()));
        std::fs::write(&path, "SUPERSECRETTOKEN").unwrap();
        let mut agent = agent_for_tests("setup-state");
        agent.setup = setup::Setup::new(path.clone());

        let result = call(&mut agent, "setup.state", json!({})).unwrap();
        let rendered = serde_json::to_string(&result).unwrap();
        assert!(
            !rendered.contains("SUPERSECRETTOKEN"),
            "the setup token reached the console: {rendered}"
        );
        assert_eq!(result["state"], "ready");
        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn a_query_for_an_ungroupable_field_is_refused_by_name() {
        let mut agent = agent_for_tests("ungroupable");
        let err = call(
            &mut agent,
            "telemetry.query",
            json!({"site": "blog", "from": 0, "to": 1, "group_by": ["visitor_ip"]}),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("visitor_ip"));
    }

    #[test]
    fn a_query_with_a_reversed_range_is_refused_rather_than_returning_nothing() {
        let mut agent = agent_for_tests("reversed-range");
        let err = call(
            &mut agent,
            "telemetry.query",
            json!({"site": "blog", "from": 100, "to": 1, "group_by": ["path"]}),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
    }

    #[test]
    fn a_query_repeating_a_group_by_field_is_refused() {
        let mut agent = agent_for_tests("repeat-group");
        let err = call(
            &mut agent,
            "telemetry.query",
            json!({"site": "blog", "from": 0, "to": 1, "group_by": ["path", "path"]}),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("twice"));
    }

    #[test]
    fn missing_parameters_are_named_in_the_error() {
        let mut agent = agent_for_tests("missing-params");
        let err = call(&mut agent, "telemetry.query", json!({})).unwrap_err();
        assert!(err.message.contains("site"), "unhelpful: {}", err.message);
    }

    #[test]
    fn an_integration_survives_a_full_add_list_remove_round_trip() {
        let mut agent = agent_for_tests("round-trip");
        call(
            &mut agent,
            "integrations.add",
            json!({
                "name": "alerts",
                "endpoint": "https://hooks.example.com/x",
                "api_key": "sk_live_abcdefghijkl",
                "method": "POST",
                "auth": {"placement": "header", "name": "X-Api-Key"}
            }),
        )
        .unwrap();

        let listed = call(&mut agent, "integrations.list", json!({})).unwrap();
        let items = listed["integrations"].as_array().unwrap();
        assert_eq!(items.len(), 1);
        assert_eq!(items[0]["name"], "alerts");
        assert_eq!(items[0]["method"], "POST");
        assert_eq!(items[0]["key_hint"], "ijkl");

        call(&mut agent, "integrations.remove", json!({"name": "alerts"})).unwrap();
        let listed = call(&mut agent, "integrations.list", json!({})).unwrap();
        assert!(listed["integrations"].as_array().unwrap().is_empty());
        std::fs::remove_dir_all(&agent.data_dir).ok();
    }

    #[test]
    fn listing_integrations_never_returns_the_key_itself() {
        let mut agent = agent_for_tests("list-redaction");
        call(
            &mut agent,
            "integrations.add",
            json!({
                "name": "alerts",
                "endpoint": "https://hooks.example.com/x",
                "api_key": "sk_live_LISTCANARY99"
            }),
        )
        .unwrap();
        let listed = call(&mut agent, "integrations.list", json!({})).unwrap();
        let rendered = serde_json::to_string(&listed).unwrap();
        assert!(
            !rendered.contains("LISTCANARY"),
            "a credential reached the console: {rendered}"
        );
        std::fs::remove_dir_all(&agent.data_dir).ok();
    }

    #[test]
    fn adding_an_integration_over_plain_http_to_a_remote_host_is_refused() {
        let mut agent = agent_for_tests("plain-http");
        let err = call(
            &mut agent,
            "integrations.add",
            json!({
                "name": "leaky",
                "endpoint": "http://api.example.com/x",
                "api_key": "sk_live_abcdefghijkl"
            }),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        assert!(err.message.contains("https"));
        std::fs::remove_dir_all(&agent.data_dir).ok();
    }

    #[test]
    fn adding_a_duplicate_integration_reports_conflict_specifically() {
        // The console shows a different message for "that name is
        // taken" than for "that request was malformed", so the codes
        // have to actually differ.
        let mut agent = agent_for_tests("duplicate");
        let params = json!({
            "name": "alerts",
            "endpoint": "https://hooks.example.com/x",
            "api_key": "sk_live_abcdefghijkl"
        });
        call(&mut agent, "integrations.add", params.clone()).unwrap();
        let err = call(&mut agent, "integrations.add", params).unwrap_err();
        assert_eq!(err.code, ErrorCode::Conflict);
        std::fs::remove_dir_all(&agent.data_dir).ok();
    }

    #[test]
    fn removing_an_integration_that_is_not_there_reports_not_found() {
        let mut agent = agent_for_tests("remove-missing");
        let err = call(&mut agent, "integrations.remove", json!({"name": "ghost"})).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        std::fs::remove_dir_all(&agent.data_dir).ok();
    }

    #[test]
    fn testing_an_integration_that_is_not_there_reports_not_found() {
        let mut agent = agent_for_tests("test-missing");
        let err = call(&mut agent, "integrations.test", json!({"name": "ghost"})).unwrap_err();
        assert_eq!(err.code, ErrorCode::NotFound);
        std::fs::remove_dir_all(&agent.data_dir).ok();
    }

    #[test]
    fn an_api_key_with_a_line_break_is_refused_at_the_protocol_boundary_too() {
        // `fossh-admin` rejects it, and this pins that the agent
        // surfaces that rejection rather than swallowing it.
        let mut agent = agent_for_tests("crlf-key");
        let err = call(
            &mut agent,
            "integrations.add",
            json!({
                "name": "inject",
                "endpoint": "https://api.example.com/x",
                "api_key": "sk_live_x\r\nX-Evil: 1"
            }),
        )
        .unwrap_err();
        assert_eq!(err.code, ErrorCode::BadRequest);
        std::fs::remove_dir_all(&agent.data_dir).ok();
    }
}
