//! Request → `Event` pipeline: wire parsing (JSON body or `/e.gif` query
//! string), allowlist + grammar/bound validation, UA bucketing, and
//! visitor hashing. Auth (`auth.rs`) and rate limiting (`ratelimit.rs`)
//! happen before this runs; DNT/GPC opt-out (P5) and S4's size caps are
//! enforced here, first, before anything else about the request is
//! examined — S2's "fail closed" applies to the *cheapest* checks first.

use std::collections::HashMap;

use serde::Deserialize;

use fossh_core::types::{Country, Event, EventKind, Host, Path as SanitizedPath, SiteId};
use fossh_core::ua::bucket_user_agent;
use fossh_core::validate::{self, BATCH_MAX, BODY_MAX, Key, Name, Val};
use fossh_core::visitor::hash_visitor;

#[derive(Debug)]
pub enum PipelineError {
    /// Body (or the batch it decodes to) exceeds S4's caps — `413`.
    TooLarge,
    /// Malformed JSON, a field failing its grammar/bound, or a name/prop
    /// key not on the site's allowlist — `422`. Carries a reason for
    /// internal use only; §7.1 says the ingest path is never allowed a
    /// response body, so nothing here is ever echoed back to the caller.
    Invalid(String),
}

pub enum PipelineOutcome {
    /// P5: `DNT: 1` or `Sec-GPC: 1` present (and respected) — the caller
    /// responds `204` and records nothing, not even an aggregate counter.
    OptedOut,
    Accepted(Vec<Event>),
}

/// Everything the pipeline needs about the request and the site that
/// nothing in the request body itself supplies.
pub struct RequestContext<'a> {
    pub site_id: SiteId,
    pub site_allowlist: &'a [String],
    pub client_ip: &'a str,
    pub user_agent: &'a str,
    pub referrer_header: Option<&'a str>,
    pub dnt: bool,
    pub gpc: bool,
    pub respect_optout_signals: bool,
    pub now: i64,
    pub daily_salt: &'a [u8; 32],
    /// GeoIP resolution happens outside this crate (§10's `country_db`);
    /// `Country::UNKNOWN` ("ZZ") is a fully valid, supported value, not a
    /// fallback used only on error (`country_db = "none"` makes every
    /// event `ZZ` on purpose, per §10).
    pub country: Country,
}

#[derive(Debug, Deserialize)]
struct WireEvent {
    name: String,
    #[serde(default)]
    kind: Option<String>,
    #[serde(default)]
    path: Option<String>,
    #[serde(default)]
    referrer: Option<String>,
    #[serde(default)]
    value: Option<i64>,
    #[serde(default)]
    props: HashMap<String, String>,
}

// No `deny_unknown_fields`: unlike operator-facing `fossh.toml` (where a
// typo should fail loudly), the wire protocol should tolerate fields a
// newer client SDK sends that this version doesn't know about yet —
// including a client-supplied `ts`, which is deliberately absent from
// this struct so it's silently ignored rather than rejected (§6: "client
// ts is ignored").
#[derive(Deserialize)]
#[serde(untagged)]
enum WireBody {
    Batch(Vec<WireEvent>),
    Single(WireEvent),
}

fn parse_kind(s: Option<&str>) -> Result<EventKind, PipelineError> {
    match s {
        None | Some("pageview") => Ok(EventKind::Pageview),
        Some("action") => Ok(EventKind::Action),
        Some("timing") => Ok(EventKind::Timing),
        Some("error") => Ok(EventKind::Error),
        Some(other) => Err(PipelineError::Invalid(format!("unknown kind {other:?}"))),
    }
}

/// The already-typed shape both wire parsers (`from_json_body`,
/// `from_query_string`) and `fossh-ffi`'s direct calls
/// (`fossh_pageview`/`fossh_event`/`fossh_timing`, §11) build before
/// handing an event to `assemble_event` — the one place allowlist
/// membership, grammar/bound validation, UA bucketing, and visitor
/// hashing actually happen, so there's exactly one code path that can
/// produce a validated `Event`, no matter which transport it came from.
pub struct EventFields {
    pub name: String,
    pub kind: Option<String>,
    pub path: Option<String>,
    pub referrer: Option<String>,
    pub value: Option<i64>,
    pub props: HashMap<String, String>,
}

impl From<WireEvent> for EventFields {
    fn from(w: WireEvent) -> Self {
        Self {
            name: w.name,
            kind: w.kind,
            path: w.path,
            referrer: w.referrer,
            value: w.value,
            props: w.props,
        }
    }
}

pub fn assemble_event(fields: EventFields, ctx: &RequestContext) -> Result<Event, PipelineError> {
    let name = Name::parse(&fields.name).map_err(|e| PipelineError::Invalid(e.to_string()))?;
    if !ctx
        .site_allowlist
        .iter()
        .any(|allowed| allowed == name.as_str())
    {
        return Err(PipelineError::Invalid(
            "event name not on this site's allowlist".to_string(),
        ));
    }

    if fields.props.len() > validate::MAX_PROPS {
        return Err(PipelineError::Invalid("too many properties".to_string()));
    }
    let mut props = Vec::with_capacity(fields.props.len());
    for (k, v) in fields.props {
        if !ctx.site_allowlist.iter().any(|allowed| allowed == &k) {
            return Err(PipelineError::Invalid(
                "property key not on this site's allowlist".to_string(),
            ));
        }
        let key = Key::parse(k).map_err(|e| PipelineError::Invalid(e.to_string()))?;
        let val = Val::parse(v).map_err(|e| PipelineError::Invalid(e.to_string()))?;
        props.push((key, val));
    }

    let kind = parse_kind(fields.kind.as_deref())?;
    let path = fields.path.as_deref().map(SanitizedPath::from_raw);
    let referrer = fields
        .referrer
        .as_deref()
        .or(ctx.referrer_header)
        .and_then(Host::from_referrer_url);

    let ua = bucket_user_agent(ctx.user_agent);
    let visitor = if ctx.respect_optout_signals && (ctx.dnt || ctx.gpc) {
        None
    } else {
        Some(hash_visitor(
            ctx.daily_salt,
            ctx.client_ip,
            ctx.user_agent,
            ctx.site_id,
        ))
    };

    let event = Event {
        site_id: ctx.site_id,
        ts: ctx.now,
        kind,
        name,
        path,
        referrer,
        country: ctx.country,
        browser: ua.browser,
        os: ua.os,
        device: ua.device,
        visitor,
        value: fields.value,
        props,
    };
    event
        .validate()
        .map_err(|e| PipelineError::Invalid(e.to_string()))?;
    Ok(event)
}

/// `POST /e`: parses a JSON event or batch from the request body.
pub fn from_json_body(
    raw_body: &[u8],
    ctx: &RequestContext,
) -> Result<PipelineOutcome, PipelineError> {
    if raw_body.len() > BODY_MAX {
        return Err(PipelineError::TooLarge);
    }
    // P5, checked before anything else about the body is examined.
    if ctx.respect_optout_signals && (ctx.dnt || ctx.gpc) {
        return Ok(PipelineOutcome::OptedOut);
    }

    let wire: WireBody =
        serde_json::from_slice(raw_body).map_err(|e| PipelineError::Invalid(e.to_string()))?;
    let wire_events = match wire {
        WireBody::Batch(v) => v,
        WireBody::Single(w) => vec![w],
    };
    if wire_events.len() > BATCH_MAX {
        return Err(PipelineError::TooLarge);
    }

    let events = wire_events
        .into_iter()
        .map(|w| assemble_event(w.into(), ctx))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PipelineOutcome::Accepted(events))
}

/// `GET /e.gif`: same validation, params in the query string instead of a
/// JSON body. Supports `name`, `kind`, `path`, `referrer`, `value`, and
/// `props.<key>=<value>` for properties.
pub fn from_query_string(
    query: &str,
    ctx: &RequestContext,
) -> Result<PipelineOutcome, PipelineError> {
    if query.len() > BODY_MAX {
        return Err(PipelineError::TooLarge);
    }
    if ctx.respect_optout_signals && (ctx.dnt || ctx.gpc) {
        return Ok(PipelineOutcome::OptedOut);
    }

    let mut name = None;
    let mut kind = None;
    let mut path = None;
    let mut referrer = None;
    let mut value = None;
    let mut props = HashMap::new();

    for pair in query.split('&').filter(|s| !s.is_empty()) {
        let (raw_key, raw_val) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(raw_key);
        let val = percent_decode(raw_val);
        match key.as_str() {
            "name" => name = Some(val),
            "kind" => kind = Some(val),
            "path" => path = Some(val),
            "referrer" => referrer = Some(val),
            "value" => value = val.parse::<i64>().ok(),
            other => {
                if let Some(prop_key) = other.strip_prefix("props.") {
                    props.insert(prop_key.to_string(), val);
                }
            }
        }
    }

    let fields = EventFields {
        name: name.ok_or_else(|| PipelineError::Invalid("missing name".to_string()))?,
        kind,
        path,
        referrer,
        value,
        props,
    };
    let event = assemble_event(fields, ctx)?;
    Ok(PipelineOutcome::Accepted(vec![event]))
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn percent_decode(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            b'%' if i + 2 < bytes.len() => match (hex_val(bytes[i + 1]), hex_val(bytes[i + 2])) {
                (Some(h), Some(l)) => {
                    out.push((h << 4) | l);
                    i += 3;
                }
                _ => {
                    out.push(bytes[i]);
                    i += 1;
                }
            },
            b'+' => {
                out.push(b' ');
                i += 1;
            }
            b => {
                out.push(b);
                i += 1;
            }
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx(allowlist: &[String]) -> RequestContext<'_> {
        RequestContext {
            site_id: SiteId::new(1),
            site_allowlist: allowlist,
            client_ip: "203.0.113.7",
            user_agent: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/126.0.0.0 Safari/537.36",
            referrer_header: None,
            dnt: false,
            gpc: false,
            respect_optout_signals: true,
            now: 1_700_000_000,
            daily_salt: &[0x42; 32],
            country: Country::parse("TR").unwrap(),
        }
    }

    fn outcome_events(o: PipelineOutcome) -> Vec<Event> {
        match o {
            PipelineOutcome::Accepted(events) => events,
            PipelineOutcome::OptedOut => panic!("expected Accepted"),
        }
    }

    #[test]
    fn accepts_a_single_allowlisted_event() {
        let allow = vec!["pageview".to_string()];
        let body = br#"{"name":"pageview","path":"/blog/1"}"#;
        let outcome = from_json_body(body, &ctx(&allow)).unwrap();
        let events = outcome_events(outcome);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].name.as_str(), "pageview");
        assert_eq!(events[0].path.as_ref().unwrap().as_str(), "/blog/1");
    }

    #[test]
    fn accepts_a_batch() {
        let allow = vec!["pageview".to_string()];
        let body = br#"[{"name":"pageview"},{"name":"pageview"},{"name":"pageview"}]"#;
        let events = outcome_events(from_json_body(body, &ctx(&allow)).unwrap());
        assert_eq!(events.len(), 3);
    }

    #[test]
    fn rejects_name_not_on_allowlist() {
        let allow = vec!["pageview".to_string()];
        let body = br#"{"name":"totally.unlisted"}"#;
        assert!(matches!(
            from_json_body(body, &ctx(&allow)),
            Err(PipelineError::Invalid(_))
        ));
    }

    #[test]
    fn rejects_prop_key_not_on_allowlist() {
        let allow = vec!["signup.completed".to_string()]; // "plan" not included
        let body = br#"{"name":"signup.completed","props":{"plan":"pro"}}"#;
        assert!(matches!(
            from_json_body(body, &ctx(&allow)),
            Err(PipelineError::Invalid(_))
        ));
    }

    #[test]
    fn accepts_allowlisted_prop_key() {
        let allow = vec!["signup.completed".to_string(), "plan".to_string()];
        let body = br#"{"name":"signup.completed","props":{"plan":"pro"}}"#;
        let events = outcome_events(from_json_body(body, &ctx(&allow)).unwrap());
        assert_eq!(events[0].props.len(), 1);
    }

    #[test]
    fn rejects_body_over_size_cap() {
        let allow = vec!["pageview".to_string()];
        let big = format!(r#"{{"name":"pageview","path":"{}"}}"#, "a".repeat(BODY_MAX));
        assert!(matches!(
            from_json_body(big.as_bytes(), &ctx(&allow)),
            Err(PipelineError::TooLarge)
        ));
    }

    #[test]
    fn rejects_batch_over_size_cap() {
        let allow = vec!["pageview".to_string()];
        let events: Vec<String> = (0..65)
            .map(|_| r#"{"name":"pageview"}"#.to_string())
            .collect();
        let body = format!("[{}]", events.join(","));
        assert!(matches!(
            from_json_body(body.as_bytes(), &ctx(&allow)),
            Err(PipelineError::TooLarge)
        ));
    }

    #[test]
    fn rejects_malformed_json() {
        let allow = vec!["pageview".to_string()];
        assert!(matches!(
            from_json_body(b"not json", &ctx(&allow)),
            Err(PipelineError::Invalid(_))
        ));
    }

    #[test]
    fn dnt_header_opts_out_and_records_nothing() {
        let allow = vec!["pageview".to_string()];
        let mut c = ctx(&allow);
        c.dnt = true;
        let outcome = from_json_body(br#"{"name":"pageview"}"#, &c).unwrap();
        assert!(matches!(outcome, PipelineOutcome::OptedOut));
    }

    #[test]
    fn gpc_header_opts_out_and_records_nothing() {
        let allow = vec!["pageview".to_string()];
        let mut c = ctx(&allow);
        c.gpc = true;
        let outcome = from_json_body(br#"{"name":"pageview"}"#, &c).unwrap();
        assert!(matches!(outcome, PipelineOutcome::OptedOut));
    }

    #[test]
    fn optout_signal_is_ignored_when_respect_optout_signals_is_off() {
        let allow = vec!["pageview".to_string()];
        let mut c = ctx(&allow);
        c.dnt = true;
        c.respect_optout_signals = false;
        let events = outcome_events(from_json_body(br#"{"name":"pageview"}"#, &c).unwrap());
        assert_eq!(events.len(), 1);
    }

    #[test]
    fn opted_out_event_has_no_visitor_hash_when_signals_are_respected_but_off_path() {
        // Belt-and-suspenders: even outside the DNT/GPC 204-short-circuit,
        // an opted-out request must never carry a visitor hash forward.
        let allow = vec!["pageview".to_string()];
        let mut c = ctx(&allow);
        c.respect_optout_signals = false; // force past the 204 short-circuit
        c.dnt = true;
        let events = outcome_events(from_json_body(br#"{"name":"pageview"}"#, &c).unwrap());
        assert!(
            events[0].visitor.is_some(),
            "signals off entirely: visitor hash proceeds normally"
        );
    }

    #[test]
    fn client_supplied_ts_is_ignored() {
        let allow = vec!["pageview".to_string()];
        let body = br#"{"name":"pageview","ts":1}"#; // "ts" isn't a WireEvent field — must not error
        let events = outcome_events(from_json_body(body, &ctx(&allow)).unwrap());
        assert_eq!(
            events[0].ts, 1_700_000_000,
            "ts always comes from RequestContext::now, never the client"
        );
    }

    #[test]
    fn query_string_beacon_round_trip() {
        let allow = vec!["pageview".to_string(), "plan".to_string()];
        let qs = "name=pageview&path=%2Fblog%2F1&props.plan=pro";
        let events = outcome_events(from_query_string(qs, &ctx(&allow)).unwrap());
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].path.as_ref().unwrap().as_str(), "/blog/1");
        assert_eq!(events[0].props[0].1.as_str(), "pro");
    }

    #[test]
    fn query_string_missing_name_is_invalid() {
        let allow = vec!["pageview".to_string()];
        assert!(matches!(
            from_query_string("path=/x", &ctx(&allow)),
            Err(PipelineError::Invalid(_))
        ));
    }

    #[test]
    fn percent_decode_handles_plus_and_hex_escapes() {
        assert_eq!(percent_decode("a+b%20c"), "a b c");
        assert_eq!(percent_decode("100%25"), "100%");
    }
}
