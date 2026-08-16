const ID_PLACEHOLDER: &str = ":id";
const EMAIL_PLACEHOLDER: &str = ":email";

const HEX_RUN_MIN: usize = 16;
const DIGIT_RUN_MIN: usize = 8;
const UUID_LEN: usize = 36;
const ULID_LEN: usize = 26;

const CROCKFORD_ALPHABET: &[u8] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

pub fn sanitize_path(raw: &str) -> String {
    let path_only = strip_query_and_fragment(raw);
    let path_only = if path_only.is_empty() { "/" } else { path_only };

    let normalized = if let Some(stripped) = path_only.strip_prefix('/') {
        stripped
    } else {
        path_only
    };

    let mut out = String::with_capacity(path_only.len() + 1);
    out.push('/');
    for (i, seg) in normalized.split('/').enumerate() {
        if i > 0 {
            out.push('/');
        }
        out.push_str(classify(seg).replacement(seg));
    }
    out
}

fn strip_query_and_fragment(raw: &str) -> &str {
    let end = raw.find(['?', '#']).unwrap_or(raw.len());
    &raw[..end]
}

enum Segment {
    Keep,
    HighEntropyId,
    Email,
}

impl Segment {
    fn replacement<'a>(&self, original: &'a str) -> &'a str {
        match self {
            Segment::Keep => original,
            Segment::HighEntropyId => ID_PLACEHOLDER,
            Segment::Email => EMAIL_PLACEHOLDER,
        }
    }
}

fn classify(seg: &str) -> Segment {
    if seg.is_empty() {
        return Segment::Keep;
    }
    if looks_like_email(seg) {
        return Segment::Email;
    }
    if looks_like_uuid(seg)
        || looks_like_ulid(seg)
        || looks_like_long_hex(seg)
        || looks_like_long_digits(seg)
    {
        return Segment::HighEntropyId;
    }
    Segment::Keep
}

fn looks_like_uuid(seg: &str) -> bool {
    let b = seg.as_bytes();
    if b.len() != UUID_LEN {
        return false;
    }
    for (i, &c) in b.iter().enumerate() {
        let want_dash = matches!(i, 8 | 13 | 18 | 23);
        if want_dash {
            if c != b'-' {
                return false;
            }
        } else if !c.is_ascii_hexdigit() {
            return false;
        }
    }
    true
}

fn looks_like_ulid(seg: &str) -> bool {
    let b = seg.as_bytes();
    b.len() == ULID_LEN
        && b.iter()
            .all(|&c| CROCKFORD_ALPHABET.contains(&c.to_ascii_uppercase()))
}

fn looks_like_long_hex(seg: &str) -> bool {
    let b = seg.as_bytes();
    b.len() >= HEX_RUN_MIN && b.iter().all(|c| c.is_ascii_hexdigit())
}

fn looks_like_long_digits(seg: &str) -> bool {
    let b = seg.as_bytes();
    b.len() >= DIGIT_RUN_MIN && b.iter().all(|c| c.is_ascii_digit())
}

fn looks_like_email(seg: &str) -> bool {
    if seg.matches('@').count() != 1 {
        return false;
    }
    let Some(at) = seg.find('@') else {
        return false;
    };
    let (local, domain) = (&seg[..at], &seg[at + 1..]);
    if local.is_empty() || domain.is_empty() {
        return false;
    }
    let Some(last_dot) = domain.rfind('.') else {
        return false;
    };
    let tld = &domain[last_dot + 1..];
    let domain_before_tld = &domain[..last_dot];
    if domain_before_tld.is_empty() || tld.len() < 2 {
        return false;
    }
    let tld_ok = tld.bytes().all(|b| b.is_ascii_alphabetic());
    let domain_ok = domain
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-');
    let local_ok = local
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'%' | b'+' | b'-'));
    tld_ok && domain_ok && local_ok
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table() {
        let cases: &[(&str, &str)] = &[

            ("", "/"),
            ("/", "/"),
            ("//", "//"),
            ("///", "///"),
            ("a", "/a"),
            ("/a", "/a"),
            ("/a/", "/a/"),
            ("/a/b", "/a/b"),
            ("/a/b/", "/a/b/"),
            ("/a//b", "/a//b"),
            ("/a/b/c/d/e", "/a/b/c/d/e"),
            ("a/b", "/a/b"),

            ("/a?x=1", "/a"),
            ("/a#frag", "/a"),
            ("/a?x=1#frag", "/a"),
            ("?x=1", "/"),
            ("#frag", "/"),
            ("?x=1#frag", "/"),
            ("/a/b?x=1&y=2", "/a/b"),
            ("/?x=1", "/"),
            ("/a/?x=1", "/a/"),
            ("/search?q=jane.doe@example.com", "/search"),
            ("/a?", "/a"),
            ("/a#", "/a"),

            ("/1234567", "/1234567"),
            ("/12345678", "/:id"),
            ("/123456789", "/:id"),
            ("/users/12345678/edit", "/users/:id/edit"),
            ("/users/1234567/edit", "/users/1234567/edit"),
            ("/order/000000012", "/order/:id"),

            ("/abcdef0123456", "/abcdef0123456"),
            ("/deadbeefdeadbeef", "/:id"),
            (
                "/sessions/9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08",
                "/sessions/:id",
            ),

            ("/550e8400-e29b-41d4-a716-446655440000", "/:id"),
            ("/550E8400-E29B-41D4-A716-446655440000", "/:id"),
            (
                "/users/550e8400-e29b-41d4-a716-446655440000/orders",
                "/users/:id/orders",
            ),
            (
                "/550e8400xe29bx41d4xa716x446655440000",
                "/550e8400xe29bx41d4xa716x446655440000",
            ),

            ("/01ARZ3NDEKTSV4RRFFQ69G5FAV", "/:id"),
            ("/01arz3ndektsv4rrffq69g5fav", "/:id"),
            (
                "/orders/01ARZ3NDEKTSV4RRFFQ69G5FAV/items",
                "/orders/:id/items",
            ),

            ("/jane.doe@example.com", "/:email"),
            ("/contact/jane.doe@example.com", "/contact/:email"),
            ("/jane@x.co", "/:email"),
            ("/not-an-email@", "/not-an-email@"),
            ("/@example.com", "/@example.com"),
            ("/jane@doe@example.com", "/jane@doe@example.com"),
            ("/jane@localhost", "/jane@localhost"),
            ("/jane@example.c", "/jane@example.c"),
            ("/jane_doe+tag@example.co.uk", "/:email"),

            ("/about", "/about"),
            (
                "/blog/2026/how-we-built-fossh",
                "/blog/2026/how-we-built-fossh",
            ),
            ("/pricing", "/pricing"),
            ("/api/v1/health", "/api/v1/health"),
            ("/tr/gizlilik", "/tr/gizlilik"),
            ("/café", "/café"),
            ("/日本語", "/日本語"),
            ("/a-b_c.d:e", "/a-b_c.d:e"),
            ("/v1.2.3", "/v1.2.3"),

            (
                "/users/12345678/posts/550e8400-e29b-41d4-a716-446655440000/comments/deadbeefdeadbeef",
                "/users/:id/posts/:id/comments/:id",
            ),
            (
                "/u/jane@example.com/orders/12345678",
                "/u/:email/orders/:id",
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(&sanitize_path(input), expected, "input: {input:?}");
        }
        assert!(
            cases.len() >= 45,
            "expected a substantial table, got {}",
            cases.len()
        );
    }

    #[test]
    fn digit_run_boundary() {
        assert_eq!(
            sanitize_path(&format!("/{}", "1".repeat(7))),
            format!("/{}", "1".repeat(7))
        );
        assert_eq!(sanitize_path(&format!("/{}", "1".repeat(8))), "/:id");
        assert_eq!(sanitize_path(&format!("/{}", "0".repeat(8))), "/:id");
        assert_eq!(sanitize_path(&format!("/{}", "9".repeat(20))), "/:id");
    }

    #[test]
    fn hex_run_boundary() {
        assert_eq!(
            sanitize_path(&format!("/{}", "a".repeat(15))),
            format!("/{}", "a".repeat(15))
        );
        assert_eq!(sanitize_path(&format!("/{}", "a".repeat(16))), "/:id");
        assert_eq!(sanitize_path(&format!("/{}", "F".repeat(16))), "/:id");
        assert_eq!(sanitize_path(&format!("/{}", "b".repeat(100))), "/:id");

        assert_eq!(
            sanitize_path(&format!("/{}", "f".repeat(7))),
            format!("/{}", "f".repeat(7))
        );
    }

    #[test]
    fn uuid_boundary() {
        let uuid = "550e8400-e29b-41d4-a716-446655440000";
        assert_eq!(uuid.len(), UUID_LEN);
        assert_eq!(sanitize_path(&format!("/{uuid}")), "/:id");
        assert_eq!(sanitize_path(&format!("/{}", uuid.to_uppercase())), "/:id");
        assert_eq!(
            sanitize_path(&format!("/{}", &uuid[..uuid.len() - 1])),
            format!("/{}", &uuid[..uuid.len() - 1])
        );
        assert_eq!(sanitize_path(&format!("/{uuid}0")), format!("/{uuid}0"));
        let wrong_sep = uuid.replace('-', "x");
        assert_eq!(
            sanitize_path(&format!("/{wrong_sep}")),
            format!("/{wrong_sep}")
        );
    }

    #[test]
    fn ulid_boundary() {
        let ulid = "01ARZ3NDEKTSV4RRFFQ69G5FAV";
        assert_eq!(ulid.len(), ULID_LEN);
        assert_eq!(sanitize_path(&format!("/{ulid}")), "/:id");
        assert_eq!(
            sanitize_path(&format!("/{}", &ulid[..ulid.len() - 1])),
            format!("/{}", &ulid[..ulid.len() - 1])
        );
        let too_long = format!("{ulid}X");
        assert_eq!(
            sanitize_path(&format!("/{too_long}")),
            format!("/{too_long}")
        );

        let with_forbidden = format!("{}I", &ulid[..ulid.len() - 1]);
        assert_eq!(with_forbidden.len(), ULID_LEN);
        assert_eq!(
            sanitize_path(&format!("/{with_forbidden}")),
            format!("/{with_forbidden}")
        );
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {

        let inputs = [
            "/",
            "",
            "?",
            "#",
            "?#",
            "/?#",
            "//??##",
            "/\0",
            "/%00",
            "/../../etc/passwd",
            "/a\u{0}b",
            "/\u{FFFD}",
            "/😀",
            "/@",
            "/@.",
            "/.@",
            "/@@@@@@@@",
        ];
        for input in inputs {
            let _ = sanitize_path(input);
        }
        let long = format!("/{}", "a".repeat(10_000));
        let _ = sanitize_path(&long);
    }

    #[test]
    fn idempotent() {
        let inputs = [
            "/users/12345678/edit",
            "/550e8400-e29b-41d4-a716-446655440000",
            "/jane@example.com",
            "/about",
        ];
        for input in inputs {
            let once = sanitize_path(input);
            let twice = sanitize_path(&once);
            assert_eq!(
                once, twice,
                "sanitize_path must be idempotent for {input:?}"
            );
        }
    }
}
