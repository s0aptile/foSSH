//! Allowlist grammar and bounded-size validation shared by event names,
//! property keys, and property values (P8, S4).
//!
//! The per-site *allowlist membership* check (is this name/key permitted for
//! this site) needs the site's config and therefore lives in `fossh-ingest`;
//! this module only enforces the context-free grammar and length bounds.
//! P8 states property values are `[a-z0-9_.:-]{1,64}`-shaped like names and
//! keys, but S4 caps values at a different length (256 B vs 64 B) — read
//! literally that's a contradiction, so the grammar (charset) is treated as
//! shared and the length cap is taken from S4 per field. See DECISIONS.md.

use std::fmt;

/// `[a-z0-9_.:-]`
fn is_grammar_byte(b: u8) -> bool {
    matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'_' | b'.' | b':' | b'-')
}

/// S4: event name cap, in bytes.
pub const NAME_MAX: usize = 64;
/// S4: property key cap, in bytes.
pub const KEY_MAX: usize = 64;
/// S4: property value cap, in bytes.
pub const VALUE_MAX: usize = 256;
/// S4: properties per event.
pub const MAX_PROPS: usize = 16;
/// S4: request body cap, in bytes.
pub const BODY_MAX: usize = 8 * 1024;
/// S4: environment variable value cap, in bytes.
pub const ENV_VALUE_MAX: usize = 4 * 1024;
/// S4: batch size cap, in events.
pub const BATCH_MAX: usize = 64;

/// A grammar or bound violation on a name/key/value/prop-count. Never
/// carries the offending input itself — P10 forbids user input from ever
/// reaching a place it could be logged verbatim, and an error type that
/// stores the bad string is exactly that kind of place.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ValidationError {
    Empty,
    TooLong { max: usize, actual: usize },
    BadByte { at: usize },
    TooMany { max: usize, actual: usize },
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ValidationError::Empty => write!(f, "value must not be empty"),
            ValidationError::TooLong { max, actual } => {
                write!(f, "value is {actual} bytes, exceeds cap of {max}")
            }
            ValidationError::BadByte { at } => {
                write!(f, "byte at offset {at} is outside [a-z0-9_.:-]")
            }
            ValidationError::TooMany { max, actual } => {
                write!(f, "{actual} items exceeds cap of {max}")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

fn validate_grammar(s: &str, max_len: usize) -> Result<(), ValidationError> {
    if s.is_empty() {
        return Err(ValidationError::Empty);
    }
    let bytes = s.as_bytes();
    if bytes.len() > max_len {
        return Err(ValidationError::TooLong {
            max: max_len,
            actual: bytes.len(),
        });
    }
    if let Some(at) = bytes.iter().position(|&b| !is_grammar_byte(b)) {
        return Err(ValidationError::BadByte { at });
    }
    Ok(())
}

macro_rules! grammar_newtype {
    ($name:ident, $max:expr, $doc:expr) => {
        #[doc = $doc]
        #[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub struct $name(String);

        impl $name {
            /// Length cap in bytes for this type (grammar + length are
            /// enforced at construction, so every live value is valid).
            pub const MAX_LEN: usize = $max;

            pub fn parse(s: impl Into<String>) -> Result<Self, ValidationError> {
                let s = s.into();
                validate_grammar(&s, $max)?;
                Ok(Self(s))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }

        impl std::borrow::Borrow<str> for $name {
            fn borrow(&self) -> &str {
                &self.0
            }
        }
    };
}

grammar_newtype!(
    Name,
    NAME_MAX,
    "An allowlisted event name: `[a-z0-9_.:-]{1,64}`."
);
grammar_newtype!(
    Key,
    KEY_MAX,
    "An allowlisted property key: `[a-z0-9_.:-]{1,64}`."
);
grammar_newtype!(
    Val,
    VALUE_MAX,
    "A bounded property value: `[a-z0-9_.:-]{1,256}`."
);

/// Bounds-checks a batch of `(Key, Val)` pairs against S4's per-event
/// property-count cap. `Key`/`Val` are already grammar- and length-valid by
/// construction, so this is the one remaining whole-event check.
pub fn validate_prop_count(props: &[(Key, Val)]) -> Result<(), ValidationError> {
    if props.len() > MAX_PROPS {
        return Err(ValidationError::TooMany {
            max: MAX_PROPS,
            actual: props.len(),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_name() {
        assert!(Name::parse("signup.completed").is_ok());
        assert!(Name::parse("a").is_ok());
        assert!(Name::parse("a_b-c.d:e0").is_ok());
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(Name::parse(""), Err(ValidationError::Empty));
    }

    #[test]
    fn rejects_too_long() {
        let s = "a".repeat(65);
        assert_eq!(
            Name::parse(s),
            Err(ValidationError::TooLong {
                max: 64,
                actual: 65
            })
        );
    }

    #[test]
    fn accepts_exactly_at_max_len() {
        let s = "a".repeat(64);
        assert!(Name::parse(s).is_ok());
        let s = "a".repeat(256);
        assert!(Val::parse(s).is_ok());
        let s = "a".repeat(257);
        assert!(Val::parse(s).is_err());
    }

    #[test]
    fn rejects_uppercase() {
        assert_eq!(
            Name::parse("Signup"),
            Err(ValidationError::BadByte { at: 0 })
        );
    }

    #[test]
    fn rejects_disallowed_bytes() {
        assert_eq!(Name::parse("a b"), Err(ValidationError::BadByte { at: 1 }));
        assert_eq!(Name::parse("a/b"), Err(ValidationError::BadByte { at: 1 }));
        assert_eq!(Name::parse("a$b"), Err(ValidationError::BadByte { at: 1 }));
        assert_eq!(
            Name::parse("caf\u{e9}"),
            Err(ValidationError::BadByte { at: 3 })
        );
    }

    #[test]
    fn allows_all_grammar_punctuation() {
        assert!(Name::parse("a.b:c-d_e").is_ok());
    }

    #[test]
    fn key_and_val_share_grammar_but_not_length() {
        assert!(Key::parse("a".repeat(64)).is_ok());
        assert!(Key::parse("a".repeat(65)).is_err());
        assert!(Val::parse("a".repeat(200)).is_ok());
    }

    #[test]
    fn prop_count_boundary() {
        let props: Vec<(Key, Val)> = (0..16)
            .map(|i| {
                (
                    Key::parse(format!("k{i}")).unwrap(),
                    Val::parse("v").unwrap(),
                )
            })
            .collect();
        assert!(validate_prop_count(&props).is_ok());

        let props: Vec<(Key, Val)> = (0..17)
            .map(|i| {
                (
                    Key::parse(format!("k{i}")).unwrap(),
                    Val::parse("v").unwrap(),
                )
            })
            .collect();
        assert_eq!(
            validate_prop_count(&props),
            Err(ValidationError::TooMany {
                max: 16,
                actual: 17
            })
        );
    }

    #[test]
    fn no_upper_bound_type_confusion() {
        // A Val exceeding NAME_MAX (64) but within VALUE_MAX (256) must be
        // accepted — regressions here would mean the macro is accidentally
        // sharing one constant across all three newtypes.
        let s = "a".repeat(100);
        assert!(Val::parse(s).is_ok());
    }
}
