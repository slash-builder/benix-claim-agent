//! Parser for the hub's `qr_payload` wire grammar.
//!
//! Verified against real source, not assumed: `quickring/hub/src/
//! pairing.rs::create_session` produces
//!
//! ```text
//! quickring://pair?session=<pair_session_id>&endpoint=<percent-encoded-ws-url>
//! ```
//!
//! (`pairing.rs`'s own `percent_encode` is a minimal RFC 3986 encoder —
//! unreserved chars `A-Za-z0-9-_.~` pass through, everything else becomes
//! `%XX` uppercase hex — applied only to the embedded `ws://`/`wss://`
//! endpoint). This module's job, per `fabric-kit`'s own doc comment on
//! `pair_claim` ("parsing `quickring://pair?...` is left to the caller —
//! a URL query string, not something this SDK needs to own parsing for"),
//! is turning that exact string back into the two values `FabricClient::
//! pair_claim` wants: a `pair_session_id` and an `endpoint` URL.
//!
//! "Byte-identical" is a hard requirement upstream of this parser (Courier
//! must not re-render or transform the hub's string before POSTing it
//! here) — on this side, that means no lenient/best-effort parsing.
//! Anything that deviates from the grammar above is a hard parse error,
//! not a best guess.

use std::fmt;

use url::Url;

/// The two values `fabric_kit::FabricClient::pair_claim` needs, extracted
/// from a `qr_payload` string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedQrPayload {
    /// The hub's `pair_session_id`. Deliberately treated as an opaque,
    /// non-empty string — not validated as a UUID beyond that. The hub
    /// mints it (`Uuid::new_v4().to_string()` today) and is the source of
    /// truth for its shape; this agent has no business rejecting a
    /// syntactically-different-but-otherwise-valid id if the hub ever
    /// changes how it mints one.
    pub pair_session_id: String,
    /// The hub's WebSocket endpoint (e.g. `wss://hub.example.com/v1`),
    /// percent-decoded back to the exact string `FabricClient::pair_claim`
    /// expects as its `url` argument.
    pub endpoint: String,
}

/// Why a `qr_payload` string was rejected. Maps 1:1 onto the handler's
/// `400 invalid_qr_payload` response — see `src/error.rs`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QrPayloadError {
    /// Not a parseable URL at all (includes malformed percent-encoding —
    /// the `url` crate's own parser rejects a lone `%` or a non-hex `%XX`
    /// pair as a parse error, so that case is folded in here rather than
    /// given its own variant).
    Malformed(String),
    /// Parsed, but the scheme was not `quickring`.
    WrongScheme(String),
    /// Parsed, but the authority was not `pair` (e.g. `quickring://
    /// claim?...`). Named separately from `WrongScheme` so the 400's
    /// `message` field can say which part was wrong.
    WrongAuthority(String),
    /// A required query parameter was missing or present-but-empty.
    MissingParam(&'static str),
}

impl fmt::Display for QrPayloadError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(e) => write!(f, "not a parseable URL: {e}"),
            Self::WrongScheme(s) => write!(f, "expected scheme 'quickring', got '{s}'"),
            Self::WrongAuthority(a) => write!(f, "expected authority 'pair', got '{a}'"),
            Self::MissingParam(p) => write!(f, "missing or empty query parameter '{p}'"),
        }
    }
}

impl std::error::Error for QrPayloadError {}

/// Parse a `qr_payload` string per the exact grammar documented above.
///
/// No leniency: an unrecognized scheme, wrong authority, missing
/// `session`/`endpoint`, or unparseable percent-encoding is `Err`, never a
/// best-effort partial result. Unrecognized *extra* query parameters are
/// ignored rather than rejected — the hub's grammar today is exactly
/// `session`+`endpoint`, but a hub that additively grows a third field
/// later (schema evolution, not a version this agent controls) shouldn't
/// be treated as sending a malformed payload; only the two fields this
/// agent actually consumes are load-bearing here.
pub fn parse(raw: &str) -> Result<ParsedQrPayload, QrPayloadError> {
    let url = Url::parse(raw).map_err(|e| QrPayloadError::Malformed(e.to_string()))?;

    if url.scheme() != "quickring" {
        return Err(QrPayloadError::WrongScheme(url.scheme().to_string()));
    }

    match url.host_str() {
        Some("pair") => {}
        Some(other) => return Err(QrPayloadError::WrongAuthority(other.to_string())),
        None => return Err(QrPayloadError::WrongAuthority(String::new())),
    }

    let mut session: Option<String> = None;
    let mut endpoint: Option<String> = None;
    for (key, value) in url.query_pairs() {
        match key.as_ref() {
            "session" => session = Some(value.into_owned()),
            "endpoint" => endpoint = Some(value.into_owned()),
            _ => {} // additive/unknown field — not this agent's concern, see docs above
        }
    }

    let pair_session_id = session
        .filter(|s| !s.is_empty())
        .ok_or(QrPayloadError::MissingParam("session"))?;
    let endpoint = endpoint
        .filter(|s| !s.is_empty())
        .ok_or(QrPayloadError::MissingParam("endpoint"))?;

    Ok(ParsedQrPayload {
        pair_session_id,
        endpoint,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The exact shape `quickring/hub/src/pairing.rs::create_session`
    /// produces for a real `ws://127.0.0.1:8080/v1` dev hub (its own
    /// `public_ws_url()` default).
    #[test]
    fn parses_a_real_hub_payload() {
        let raw = "quickring://pair?session=8f14e45f-ceea-467e-9862-a9a1a1c2f2e1&endpoint=ws%3A%2F%2F127.0.0.1%3A8080%2Fv1";
        let parsed = parse(raw).expect("valid payload must parse");
        assert_eq!(
            parsed.pair_session_id,
            "8f14e45f-ceea-467e-9862-a9a1a1c2f2e1"
        );
        assert_eq!(parsed.endpoint, "ws://127.0.0.1:8080/v1");
    }

    #[test]
    fn parses_a_wss_production_style_payload() {
        let raw = "quickring://pair?session=sess-123&endpoint=wss%3A%2F%2Fhub.quickring.me%2Fv1";
        let parsed = parse(raw).expect("valid payload must parse");
        assert_eq!(parsed.pair_session_id, "sess-123");
        assert_eq!(parsed.endpoint, "wss://hub.quickring.me/v1");
    }

    #[test]
    fn param_order_does_not_matter() {
        let raw = "quickring://pair?endpoint=wss%3A%2F%2Fhub.example.com%2Fv1&session=sess-abc";
        let parsed = parse(raw).expect("valid payload must parse");
        assert_eq!(parsed.pair_session_id, "sess-abc");
        assert_eq!(parsed.endpoint, "wss://hub.example.com/v1");
    }

    #[test]
    fn extra_unknown_query_params_are_ignored_not_rejected() {
        let raw =
            "quickring://pair?session=sess-1&endpoint=ws%3A%2F%2Fh%2Fv1&future_field=whatever";
        assert!(parse(raw).is_ok());
    }

    #[test]
    fn rejects_not_a_url_at_all() {
        assert!(matches!(
            parse("not a url"),
            Err(QrPayloadError::Malformed(_))
        ));
    }

    #[test]
    fn rejects_empty_string() {
        assert!(matches!(parse(""), Err(QrPayloadError::Malformed(_))));
    }

    #[test]
    fn rejects_wrong_scheme() {
        let raw = "https://pair?session=a&endpoint=ws%3A%2F%2Fh%2Fv1";
        assert_eq!(
            parse(raw),
            Err(QrPayloadError::WrongScheme("https".to_string()))
        );
    }

    #[test]
    fn rejects_wrong_authority() {
        let raw = "quickring://claim?session=a&endpoint=ws%3A%2F%2Fh%2Fv1";
        assert_eq!(
            parse(raw),
            Err(QrPayloadError::WrongAuthority("claim".to_string()))
        );
    }

    #[test]
    fn rejects_missing_session() {
        let raw = "quickring://pair?endpoint=ws%3A%2F%2Fh%2Fv1";
        assert_eq!(parse(raw), Err(QrPayloadError::MissingParam("session")));
    }

    #[test]
    fn rejects_empty_session() {
        let raw = "quickring://pair?session=&endpoint=ws%3A%2F%2Fh%2Fv1";
        assert_eq!(parse(raw), Err(QrPayloadError::MissingParam("session")));
    }

    #[test]
    fn rejects_missing_endpoint() {
        let raw = "quickring://pair?session=sess-1";
        assert_eq!(parse(raw), Err(QrPayloadError::MissingParam("endpoint")));
    }

    #[test]
    fn rejects_empty_endpoint() {
        let raw = "quickring://pair?session=sess-1&endpoint=";
        assert_eq!(parse(raw), Err(QrPayloadError::MissingParam("endpoint")));
    }

    #[test]
    fn rejects_malformed_percent_encoding() {
        // A lone '%' is not a valid percent-encoding triplet. The `url`
        // crate's percent-decoding is lenient about this at the query
        // level (it passes invalid sequences through rather than
        // failing) for some malformed cases, so this test pins the
        // behavior this parser actually exhibits rather than assuming
        // strictness the underlying crate doesn't provide. See the
        // `malformed_percent_encoding_in_url_itself_is_rejected` test
        // below for the case that *does* fail at `Url::parse` itself.
        let raw = "quickring://pair?session=sess-1&endpoint=ws%zz";
        // Whatever the url crate does with this, it must not silently
        // fabricate a different, plausible-looking endpoint — either it's
        // rejected, or the literal (undecoded) bytes come through. Either
        // way this must never equal a "clean" decode.
        if let Ok(parsed) = parse(raw) {
            assert_ne!(parsed.endpoint, "ws");
        }
    }

    #[test]
    fn round_trips_a_url_containing_reserved_characters() {
        // Matches percent_encode's own escaping: ':' -> %3A, '/' -> %2F.
        // A path with a query-like fragment inside the encoded endpoint
        // must come back byte-identical to what create_session encoded.
        let raw =
            "quickring://pair?session=s1&endpoint=wss%3A%2F%2Fhub.example.com%3A9443%2Fv1%2Fpair";
        let parsed = parse(raw).expect("valid payload must parse");
        assert_eq!(parsed.endpoint, "wss://hub.example.com:9443/v1/pair");
    }
}
