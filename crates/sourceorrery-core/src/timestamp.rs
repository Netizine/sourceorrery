//! RFC 3339 timestamp helpers shared by the CLI, storage and bindings.

use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::error::{Result, SecretError};

/// Current time in UTC.
pub fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

/// Format a timestamp as RFC 3339 in UTC with second precision
/// (`2026-10-20T12:34:56Z`).
pub fn format(ts: OffsetDateTime) -> String {
    let utc = ts.to_offset(time::UtcOffset::UTC);
    utc.replace_nanosecond(0)
        .unwrap_or(utc)
        .format(&Rfc3339)
        .unwrap_or_else(|_| utc.unix_timestamp().to_string())
}

/// Parse an RFC 3339 timestamp (`2026-12-31T00:00:00Z`; offsets allowed).
pub fn parse(input: &str) -> Result<OffsetDateTime> {
    OffsetDateTime::parse(input.trim(), &Rfc3339).map_err(|err| {
        SecretError::InvalidArgument(format!(
            "'{input}' is not an RFC 3339 timestamp (expected e.g. 2026-12-31T00:00:00Z): {err}"
        ))
    })
}

/// Unix time in nanoseconds, the storage representation used by backends.
pub fn to_unix_nanos(ts: OffsetDateTime) -> i128 {
    ts.unix_timestamp_nanos()
}

/// Inverse of [`to_unix_nanos`].
pub fn from_unix_nanos(nanos: i128) -> Result<OffsetDateTime> {
    OffsetDateTime::from_unix_timestamp_nanos(nanos)
        .map_err(|err| SecretError::Storage(format!("corrupt timestamp {nanos}: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips() {
        let ts = parse("2026-12-31T00:00:00Z").unwrap();
        assert_eq!(format(ts), "2026-12-31T00:00:00Z");
        let back = from_unix_nanos(to_unix_nanos(ts)).unwrap();
        assert_eq!(back, ts);
    }

    #[test]
    fn normalises_offsets_to_utc() {
        let ts = parse("2026-12-31T02:00:00+02:00").unwrap();
        assert_eq!(format(ts), "2026-12-31T00:00:00Z");
    }

    #[test]
    fn rejects_garbage() {
        assert!(parse("tomorrow").is_err());
        assert!(parse("2026-12-31").is_err());
    }
}
