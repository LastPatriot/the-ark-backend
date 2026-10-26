use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use chrono::{DateTime, SecondsFormat, Utc};
use sha2::{Digest, Sha256};

/// All stored timestamps share this exact format so they compare correctly as strings.
pub fn fmt_time(t: DateTime<Utc>) -> String {
    t.to_rfc3339_opts(SecondsFormat::Millis, true)
}

pub fn now() -> String {
    fmt_time(Utc::now())
}

/// Parses a client-supplied RFC 3339 timestamp and normalizes it to the stored format.
pub fn normalize_time(s: &str) -> Option<String> {
    DateTime::parse_from_rfc3339(s)
        .ok()
        .map(|t| fmt_time(t.with_timezone(&Utc)))
}

/// 128-bit random token, base64url without padding (22 chars).
pub fn random_token() -> String {
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

pub fn sha256_hex(data: &[u8]) -> String {
    hex(&Sha256::digest(data))
}

pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn new_id() -> String {
    uuid::Uuid::now_v7().to_string()
}

/// URL-safe slug: lowercase ASCII alphanumerics separated by single dashes.
pub fn slugify(name: &str) -> String {
    let mut out = String::new();
    for c in name.trim().chars().flat_map(char::to_lowercase) {
        if c.is_ascii_alphanumeric() {
            out.push(c);
        } else if !out.is_empty() && !out.ends_with('-') {
            out.push('-');
        }
    }
    while out.ends_with('-') {
        out.pop();
    }
    out.truncate(64);
    out
}

pub fn is_valid_slug(slug: &str) -> bool {
    !slug.is_empty() && slugify(slug) == slug
}

/// For PATCH bodies: distinguishes an absent field (`None`) from an explicit `null`
/// (`Some(None)`). Use with `#[serde(default, deserialize_with = "util::double_option")]`.
pub fn double_option<'de, D, T>(d: D) -> Result<Option<Option<T>>, D::Error>
where
    D: serde::Deserializer<'de>,
    T: serde::Deserialize<'de>,
{
    <Option<T> as serde::Deserialize>::deserialize(d).map(Some)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slugs() {
        assert_eq!(slugify("Sunday Service"), "sunday-service");
        assert_eq!(slugify("  Youth -- Camp 2026! "), "youth-camp-2026");
        assert_eq!(slugify("../.."), "");
        assert!(is_valid_slug("youth-camp"));
        assert!(!is_valid_slug("Youth"));
        assert!(!is_valid_slug("a/b"));
    }

    #[test]
    fn times_compare_as_strings() {
        let a = normalize_time("2026-10-26T10:00:00+01:00").unwrap();
        assert_eq!(a, "2026-10-26T09:00:00.000Z");
        assert!(a < now());
    }
}
