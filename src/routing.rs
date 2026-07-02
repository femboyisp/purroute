//! Username-token routing.
//!
//! A proxy username can carry a routing selection, e.g.
//! `me-country-us,de-isp-comcast-session-ab12`. This module parses that into a
//! base username (used for auth) plus a [`Selection`], and matches/picks tagged
//! upstreams.

use std::collections::BTreeMap;

use crate::config::Tags;

/// Recognised routing keys. The base username ends at the first one of these
/// that is followed by a value.
const KEYS: &[&str] = &[
    "country", "state", "city", "isp", "type", "session", "chain",
];

/// A parsed routing selection. Each dimension is a set; empty = unconstrained.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub country: Vec<String>,
    pub state: Vec<String>,
    pub city: Vec<String>,
    pub isp: Vec<String>,
    /// The `type` dimension (`residential` | `mobile` | `datacenter`).
    pub kind: Vec<String>,
    /// Sticky-session id: pins one exit deterministically when present.
    pub session: Option<String>,
    /// Explicit upstream/chain by name: selects a `[[proxy]]` label or a
    /// `[[chain]]` id directly, taking precedence over the tag dimensions.
    pub chain: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("unknown routing key '{0}' in username")]
    UnknownKey(String),
}

impl Selection {
    /// True when no dimension is constrained.
    pub fn is_empty(&self) -> bool {
        self.country.is_empty()
            && self.state.is_empty()
            && self.city.is_empty()
            && self.isp.is_empty()
            && self.kind.is_empty()
            && self.session.is_none()
            && self.chain.is_none()
    }

    /// True when the selection constrains *only* the session (no geo/isp/type) —
    /// i.e. it pins stickiness but doesn't narrow the candidate set.
    pub fn only_session(&self) -> bool {
        self.country.is_empty()
            && self.state.is_empty()
            && self.city.is_empty()
            && self.isp.is_empty()
            && self.kind.is_empty()
    }

    /// Does an upstream's `tags` satisfy every constrained dimension?
    pub fn matches(&self, tags: &Tags) -> bool {
        dim_ok(&self.country, &tags.country)
            && dim_ok(&self.state, &tags.state)
            && dim_ok(&self.city, &tags.city)
            && dim_ok(&self.isp, &tags.isp)
            && dim_ok(&self.kind, &tags.kind)
    }
}

fn dim_ok(wanted: &[String], tag: &Option<String>) -> bool {
    if wanted.is_empty() {
        return true; // dimension unconstrained
    }
    match tag {
        Some(v) => wanted.iter().any(|w| w.eq_ignore_ascii_case(v)),
        None => false, // selection constrains this dimension but the upstream is untagged
    }
}

/// Parse a proxy username into `(base_username, selection)`.
///
/// The base is everything up to the first recognised key that has a value;
/// remaining `key-value` pairs populate the selection. Comma-separated values
/// form a set. An unrecognised key in the token region is an error.
pub fn parse_username(username: &str) -> Result<(String, Selection), RoutingError> {
    let parts: Vec<&str> = username.split('-').collect();

    // First known key (with a following token) ends the base username.
    let mut key_start = parts.len();
    for (i, part) in parts.iter().enumerate() {
        if KEYS.contains(part) && i + 1 < parts.len() {
            key_start = i;
            break;
        }
    }

    let base = parts[..key_start].join("-");
    let mut sel = Selection::default();
    let mut i = key_start;
    while i < parts.len() {
        let key = parts[i];
        if !KEYS.contains(&key) {
            return Err(RoutingError::UnknownKey(key.to_owned()));
        }
        // `chain` is terminal and greedy: the remainder is the name. Chain ids
        // and proxy labels often contain dashes (e.g. `local-exit`), so it can't
        // be a single `-`-split token like the other dimensions.
        if key == "chain" {
            let value = parts[i + 1..].join("-");
            sel.chain = (!value.is_empty()).then_some(value);
            break;
        }
        let value = parts.get(i + 1).copied().unwrap_or("");
        let set: Vec<String> = value
            .split(',')
            .filter(|s| !s.is_empty())
            .map(str::to_owned)
            .collect();
        match key {
            "country" => sel.country = set,
            "state" => sel.state = set,
            "city" => sel.city = set,
            "isp" => sel.isp = set,
            "type" => sel.kind = set,
            "session" => sel.session = (!value.is_empty()).then(|| value.to_owned()),
            _ => unreachable!("checked against KEYS above; chain handled separately"),
        }
        i += 2;
    }
    Ok((base, sel))
}

/// Build an upstream username from `base` by appending each selected dimension
/// with its configured prefix, in a fixed order. Multi-value dimensions pick one
/// value (sticky by session, else random) via [`pick_index`]. A dimension with
/// no configured prefix, or no selected value, is skipped. An empty selection
/// yields `base` unchanged.
#[allow(dead_code, clippy::allow_attributes)]
pub fn build_username(base: &str, prefixes: &BTreeMap<String, String>, sel: &Selection) -> String {
    let session = sel.session.as_deref();
    let mut out = base.to_owned();

    let dims = [
        ("country", &sel.country),
        ("state", &sel.state),
        ("city", &sel.city),
        ("isp", &sel.isp),
    ];

    for (dim, vals) in dims {
        if let Some(i) = pick_index(vals.len(), session) {
            if let Some(prefix) = prefixes.get(dim) {
                out.push_str(prefix);
                out.push_str(&vals[i]);
            }
        }
    }

    if let Some(s) = session {
        if let Some(prefix) = prefixes.get("session") {
            out.push_str(prefix);
            out.push_str(s);
        }
    }

    out
}

/// Pick one index into `len` candidates: deterministic by `session` (sticky),
/// otherwise random (rotate). Returns `None` when `len == 0`.
pub fn pick_index(len: usize, session: Option<&str>) -> Option<usize> {
    if len == 0 {
        return None;
    }
    match session {
        Some(s) => Some((fnv1a(s) as usize) % len),
        None => {
            use rand::Rng as _;
            Some(rand::rng().random_range(0..len))
        }
    }
}

/// Small stable hash (FNV-1a, 64-bit) so the same session id pins the same exit.
fn fnv1a(s: &str) -> u64 {
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for b in s.as_bytes() {
        hash ^= u64::from(*b);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(country: &str, isp: &str, kind: &str) -> Tags {
        Tags {
            country: Some(country.into()),
            state: None,
            city: None,
            isp: Some(isp.into()),
            kind: Some(kind.into()),
        }
    }

    #[test]
    fn plain_username_has_no_selection() {
        let (base, sel) = parse_username("me").unwrap();
        assert_eq!(base, "me");
        assert!(sel.is_empty());
    }

    #[test]
    fn base_may_contain_dashes() {
        let (base, sel) = parse_username("my-cool-name-country-us").unwrap();
        assert_eq!(base, "my-cool-name");
        assert_eq!(sel.country, vec!["us"]);
    }

    #[test]
    fn parses_all_dimensions_and_sets() {
        let (base, sel) =
            parse_username("u-country-us,de-city-nyc-isp-comcast-type-residential-session-ab12")
                .unwrap();
        assert_eq!(base, "u");
        assert_eq!(sel.country, vec!["us", "de"]);
        assert_eq!(sel.city, vec!["nyc"]);
        assert_eq!(sel.isp, vec!["comcast"]);
        assert_eq!(sel.kind, vec!["residential"]);
        assert_eq!(sel.session.as_deref(), Some("ab12"));
    }

    #[test]
    fn parses_chain_selection_terminal_and_greedy() {
        // The chain name is the greedy remainder, so dashed ids work.
        let (base, sel) = parse_username("u-chain-eu-circuit").unwrap();
        assert_eq!(base, "u");
        assert_eq!(sel.chain.as_deref(), Some("eu-circuit"));
        assert!(!sel.is_empty());
        // A chain selection isn't a tag dimension, so only_session stays true
        // (the resolver intercepts `chain` before the tag-filter path).
        assert!(sel.only_session());
    }

    #[test]
    fn chain_after_tags_consumes_remainder() {
        let (base, sel) = parse_username("u-country-us-chain-local-exit").unwrap();
        assert_eq!(base, "u");
        assert_eq!(sel.country, vec!["us"]);
        assert_eq!(sel.chain.as_deref(), Some("local-exit"));
    }

    #[test]
    fn unknown_key_in_token_region_is_an_error() {
        // Once a known key starts the tokens, an unknown key is rejected.
        assert_eq!(
            parse_username("u-country-us-region-eu"),
            Err(RoutingError::UnknownKey("region".into()))
        );
    }

    #[test]
    fn unknown_word_before_any_key_is_just_part_of_the_base() {
        // No known key appears, so the whole thing is the base username.
        let (base, sel) = parse_username("u-region-us").unwrap();
        assert_eq!(base, "u-region-us");
        assert!(sel.is_empty());
    }

    #[test]
    fn matching_respects_constrained_dimensions() {
        let (_b, sel) = parse_username("u-country-us-isp-comcast").unwrap();
        assert!(sel.matches(&tags("us", "comcast", "residential")));
        assert!(!sel.matches(&tags("de", "comcast", "residential"))); // wrong country
        assert!(!sel.matches(&tags("us", "verizon", "residential"))); // wrong isp
    }

    #[test]
    fn constrained_dimension_rejects_untagged_upstream() {
        let (_b, sel) = parse_username("u-country-us").unwrap();
        let untagged = Tags::default();
        assert!(!sel.matches(&untagged));
    }

    #[test]
    fn case_insensitive_match() {
        let (_b, sel) = parse_username("u-country-US").unwrap();
        assert!(sel.matches(&tags("us", "x", "y")));
    }

    #[test]
    fn sticky_session_is_deterministic_random_varies() {
        // Same session id => same index every time.
        let a = pick_index(5, Some("sess"));
        let b = pick_index(5, Some("sess"));
        assert_eq!(a, b);
        assert!(a.unwrap() < 5);
        // No session => valid index in range.
        assert!(pick_index(3, None).unwrap() < 3);
        assert_eq!(pick_index(0, None), None);
    }

    #[test]
    fn parses_state_dimension() {
        let (base, sel) = parse_username("u-country-us-state-california-city-losangeles").unwrap();
        assert_eq!(base, "u");
        assert_eq!(sel.country, vec!["us"]);
        assert_eq!(sel.state, vec!["california"]);
        assert_eq!(sel.city, vec!["losangeles"]);
        assert!(!sel.is_empty());
        assert!(!sel.only_session());
    }

    #[test]
    fn build_username_appends_selected_dimensions() {
        use std::collections::BTreeMap;
        let prefixes: BTreeMap<String, String> = [
            ("country", "-country-"),
            ("state", "-state-"),
            ("city", "-city-"),
            ("isp", "-isp-"),
            ("session", "-session-"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        // A full single-value selection composes in country/state/city/isp/session order.
        let (_b, sel) =
            parse_username("BASE-country-us-state-california-city-la-isp-comcast-session-s1")
                .unwrap();
        assert_eq!(
            build_username("BASE", &prefixes, &sel),
            "BASE-country-us-state-california-city-la-isp-comcast-session-s1"
        );

        // Empty selection => base only (no tokens appended).
        assert_eq!(
            build_username("BASE", &prefixes, &Selection::default()),
            "BASE"
        );

        // A dimension with no configured prefix is skipped even if selected.
        let only_country: BTreeMap<String, String> = [("country", "-country-")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (_b, sel2) = parse_username("BASE-country-de-city-berlin").unwrap();
        assert_eq!(
            build_username("BASE", &only_country, &sel2),
            "BASE-country-de"
        );
    }

    #[test]
    fn build_username_picks_one_value_for_multi_value_dims() {
        use std::collections::BTreeMap;
        let prefixes: BTreeMap<String, String> = [("country", "-country-")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        // Sticky session makes the pick deterministic.
        let (_b, sel) = parse_username("BASE-country-us,de,fr-session-abc").unwrap();
        let u = build_username("BASE", &prefixes, &sel);
        // Exactly one of the three countries is chosen, deterministically.
        assert_eq!(u, build_username("BASE", &prefixes, &sel));
        assert!(["BASE-country-us", "BASE-country-de", "BASE-country-fr"].contains(&u.as_str()));
    }
}
