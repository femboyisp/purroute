//! Username-token routing.
//!
//! A proxy username can carry a routing selection, e.g.
//! `me-country-us,de-isp-comcast-session-ab12`. This module parses that into a
//! base username (used for auth) plus a [`Selection`], and matches/picks tagged
//! upstreams.

use std::collections::BTreeMap;

use crate::config::{ProxyConfig, RouterSelectionConfig, Tags};

/// Recognised routing keys. The base username ends at the first one of these
/// that is followed by a value.
const KEYS: &[&str] = &[
    "country", "state", "city", "isp", "type", "session", "lifetime", "strict", "chain",
];

/// A parsed routing selection. Each dimension is a set; empty = unconstrained.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Selection {
    pub country: Vec<String>,
    pub state: Vec<String>,
    pub city: Vec<String>,
    pub postal: Vec<String>,
    pub isp: Vec<String>,
    /// The `type` dimension (`residential` | `mobile` | `datacenter`).
    pub kind: Vec<String>,
    pub asn: Option<u32>,
    /// Sticky-session id: pins one exit deterministically when present.
    pub session: Option<String>,
    /// Sticky session lifetime in minutes (provider-specific passthrough).
    pub lifetime: Option<String>,
    /// Strict geo matching: `on` or `off` (provider-specific passthrough).
    pub strict: Option<String>,
    /// Explicit upstream/chain by name: selects a `[[proxy]]` label or a
    /// `[[chain]]` id directly, taking precedence over the tag dimensions.
    pub chain: Option<String>,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum RoutingError {
    #[error("unknown routing key '{0}' in username")]
    UnknownKey(String),
    #[error("invalid routing selection: {0}")]
    InvalidSelection(String),
}

impl Selection {
    /// True when no dimension is constrained.
    pub fn is_empty(&self) -> bool {
        self.country.is_empty()
            && self.state.is_empty()
            && self.city.is_empty()
            && self.postal.is_empty()
            && self.isp.is_empty()
            && self.kind.is_empty()
            && self.asn.is_none()
            && self.session.is_none()
            && self.lifetime.is_none()
            && self.strict.is_none()
            && self.chain.is_none()
    }

    /// True when the selection constrains *only* the session (no geo/isp/type) -
    /// i.e. it pins stickiness but doesn't narrow the candidate set.
    pub fn only_session(&self) -> bool {
        self.country.is_empty()
            && self.state.is_empty()
            && self.city.is_empty()
            && self.postal.is_empty()
            && self.isp.is_empty()
            && self.kind.is_empty()
            && self.asn.is_none()
    }

    /// Does an upstream's `tags` satisfy every constrained dimension?
    ///
    /// Superseded by [`matches_upstream`](Self::matches_upstream) as the
    /// production call site (which additionally accounts for templated
    /// dimensions); kept for its more direct semantics and exercised by
    /// tests here and via `matches_upstream(.., None)` equivalence checks.
    #[allow(dead_code, clippy::allow_attributes)]
    pub fn matches(&self, tags: &Tags) -> bool {
        dim_ok(&self.country, &tags.country)
            && dim_ok(&self.state, &tags.state)
            && dim_ok(&self.city, &tags.city)
            && dim_ok(&self.postal, &tags.postal)
            && dim_ok(&self.isp, &tags.isp)
            && dim_ok(&self.kind, &tags.kind)
            && asn_ok(self.asn, tags.asn)
    }

    /// Like [`matches`](Self::matches) but an upstream that *templates* a
    /// dimension (has a `username_prefixes` or `password_prefixes` entry for it)
    /// serves any value for that dimension, so the tag check is skipped for it.
    #[allow(dead_code, clippy::allow_attributes)]
    pub fn matches_upstream(
        &self,
        tags: &Tags,
        prefixes: Option<&BTreeMap<String, String>>,
    ) -> bool {
        self.matches_upstream_all(tags, prefixes, None)
    }

    /// Check whether an upstream satisfies the selection, treating dimensions
    /// configured in either `username_prefixes` or `password_prefixes` as templated.
    pub fn matches_upstream_all(
        &self,
        tags: &Tags,
        username_prefixes: Option<&BTreeMap<String, String>>,
        password_prefixes: Option<&BTreeMap<String, String>>,
    ) -> bool {
        let templated = |dim: &str| {
            username_prefixes.is_some_and(|p| p.contains_key(dim))
                || password_prefixes.is_some_and(|p| p.contains_key(dim))
        };
        (templated("country") || dim_ok(&self.country, &tags.country))
            && (templated("state") || dim_ok(&self.state, &tags.state))
            && (templated("city") || dim_ok(&self.city, &tags.city))
            && (templated("postal") || dim_ok(&self.postal, &tags.postal))
            && (templated("isp") || dim_ok(&self.isp, &tags.isp))
            && dim_ok(&self.kind, &tags.kind)
            && asn_ok(self.asn, tags.asn)
    }
}

fn asn_ok(wanted: Option<u32>, tag: Option<u32>) -> bool {
    match wanted {
        None => true,
        Some(w) => tag == Some(w),
    }
}

fn dim_ok(wanted: &[String], tag: &Option<String>) -> bool {
    if wanted.is_empty() {
        return true;
    }
    if wanted.iter().any(|w| w.eq_ignore_ascii_case("XX")) {
        return true;
    }
    match tag {
        Some(v) => wanted.iter().any(|w| w.eq_ignore_ascii_case(v)),
        None => false,
    }
}

fn legacy_kind_to_scope_modifier(k: &str) -> Option<String> {
    Some(match k {
        "residential" | "res" => "res".into(),
        "mobile" | "mob" => "mob".into(),
        "datacenter" | "dc" => "dc".into(),
        other => other.to_owned(),
    })
}

/// Map a parsed legacy-keyed selection to the pawprint scope string (geo/type/isp only).
fn selection_to_auth_scope(sel: &Selection) -> String {
    if sel.chain.is_some() {
        return catmac::SCOPE_ANY.to_owned();
    }
    if sel.country.len() > 1
        || sel.state.len() > 1
        || sel.city.len() > 1
        || sel.isp.len() > 1
        || sel.kind.len() > 1
    {
        return catmac::SCOPE_ANY.to_owned();
    }

    let mut territory = catmac::Territory::default();
    if let Some(c) = sel.country.first() {
        territory.country = vec![c.to_ascii_uppercase()];
    }
    if let Some(s) = sel.state.first() {
        territory.state = vec![s.to_ascii_uppercase()];
    }
    if let Some(c) = sel.city.first() {
        territory.city = vec![c.to_ascii_uppercase()];
    }
    territory.asn = sel.asn;

    let territory = if territory.country.is_empty()
        && territory.state.is_empty()
        && territory.city.is_empty()
        && territory.asn.is_none()
    {
        None
    } else {
        Some(territory)
    };

    let mut mods = catmac::Modifiers::default();
    if let Some(k) = sel.kind.first() {
        mods.kind = legacy_kind_to_scope_modifier(k);
    }
    if let Some(isp) = sel.isp.first() {
        mods.isp = Some(isp.to_ascii_lowercase());
    }

    catmac::canonical_scope(territory.as_ref(), &mods)
}

/// Canonical credential scope for a raw proxy username (SCRFC 2 §6).
pub fn auth_scope(raw: &str) -> String {
    if raw.contains('_') {
        if let Ok((_base, territory, mods)) = catmac::parse_proxy_username(raw) {
            let auth_mods = catmac::Modifiers {
                kind: mods.kind.clone(),
                isp: mods.isp.clone(),
                ..Default::default()
            };
            return catmac::canonical_scope(territory.as_ref(), &auth_mods);
        }
    }
    match parse_username_legacy(raw) {
        Ok((_base, sel)) => selection_to_auth_scope(&sel),
        Err(_) => catmac::SCOPE_ANY.to_owned(),
    }
}

/// Parse a proxy username into `(base_username, selection)`.
///
/// Usernames containing `_` use SCRFC 1 territory grammar; on parse failure the
/// connection is rejected. Usernames without `_` use the legacy keyed grammar.
pub fn parse_username(username: &str) -> Result<(String, Selection), RoutingError> {
    if username.contains('_') {
        return parse_username_territory(username);
    }
    parse_username_legacy(username)
}

fn parse_username_territory(username: &str) -> Result<(String, Selection), RoutingError> {
    let (base, territory, mods) = catmac::parse_proxy_username(username).map_err(|e| {
        RoutingError::InvalidSelection(match e {
            catmac::TerritoryError::LegacyUsername => "legacy username".into(),
            other => other.to_string(),
        })
    })?;
    Ok((
        base,
        routing_selection_to_sel(catmac::territory_to_selection(territory.as_ref(), &mods)),
    ))
}

fn routing_selection_to_sel(r: catmac::territory::RoutingSelection) -> Selection {
    Selection {
        country: r.country,
        state: r.state,
        city: r.city,
        postal: r.postal,
        isp: r.isp,
        kind: r.kind,
        asn: r.asn,
        session: r.session,
        lifetime: r.lifetime,
        strict: r.strict,
        chain: r.chain,
    }
}

/// Parse a stored default selection (territory tag or legacy keyed tokens).
pub fn parse_default_selection(s: &str) -> Result<Selection, RoutingError> {
    let s = s.trim();
    if s.is_empty() {
        return Ok(Selection::default());
    }
    if let Ok(sel) = catmac::parse_default_selection(s).map(routing_selection_to_sel) {
        if !sel.is_empty() {
            return Ok(sel);
        }
    }
    // Back-compat: stored defaults may still embed a legacy base prefix (`me-country-us`).
    parse_username_legacy(s).map(|(_base, sel)| sel)
}

fn parse_username_legacy(username: &str) -> Result<(String, Selection), RoutingError> {
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
            "lifetime" => sel.lifetime = (!value.is_empty()).then(|| value.to_owned()),
            "strict" => sel.strict = (!value.is_empty()).then(|| value.to_owned()),
            _ => unreachable!("checked against KEYS above; chain handled separately"),
        }
        i += 2;
    }
    validate_selection(&sel)?;
    Ok((base, sel))
}

fn validate_selection(sel: &Selection) -> Result<(), RoutingError> {
    if !sel.state.is_empty() && !sel.city.is_empty() {
        return Err(RoutingError::InvalidSelection(
            "state and city cannot be combined".into(),
        ));
    }
    if !sel.isp.is_empty() && sel.country.is_empty() {
        return Err(RoutingError::InvalidSelection(
            "isp requires country".into(),
        ));
    }
    Ok(())
}

/// Clamp a session id to provider-safe `[A-Za-z0-9_]{1,25}`.
fn clamp_session_id(s: &str) -> String {
    const MAX: usize = 25;
    if !s.is_empty() && s.len() <= MAX && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    {
        return s.to_owned();
    }
    let mut out = format!("s{:016x}", fnv1a(s));
    out.truncate(MAX);
    out
}

/// Build an upstream username from `base` by appending each selected dimension
/// with its configured prefix, in a fixed order. Multi-value dimensions pick one
/// value (sticky by session, else random) via [`pick_index`]. A dimension with
/// no configured prefix, or no selected value, is skipped. An empty selection
/// yields `base` unchanged.
pub fn build_username(base: &str, prefixes: &BTreeMap<String, String>, sel: &Selection) -> String {
    let session = sel.session.as_deref();
    let mut out = base.to_owned();

    let dims = [
        ("country", &sel.country),
        ("state", &sel.state),
        ("city", &sel.city),
        ("postal", &sel.postal),
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

    if let Some(i) = pick_index(sel.kind.len(), session) {
        if let Some(prefix) = prefixes.get("type") {
            out.push_str(prefix);
            out.push_str(&sel.kind[i]);
        }
    }

    if let Some(s) = session {
        if let Some(prefix) = prefixes.get("session") {
            out.push_str(prefix);
            out.push_str(&clamp_session_id(s));
        }
    }

    if let Some(v) = sel.lifetime.as_deref() {
        if let Some(prefix) = prefixes.get("lifetime") {
            out.push_str(prefix);
            out.push_str(v);
        }
    }

    if let Some(v) = sel.strict.as_deref() {
        if let Some(prefix) = prefixes.get("strict") {
            out.push_str(prefix);
            out.push_str(v);
        }
    }

    out
}

/// Format an upstream password string by injecting routing selection dimensions.
pub fn build_password(
    base: &str,
    prefixes: &BTreeMap<String, String>,
    delimiter: Option<&str>,
    selection: &Selection,
) -> String {
    let delim = delimiter.unwrap_or("_");
    let mut tokens = Vec::new();

    if let (Some(prefix), Some(c)) = (prefixes.get("country"), selection.country.first()) {
        tokens.push(format!("{}{}", prefix.trim_start_matches('-'), c.to_ascii_uppercase()));
    }
    if let (Some(prefix), Some(s)) = (prefixes.get("state"), selection.state.first()) {
        tokens.push(format!("{}{}", prefix.trim_start_matches('-'), s.to_ascii_uppercase()));
    }
    if let (Some(prefix), Some(c)) = (prefixes.get("city"), selection.city.first()) {
        tokens.push(format!("{}{}", prefix.trim_start_matches('-'), c));
    }
    if let (Some(prefix), Some(i)) = (prefixes.get("isp"), selection.isp.first()) {
        tokens.push(format!("{}{}", prefix.trim_start_matches('-'), i));
    }
    if let (Some(prefix), Some(s)) = (prefixes.get("session"), &selection.session) {
        tokens.push(format!("{}{}", prefix.trim_start_matches('-'), s));
    }

    if tokens.is_empty() {
        base.to_owned()
    } else {
        format!("{}{}{}", base, delim, tokens.join(delim))
    }
}

/// Pick one port from an inclusive range: sticky by `session`, else random.
#[expect(dead_code)]
pub fn pick_port(range: (u16, u16), session: Option<&str>) -> u16 {
    let len = u32::from(range.1.saturating_sub(range.0)) + 1;
    let idx = pick_index(len as usize, session).unwrap_or(0);
    range.0.saturating_add(idx as u16)
}

/// Pick one port from an inclusive range with health awareness and exclusion filtering.
/// In rotating mode, picks randomly from candidate healthy ports.
/// In sticky mode, selects the primary hashed port if healthy, or deterministically
/// maps across candidate healthy ports to maintain consistency during outages.
pub fn pick_port_healthy(
    host: &str,
    range: (u16, u16),
    session: Option<&str>,
    tracker: &crate::health::UpstreamHealthTracker,
    excluded_ports: &[u16],
) -> u16 {
    let healthy_ports = tracker.get_healthy_ports(host, range);
    let mut candidates: Vec<u16> = healthy_ports
        .into_iter()
        .filter(|p| !excluded_ports.contains(p))
        .collect();

    if candidates.is_empty() {
        // Fallback: ignore excluded_ports if all healthy ports were excluded
        candidates = tracker.get_healthy_ports(host, range);
    }

    match session {
        None => {
            use rand::seq::IndexedRandom as _;
            let mut rng = rand::rng();
            *candidates.choose(&mut rng).unwrap_or(&range.0)
        }
        Some(s) => {
            let total_range_len = usize::from(range.1.saturating_sub(range.0)) + 1;
            let primary_offset = (fnv1a(s) as usize) % total_range_len;
            let primary_port = range.0.saturating_add(primary_offset as u16);

            if candidates.contains(&primary_port) {
                primary_port
            } else {
                // Primary is dead or excluded: deterministically pick from healthy candidates
                let idx = (fnv1a(s) as usize) % candidates.len();
                candidates[idx]
            }
        }
    }
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
            use rand::RngExt as _;
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

/// Pick one upstream candidate index according to the configured selection strategy.
pub fn pick_candidate_index(
    candidates: &[ProxyConfig],
    selection: &Selection,
    strategy: &RouterSelectionConfig,
) -> Option<usize> {
    if candidates.is_empty() {
        return None;
    }

    match strategy.mode.as_str() {
        "pinned" => {
            if let Some(target) = &strategy.pinned_label {
                candidates.iter().position(|p| p.label.as_deref() == Some(target))
            } else {
                Some(0)
            }
        }
        "priority" => {
            candidates
                .iter()
                .enumerate()
                .min_by_key(|(_, p)| p.priority.unwrap_or(u32::MAX))
                .map(|(idx, _)| idx)
        }
        _ => {
            // Weighted selection (default)
            if let Some(sess) = &selection.session {
                // Deterministic sticky selection using session hash
                pick_index(candidates.len(), Some(sess))
            } else {
                let total_weight: u32 = candidates.iter().map(|p| p.weight.unwrap_or(1).max(1)).sum();
                let mut rng_val = rand::random::<u32>() % total_weight;
                for (i, p) in candidates.iter().enumerate() {
                    let w = p.weight.unwrap_or(1).max(1);
                    if rng_val < w {
                        return Some(i);
                    }
                    rng_val -= w;
                }
                Some(0)
            }
        }
    }
}

#[allow(clippy::allow_attributes, unused_imports, dead_code)]
pub use pick_candidate_index as pick_upstream_candidate;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{ProxyConfig, RouterSelectionConfig};

    #[test]
    fn test_pick_upstream_priority_mode() {
        let mut p1 = ProxyConfig::default_for_test();
        p1.priority = Some(20);
        p1.label = Some("low-priority".into());

        let mut p2 = ProxyConfig::default_for_test();
        p2.priority = Some(5);
        p2.label = Some("high-priority".into());

        let candidates = vec![p1, p2];
        let sel = Selection::default();
        let strategy = RouterSelectionConfig {
            mode: "priority".into(),
            pinned_label: None,
        };

        let idx = pick_candidate_index(&candidates, &sel, &strategy);
        assert_eq!(idx, Some(1)); // p2 has lower priority number (higher rank)
    }

    #[test]
    fn test_pick_upstream_pinned_mode() {
        let mut p1 = ProxyConfig::default_for_test();
        p1.label = Some("gw-a".into());

        let mut p2 = ProxyConfig::default_for_test();
        p2.label = Some("gw-b".into());

        let candidates = vec![p1, p2];
        let sel = Selection::default();
        let strategy = RouterSelectionConfig {
            mode: "pinned".into(),
            pinned_label: Some("gw-b".into()),
        };

        let idx = pick_candidate_index(&candidates, &sel, &strategy);
        assert_eq!(idx, Some(1));
    }

    #[test]
    fn test_pick_upstream_pinned_missing_label() {
        let p1 = ProxyConfig::default_for_test();
        let candidates = vec![p1];
        let sel = Selection::default();
        let strategy = RouterSelectionConfig {
            mode: "pinned".into(),
            pinned_label: Some("non-existent".into()),
        };
        assert_eq!(pick_candidate_index(&candidates, &sel, &strategy), None);

        let strategy_none = RouterSelectionConfig {
            mode: "pinned".into(),
            pinned_label: None,
        };
        assert_eq!(pick_candidate_index(&candidates, &sel, &strategy_none), Some(0));
    }

    #[test]
    fn test_pick_upstream_weighted_mode() {
        let mut p1 = ProxyConfig::default_for_test();
        p1.weight = Some(10);
        let mut p2 = ProxyConfig::default_for_test();
        p2.weight = Some(20);

        let candidates = vec![p1, p2];
        let strategy = RouterSelectionConfig::default(); // mode: "weighted"

        // Random pick without session should always return valid index
        let sel_no_sess = Selection::default();
        let idx = pick_candidate_index(&candidates, &sel_no_sess, &strategy);
        assert!(idx == Some(0) || idx == Some(1));

        // Deterministic sticky selection with session
        let mut sel_sess = Selection::default();
        sel_sess.session = Some("sticky-abc".into());
        let idx_a = pick_candidate_index(&candidates, &sel_sess, &strategy);
        let idx_b = pick_candidate_index(&candidates, &sel_sess, &strategy);
        assert_eq!(idx_a, idx_b);
        assert!(idx_a.is_some());
    }

    #[test]
    fn test_pick_upstream_empty_candidates() {
        let candidates: Vec<ProxyConfig> = vec![];
        let sel = Selection::default();
        let strategy = RouterSelectionConfig::default();
        assert_eq!(pick_candidate_index(&candidates, &sel, &strategy), None);
    }

    fn tags(country: &str, isp: &str, kind: &str) -> Tags {
        Tags {
            country: Some(country.into()),
            state: None,
            city: None,
            isp: Some(isp.into()),
            kind: Some(kind.into()),
            postal: None,
            asn: None,
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
    fn rejects_state_and_city_combined() {
        assert_eq!(
            parse_username("u-country-us-state-ca-city-la"),
            Err(RoutingError::InvalidSelection(
                "state and city cannot be combined".into()
            ))
        );
    }

    #[test]
    fn rejects_isp_without_country() {
        assert_eq!(
            parse_username("u-isp-comcast"),
            Err(RoutingError::InvalidSelection(
                "isp requires country".into()
            ))
        );
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
    fn sticky_port_is_deterministic_random_varies() {
        let range = (11000_u16, 11010_u16);
        let a = pick_port(range, Some("sess"));
        let b = pick_port(range, Some("sess"));
        assert_eq!(a, b);
        assert!((11000..=11010).contains(&a));
        let r = pick_port(range, None);
        assert!((11000..=11010).contains(&r));
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
    fn pick_port_healthy_bypasses_dead_and_excluded_ports() {
        use crate::config::UpstreamHealthConfig;
        use crate::health::UpstreamHealthTracker;

        let tracker = UpstreamHealthTracker::new(UpstreamHealthConfig {
            failure_threshold: 1,
            ..Default::default()
        });
        tracker.record_failure("proxy.socks.cat", 11002);

        let range = (11000, 11005);
        // 11002 is dead, 11001 is dynamically excluded
        for _ in 0..20 {
            let p = pick_port_healthy("proxy.socks.cat", range, None, &tracker, &[11001]);
            assert!(p != 11002 && p != 11001);
            assert!((11000..=11005).contains(&p));
        }
    }

    #[test]
    fn pick_port_healthy_sticky_deterministic_fallback() {
        use crate::config::UpstreamHealthConfig;
        use crate::health::UpstreamHealthTracker;

        let tracker = UpstreamHealthTracker::new(UpstreamHealthConfig {
            failure_threshold: 1,
            ..Default::default()
        });

        let range = (11000, 11005);
        let normal = pick_port_healthy("proxy.socks.cat", range, Some("sess-123"), &tracker, &[]);

        // Mark that chosen port dead:
        tracker.record_failure("proxy.socks.cat", normal);

        let fallback_1 = pick_port_healthy("proxy.socks.cat", range, Some("sess-123"), &tracker, &[]);
        let fallback_2 = pick_port_healthy("proxy.socks.cat", range, Some("sess-123"), &tracker, &[]);

        assert_ne!(normal, fallback_1);
        assert_eq!(fallback_1, fallback_2); // Consistent fallback across requests!
    }

    #[test]
    fn parses_state_dimension() {
        let (base, sel) = parse_username("u-country-us-state-california").unwrap();
        assert_eq!(base, "u");
        assert_eq!(sel.country, vec!["us"]);
        assert_eq!(sel.state, vec!["california"]);
        assert!(sel.city.is_empty());
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
            ("isp", "-asn-"),
            ("session", "-session-"),
        ]
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect();

        // A full single-value selection composes in country/state/city/isp/session
        // order, each dimension using its *configured* prefix — note the `isp`
        // dimension is emitted with the `-asn-` prefix, distinct from its key, so
        // this asserts the prefix comes from config and not the dimension name.
        let (_b, sel) =
            parse_username("BASE-country-us-state-california-isp-comcast-session-s1").unwrap();
        assert_eq!(
            build_username("BASE", &prefixes, &sel),
            "BASE-country-us-state-california-asn-comcast-session-s1"
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

    #[test]
    fn test_build_password_with_underscore_delimiter() {
        let mut prefixes = BTreeMap::new();
        prefixes.insert("country".into(), "-country-".into());
        prefixes.insert("session".into(), "-session-".into());

        let mut selection = Selection::default();
        selection.country = vec!["us".into()];
        selection.session = Some("sess123".into());

        let result = build_password("mypassword", &prefixes, Some("_"), &selection);
        assert_eq!(result, "mypassword_country-US_session-sess123");
    }

    #[test]
    fn test_build_password_empty_selection_keeps_base() {
        let mut prefixes = BTreeMap::new();
        prefixes.insert("country".into(), "-country-".into());

        let selection = Selection::default();
        let result = build_password("mypassword", &prefixes, Some("_"), &selection);
        assert_eq!(result, "mypassword");
    }

    #[test]
    fn test_build_password_all_dimensions_and_default_delimiter() {
        let mut prefixes = BTreeMap::new();
        prefixes.insert("country".into(), "-country-".into());
        prefixes.insert("state".into(), "-state-".into());
        prefixes.insert("city".into(), "-city-".into());
        prefixes.insert("isp".into(), "-isp-".into());
        prefixes.insert("session".into(), "session-".into());

        let mut selection = Selection::default();
        selection.country = vec!["us".into()];
        selection.state = vec!["ca".into()];
        selection.city = vec!["losangeles".into()];
        selection.isp = vec!["comcast".into()];
        selection.session = Some("sess999".into());

        // Default delimiter is "_" when None
        let result = build_password("basepass", &prefixes, None, &selection);
        assert_eq!(
            result,
            "basepass_country-US_state-CA_city-losangeles_isp-comcast_session-sess999"
        );
    }

    #[test]
    fn templated_dimension_matches_any_value() {
        use std::collections::BTreeMap;
        // An upstream that templates `country` serves any country, even though its
        // own country tag is unset.
        let gw_prefixes: BTreeMap<String, String> = [("country", "-country-")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let untagged = Tags::default();
        let (_b, sel) = parse_username("u-country-jp").unwrap();
        // Without templating, an untagged upstream would NOT match a country-constrained selection.
        assert!(!sel.matches(&untagged));
        // With the country prefix, it matches any country.
        assert!(sel.matches_upstream(&untagged, Some(&gw_prefixes)));
    }

    #[test]
    fn non_templated_dimension_still_uses_tags() {
        use std::collections::BTreeMap;
        // Templates country but NOT isp; an isp-constrained selection still checks the tag.
        let prefixes: BTreeMap<String, String> = [("country", "-country-")]
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (_b, sel) = parse_username("u-country-us-isp-comcast").unwrap();
        assert!(!sel.matches_upstream(&Tags::default(), Some(&prefixes))); // isp untagged, not templated
    }

    #[test]
    fn matches_upstream_with_no_prefixes_equals_matches() {
        // A static (non-gateway) upstream templates nothing, so `matches_upstream`
        // with `None` must fall through to exactly the same result as `matches` —
        // the back-compat guarantee the static-upstream path in resolution relies on.
        let (_b, sel) = parse_username("u-country-us-isp-comcast").unwrap();
        let hit = tags("us", "comcast", "residential");
        let miss = tags("de", "comcast", "residential");
        assert_eq!(sel.matches_upstream(&hit, None), sel.matches(&hit));
        assert!(sel.matches_upstream(&hit, None));
        assert_eq!(sel.matches_upstream(&miss, None), sel.matches(&miss));
        assert!(!sel.matches_upstream(&miss, None));
    }

    #[test]
    fn auth_scope_plain_collar_is_any() {
        assert_eq!(auth_scope("cat-ABCD"), "*");
    }

    #[test]
    fn auth_scope_legacy_country_state_type() {
        assert_eq!(
            auth_scope("cat-ABCD-country-us-state-ut-type-residential"),
            "US-UT_t-res"
        );
    }

    #[test]
    fn auth_scope_chain_only_is_any() {
        assert_eq!(auth_scope("cat-ABCD-chain-eu-circuit"), "*");
    }

    #[test]
    fn auth_scope_multi_country_is_any() {
        assert_eq!(auth_scope("cat-ABCD-country-us,de"), "*");
    }

    /// Closes the scoped pawprint loop: whisker → paw_key → auth_scope(username) → pawprint → verify.
    #[test]
    fn scoped_pawprint_round_trip_for_legacy_username() {
        use catmac::{mint_whisker, paw_key, paw_key_hex, pawprint, verify_pawprint, AuthKind};

        let username = "cat-TESTCOLLAR1234-country-us-state-ut-type-residential";
        let whisker = mint_whisker();
        let k = paw_key(&whisker, 1);
        let k_hex = paw_key_hex(&whisker, 1);

        let scope = auth_scope(username);
        assert_eq!(scope, "US-UT_t-res");

        let secret = pawprint(&k, &scope);

        assert!(verify_pawprint(
            &secret,
            Some(&k_hex),
            None,
            false,
            AuthKind::Whisker,
            None,
            &auth_scope(username),
        ));
    }
}
