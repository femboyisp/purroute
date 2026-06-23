//! The proxy protocol enum, used for both the detected inbound protocol and a
//! configured upstream's `proxy_type`.

use serde::{Deserialize, Serialize};

/// A proxy protocol.
///
/// Variant names are kept stable because they are deserialised directly from the
/// `proxy_type` field of `[[proxy]]` blocks in `config.toml`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, Serialize)]
pub enum Protocol {
    Http,
    Https,
    Socks4,
    Socks5,
}

impl Protocol {
    /// Lower-case identifier suitable for metrics labels and JSON output.
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Http => "http",
            Protocol::Https => "https",
            Protocol::Socks4 => "socks4",
            Protocol::Socks5 => "socks5",
        }
    }
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod protocol_cov {
    use super::*;

    #[test]
    fn as_str_covers_all_variants() {
        assert_eq!(Protocol::Http.as_str(), "http");
        assert_eq!(Protocol::Https.as_str(), "https");
        assert_eq!(Protocol::Socks4.as_str(), "socks4");
        assert_eq!(Protocol::Socks5.as_str(), "socks5");
    }

    #[test]
    fn display_matches_as_str() {
        for p in [
            Protocol::Http,
            Protocol::Https,
            Protocol::Socks4,
            Protocol::Socks5,
        ] {
            assert_eq!(format!("{p}"), p.as_str());
            assert_eq!(p.to_string(), p.as_str());
        }
    }

    #[test]
    fn debug_uses_variant_name() {
        assert_eq!(format!("{:?}", Protocol::Http), "Http");
        assert_eq!(format!("{:?}", Protocol::Https), "Https");
        assert_eq!(format!("{:?}", Protocol::Socks4), "Socks4");
        assert_eq!(format!("{:?}", Protocol::Socks5), "Socks5");
    }

    #[test]
    fn clone_copy_and_eq() {
        let a = Protocol::Socks5;
        let b = a; // Copy
        let c = a; // Copy again; Clone is identical for a Copy type
        assert_eq!(a, b);
        assert_eq!(a, c);
        assert_ne!(Protocol::Http, Protocol::Https);
        assert_ne!(Protocol::Socks4, Protocol::Socks5);
    }

    // The `proxy_type` field of a `[[proxy]]` block is deserialised from TOML, so
    // we exercise the serde derives through the `toml` crate.
    #[derive(Deserialize, Serialize, Debug, PartialEq, Eq)]
    struct Holder {
        proxy_type: Protocol,
    }

    #[test]
    fn serialize_uses_variant_names() {
        let s = toml::to_string(&Holder {
            proxy_type: Protocol::Socks5,
        })
        .unwrap();
        assert!(s.contains("proxy_type = \"Socks5\""), "got: {s}");
    }

    #[test]
    fn deserialize_round_trips() {
        for (text, expected) in [
            ("Http", Protocol::Http),
            ("Https", Protocol::Https),
            ("Socks4", Protocol::Socks4),
            ("Socks5", Protocol::Socks5),
        ] {
            let toml = format!("proxy_type = \"{text}\"");
            let h: Holder = toml::from_str(&toml).unwrap();
            assert_eq!(h.proxy_type, expected);
        }
    }

    #[test]
    fn deserialize_unknown_variant_errors() {
        // Variant names are case-sensitive; lower-case identifiers are rejected.
        assert!(toml::from_str::<Holder>("proxy_type = \"http\"").is_err());
        assert!(toml::from_str::<Holder>("proxy_type = \"bogus\"").is_err());
        assert!(toml::from_str::<Holder>("proxy_type = 123").is_err());
    }
}
