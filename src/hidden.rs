//! Tor (.onion) and I2P (.i2p / .b32.i2p) host helpers.

/// True when `host` is a Tor v2/v3 onion service name.
pub fn is_onion(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h.ends_with(".onion")
}

/// True when `host` is an I2P destination (`.i2p` or `.b32.i2p`).
pub fn is_i2p(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    h.ends_with(".i2p") || h.ends_with(".b32.i2p")
}

/// Default port when none is specified for hidden-network hosts.
pub fn default_port(host: &str) -> u16 {
    if is_onion(host) || is_i2p(host) {
        80
    } else {
        80
    }
}

/// Split `authority` (`host` or `host:port`) using the last `:` as the port
/// separator. IPv6 bracket form (`[::1]:9050`) is supported.
pub fn split_authority(authority: &str, default_port: u16) -> Result<(String, u16), String> {
    let authority = authority.trim();
    if authority.is_empty() {
        return Err("empty authority".into());
    }
    if let Some(rest) = authority.strip_prefix('[') {
        let (inside, after) = rest
            .split_once(']')
            .ok_or_else(|| "invalid bracketed host".to_string())?;
        if after.is_empty() {
            return Ok((format!("[{inside}]"), default_port));
        }
        if let Some(port) = after.strip_prefix(':') {
            let port = port
                .parse()
                .map_err(|_| format!("invalid port in '{authority}'"))?;
            return Ok((format!("[{inside}]"), port));
        }
        return Err(format!("invalid authority '{authority}'"));
    }
    match authority.rsplit_once(':') {
        Some((host, port)) if !host.is_empty() => {
            let port = port
                .parse()
                .map_err(|_| format!("invalid port in '{authority}'"))?;
            Ok((host.to_string(), port))
        }
        _ => Ok((authority.to_string(), default_port)),
    }
}

/// `host:port` suitable for `TcpStream::connect`, applying default port 80 for
/// `.onion` / `.i2p` hosts when no port is configured.
pub fn socket_addr(host: &str, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{host}:{p}"),
        None if is_onion(host) || is_i2p(host) => format!("{host}:80"),
        None => host.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn onion_and_i2p_detection() {
        assert!(is_onion("abc123def456.onion"));
        assert!(!is_onion("clearnet.example"));
        assert!(is_i2p("foo.b32.i2p"));
        assert!(is_i2p("mysite.i2p"));
        assert!(!is_i2p("example.com"));
    }

    #[test]
    fn split_authority_onion_without_port() {
        let (h, p) = split_authority("abc123.onion", 80).unwrap();
        assert_eq!(h, "abc123.onion");
        assert_eq!(p, 80);
    }

    #[test]
    fn split_authority_with_port() {
        let (h, p) = split_authority("127.0.0.1:9050", 80).unwrap();
        assert_eq!(h, "127.0.0.1");
        assert_eq!(p, 9050);
    }

    #[test]
    fn split_authority_ipv6() {
        let (h, p) = split_authority("[::1]:9050", 80).unwrap();
        assert_eq!(h, "[::1]");
        assert_eq!(p, 9050);
    }

    #[test]
    fn socket_addr_applies_default() {
        assert_eq!(socket_addr("xyz.onion", None), "xyz.onion:80");
        assert_eq!(socket_addr("clearnet.example", None), "clearnet.example");
        assert_eq!(socket_addr("127.0.0.1", Some(9050)), "127.0.0.1:9050");
    }
}
