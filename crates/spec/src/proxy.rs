//! Validated, credential-free addresses of host-side outbound proxies.

use serde::de::{self, Visitor};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::net::SocketAddr;
use std::str::FromStr;
use thiserror::Error;

/// An outbound proxy reached by the host, rather than by the guest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxySpec {
    /// TCP tunnels opened with HTTP CONNECT.
    HttpConnect(SocketAddr),
    /// SOCKS4 TCP proxy, without a user ID.
    Socks4(SocketAddr),
    /// SOCKS5 proxy, without authentication.
    Socks5(SocketAddr),
}

/// Invalid proxy input. Deliberately excludes the input, which might contain credentials.
#[derive(Debug, Clone, Copy, Error)]
#[error(
    "invalid network.proxy: use http://IP:port, socks4://IP:port or socks5://IP:port without credentials, a path or a query; the port must be nonzero"
)]
pub struct InvalidProxy;

impl FromStr for ProxySpec {
    type Err = InvalidProxy;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        let (scheme, address) = value.split_once("://").ok_or(InvalidProxy)?;
        let address: SocketAddr = address.parse().map_err(|_| InvalidProxy)?;
        if address.port() == 0 {
            return Err(InvalidProxy);
        }
        match scheme {
            "http" => Ok(Self::HttpConnect(address)),
            "socks4" if address.is_ipv4() => Ok(Self::Socks4(address)),
            "socks5" => Ok(Self::Socks5(address)),
            _ => Err(InvalidProxy),
        }
    }
}

impl fmt::Display for ProxySpec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::HttpConnect(address) => write!(f, "http://{address}"),
            Self::Socks4(address) => write!(f, "socks4://{address}"),
            Self::Socks5(address) => write!(f, "socks5://{address}"),
        }
    }
}

impl Serialize for ProxySpec {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ProxySpec {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        deserializer.deserialize_str(ProxyVisitor)
    }
}

/// Parses at the scalar's position so YAML diagnostics identify the proxy setting.
struct ProxyVisitor;

impl Visitor<'_> for ProxyVisitor {
    type Value = ProxySpec;

    fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        formatter.write_str("a proxy URL with an IP address and port")
    }

    fn visit_str<E: de::Error>(self, value: &str) -> Result<Self::Value, E> {
        value.parse().map_err(E::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::NetworkSpec;

    #[test]
    fn proxy_urls_round_trip_through_the_network_section() {
        for url in [
            "http://127.0.0.1:3128",
            "http://[::1]:3128",
            "socks4://192.168.1.10:1080",
            "socks5://[::1]:1080",
        ] {
            let spec: NetworkSpec = serde_yaml::from_str(&format!("proxy: {url}\n")).unwrap();
            assert_eq!(spec.proxy.as_ref().unwrap().to_string(), url);
            let restored: NetworkSpec =
                serde_yaml::from_str(&serde_yaml::to_string(&spec).unwrap()).unwrap();
            assert_eq!(restored, spec);
        }
    }

    #[test]
    fn rejects_unsupported_or_ambiguous_proxy_urls_without_echoing_them() {
        for url in [
            "",
            "127.0.0.1:3128",
            "https://127.0.0.1:3128",
            "http://proxy.example:3128",
            "http://127.0.0.1:0",
            "http://127.0.0.1",
            "http://127.0.0.1:3128/",
            "http://user:secret@127.0.0.1:3128",
            "http://127.0.0.1:3128?secret",
            "socks4://[::1]:1080",
            "http://127.0.0.1:70000",
        ] {
            assert!(url.parse::<ProxySpec>().is_err(), "{url}");
        }
        let error = "http://user:secret@127.0.0.1:3128"
            .parse::<ProxySpec>()
            .unwrap_err()
            .to_string();
        assert!(!error.contains("secret"));
    }

    #[test]
    fn missing_proxy_keeps_the_existing_spec_format() {
        let spec: NetworkSpec = serde_yaml::from_str("enforce: true\n").unwrap();
        assert!(spec.proxy.is_none());
        assert!(!serde_yaml::to_string(&spec).unwrap().contains("proxy"));
    }
}
