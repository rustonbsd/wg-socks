use anyhow::{Context, Result};
use std::net::SocketAddr;

/// Parsed WireGuard configuration.
#[derive(Debug, Clone)]
pub struct WgConfig {
    pub private_key: [u8; 32],
    pub address: String,
    pub dns: Option<String>,
    pub peer_public_key: [u8; 32],
    pub peer_endpoint: SocketAddr,
    pub peer_allowed_ips: Vec<String>,
    pub peer_preshared_key: Option<[u8; 32]>,
    pub persistent_keepalive: Option<u16>,
}

impl WgConfig {
    /// Parse a standard wg-quick style config string.
    ///
    /// ```text
    /// [Interface]
    /// PrivateKey = ...
    /// Address = 10.0.0.2/32
    /// DNS = 1.1.1.1
    ///
    /// [Peer]
    /// PublicKey = ...
    /// Endpoint = 1.2.3.4:51820
    /// AllowedIPs = 0.0.0.0/0
    /// PersistentKeepalive = 25
    /// ```
    pub fn from_string(config: &str) -> Result<Self> {
        let mut private_key = None;
        let mut address = None;
        let mut dns = None;
        let mut peer_public_key = None;
        let mut peer_endpoint = None;
        let mut peer_allowed_ips = Vec::new();
        let mut peer_preshared_key = None;
        let mut persistent_keepalive = None;

        let mut in_peer = false;

        for line in config.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == "[Interface]" {
                in_peer = false;
                continue;
            }
            if line == "[Peer]" {
                in_peer = true;
                continue;
            }

            if let Some((key, value)) = line.split_once('=') {
                let key = key.trim();
                let value = value.trim();

                if !in_peer {
                    match key {
                        "PrivateKey" => {
                            private_key = Some(decode_key(value)?);
                        }
                        "Address" => {
                            address = Some(value.to_string());
                        }
                        "DNS" => {
                            dns = Some(value.to_string());
                        }
                        _ => {}
                    }
                } else {
                    match key {
                        "PublicKey" => {
                            peer_public_key = Some(decode_key(value)?);
                        }
                        "Endpoint" => {
                            peer_endpoint =
                                Some(value.parse::<SocketAddr>().context("invalid endpoint")?);
                        }
                        "AllowedIPs" => {
                            peer_allowed_ips =
                                value.split(',').map(|s| s.trim().to_string()).collect();
                        }
                        "PresharedKey" => {
                            peer_preshared_key = Some(decode_key(value)?);
                        }
                        "PersistentKeepalive" => {
                            persistent_keepalive = Some(value.parse::<u16>()?);
                        }
                        _ => {}
                    }
                }
            }
        }

        Ok(WgConfig {
            private_key: private_key.context("missing PrivateKey")?,
            address: address.context("missing Address")?,
            dns,
            peer_public_key: peer_public_key.context("missing peer PublicKey")?,
            peer_endpoint: peer_endpoint.context("missing peer Endpoint")?,
            peer_allowed_ips,
            peer_preshared_key,
            persistent_keepalive,
        })
    }

    pub fn from_file(path: &str) -> Result<Self> {
        let contents = std::fs::read_to_string(path).context("failed to read config file")?;
        Self::from_string(&contents)
    }
}

fn decode_key(b64: &str) -> Result<[u8; 32]> {
    use base64::Engine;
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64.trim())
        .context("invalid base64 key")?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("key must be 32 bytes"))?;
    Ok(arr)
}
