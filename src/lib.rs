pub mod config;

use anyhow::{Context, Result};
use fast_socks5::{
    ReplyError, Socks5Command,
    server::{DnsResolveHelper, Socks5ServerProtocol},
};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{debug, error, info, warn};

pub use config::WgConfig;

pub struct WgSocksProxy {
    pub socks_addr: SocketAddr,
    shutdown: tokio::sync::watch::Sender<bool>,
}

impl WgSocksProxy {
    pub async fn start(wg_config: &WgConfig, socks_bind: SocketAddr) -> Result<Self> {
        let interface = create_interface(wg_config)
            .await
            .context("failed to create WG interface")?;
        info!("WireGuard tunnel established");

        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        tokio::spawn(run_server(socks_bind, interface, shutdown_rx));

        Ok(Self {
            socks_addr: socks_bind,
            shutdown: shutdown_tx,
        })
    }

    pub async fn start_from_str(config_str: &str, socks_bind: SocketAddr) -> Result<Self> {
        let wg_config = WgConfig::from_string(config_str)?;
        Self::start(&wg_config, socks_bind).await
    }

    pub async fn start_from_file(path: &str, socks_bind: SocketAddr) -> Result<Self> {
        let wg_config = WgConfig::from_file(path)?;
        Self::start(&wg_config, socks_bind).await
    }

    pub fn proxy_url(&self) -> String {
        format!("socks5h://{}", self.socks_addr)
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown.send(true);
    }
}

async fn run_server(
    bind: SocketAddr,
    interface: tokio_wireguard::Interface,
    mut shutdown_rx: tokio::sync::watch::Receiver<bool>,
) {
    let listener = match TcpListener::bind(bind).await {
        Ok(l) => l,
        Err(e) => {
            error!("Failed to bind SOCKS5: {:#}", e);
            return;
        }
    };

    info!("SOCKS5 proxy listening on {}", bind);

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((socket, peer)) => {
                        debug!("new client: {}", peer);
                        let iface = interface.clone();
                        tokio::spawn(async move {
                            if let Err(e) =
                                handle_client(socket, iface).await
                            {
                                warn!(
                                    "client {} error: {:#}",
                                    peer, e
                                );
                            }
                        });
                    }
                    Err(e) => {
                        error!("accept error: {:#}", e);
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("SOCKS5 server shutting down");
                break;
            }
        }
    }
}

async fn handle_client(
    socket: tokio::net::TcpStream,
    interface: tokio_wireguard::Interface,
) -> Result<()> {
    let (proto, cmd, target_addr) = Socks5ServerProtocol::accept_no_auth(socket)
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .read_command()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?
        .resolve_dns()
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    if cmd != Socks5Command::TCPConnect {
        proto
            .reply_error(&ReplyError::CommandNotSupported)
            .await
            .map_err(|e| anyhow::anyhow!("{}", e))?;
        anyhow::bail!("unsupported command: {:?}", cmd);
    }

    let target_str = target_addr.to_string();
    debug!("CONNECT → {}", target_str);

    let wg_stream = match tokio_wireguard::TcpStream::connect(&target_str, &interface).await {
        Ok(s) => s,
        Err(e) => {
            error!("WG connect to {} failed: {:#}", target_str, e);
            proto
                .reply_error(&ReplyError::HostUnreachable)
                .await
                .map_err(|e| anyhow::anyhow!("{}", e))?;
            anyhow::bail!("WG connect failed: {}", e);
        }
    };

    let client_stream = proto
        .reply_success(SocketAddr::from(([0, 0, 0, 0], 0)))
        .await
        .map_err(|e| anyhow::anyhow!("{}", e))?;

    let (mut cr, mut cw) = tokio::io::split(client_stream);
    let (mut wr, mut ww) = tokio::io::split(wg_stream);

    tokio::select! {
        r = tokio::io::copy(&mut cr, &mut ww) => {
            r.context("client -> wg")?;
        }
        r = tokio::io::copy(&mut wr, &mut cw) => {
            r.context("wg -> client")?;
        }
    }

    Ok(())
}

async fn create_interface(wg: &WgConfig) -> Result<tokio_wireguard::Interface> {
    use tokio_wireguard::config::{Config, Interface, Peer};
    use tokio_wireguard::interface::ToInterface;

    let config = Config {
        interface: Interface {
            private_key: wg.private_key.into(),
            address: wg.address.parse().context("invalid WG address")?,
            listen_port: None,
            mtu: None,
        },
        peers: vec![Peer {
            public_key: wg.peer_public_key.into(),
            endpoint: Some(wg.peer_endpoint),
            allowed_ips: wg
                .peer_allowed_ips
                .iter()
                .map(|s| s.parse())
                .collect::<Result<Vec<_>, _>>()
                .context("invalid AllowedIPs")?,
            persistent_keepalive: wg.persistent_keepalive,
        }],
    };

    config
        .to_interface()
        .await
        .context("failed to init WG interface")
}
