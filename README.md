# wg-socks

[![crates.io](https://img.shields.io/crates/v/wg-socks.svg)](https://crates.io/crates/wg-socks)
[![docs.rs](https://img.shields.io/docsrs/wg-socks)](https://docs.rs/wg-socks)
[![build](https://github.com/rustonbsd/wg-socks/actions/workflows/ci.yml/badge.svg)](https://github.com/rustonbsd/wg-socks/actions/workflows/ci.yml)

Turn a WireGuard config into a local SOCKS5 proxy.

Load a wireguard style config, start the proxy, and route traffic through bind address (`127.0.0.1:1080`).

## Quick start

```rust
#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxy = wg_socks::WgSocksProxy::start_from_file(
        "wireguard.conf",
        "127.0.0.1:1080".parse()?)
        .await?;

    // use proxy.proxy_url()

    proxy.shutdown();
    Ok(())
}

```

API entry points: `start`, `start_from_str`, `start_from_file`
