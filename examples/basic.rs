#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxy =
        wg_socks::WgSocksProxy::start_from_file(
            "wireguard.conf",
            "127.0.0.1:1080".parse()?)
            .await?;

    // use proxy.proxy_url()

    proxy.shutdown();
    Ok(())
}
