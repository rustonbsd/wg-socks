#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let proxy = wg_socks::WgSocksProxy::start_from_file(
        "mullvad_wg.conf",
        "127.0.0.1:1080".parse()?,
    )
    .await?;

    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(proxy.proxy_url())?)
        .build()?;

    let resp = client.get("https://am.i.mullvad.net/json").send().await?;
    println!("{}", resp.text().await?);

    proxy.shutdown();
    Ok(())
}
