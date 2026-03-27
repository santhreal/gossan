use tokio::net::TcpStream;

pub async fn connect_tcp(addr: &str, port: u16, proxy: Option<&str>) -> std::io::Result<TcpStream> {
    if let Some(p) = proxy {
        let p_addr = p
            .trim_start_matches("http://")
            .trim_start_matches("socks5://")
            .trim_start_matches("socks5h://");
        let stream = tokio_socks::tcp::Socks5Stream::connect(p_addr, (addr, port))
            .await
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        Ok(stream.into_inner())
    } else {
        TcpStream::connect((addr, port)).await
    }
}
