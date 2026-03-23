use anyhow::Result;
use metrics_exporter_prometheus::PrometheusBuilder;
use std::net::SocketAddr;

/// Initialize Prometheus exporter on the provided address (e.g. "0.0.0.0:9000").
pub fn init_metrics(listen_addr: &str) -> Result<()> {
    let addr: SocketAddr = listen_addr.parse()?;
    PrometheusBuilder::new()
        .with_http_listener(addr)
        .install()?;
    Ok(())
}

