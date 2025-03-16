use anyhow::Result;
use lazy_static::lazy_static;
use prometheus::{gather, Encoder, TextEncoder};
use prometheus::{register_counter_vec, register_histogram_vec, CounterVec, HistogramVec};
use std::net::SocketAddr;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tracing::info;

// Define metrics as lazy_static to ensure they're initialized only once
lazy_static! {
    static ref REQUESTS: CounterVec =
        register_counter_vec!("requests_total", "Number of requests", &["key"]).unwrap();
    static ref ERRORS: CounterVec =
        register_counter_vec!("errors_total", "Number of errors", &["key"]).unwrap();
    static ref LATENCY: HistogramVec =
        register_histogram_vec!("latency_seconds", "Request latency in seconds", &["key"]).unwrap();
}

/// Record metrics for a request
pub fn record_metrics(key: &str, is_error: bool, latency_ms: u128) {
    REQUESTS.with_label_values(&[key]).inc();
    LATENCY
        .with_label_values(&[key])
        .observe(latency_ms as f64 / 1000.0); // Convert ms to seconds

    if is_error {
        ERRORS.with_label_values(&[key]).inc();
    }
}

/// Start the Prometheus metrics server
pub async fn run_prometheus_server() -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 9090));
    let listener = TcpListener::bind(&addr).await?;

    info!("Prometheus metrics server listening on: {}", addr);

    loop {
        let (mut socket, _) = listener.accept().await?;
        let encoder = TextEncoder::new();
        let metric_families = gather();
        let mut buffer = vec![];
        encoder.encode(&metric_families, &mut buffer)?;

        let response = format!(
            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
            buffer.len(),
            String::from_utf8(buffer).unwrap()
        );

        socket.write_all(response.as_bytes()).await?;
    }
}
