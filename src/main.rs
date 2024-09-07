mod live_packet_reader;
mod plugin;
mod post_processor;
mod probes;
mod tls_reader;
mod tun;

use anyhow::Result;
use clap::Parser;
use live_packet_reader::LivePacketReader;
use plugin::redis::handler::RespHandler;
use post_processor::prometheus::PrometheusPostProcessor;
use prometheus::{gather, Encoder, TextEncoder};
use std::sync::Arc;
use std::{io, net::SocketAddr};
use tls_reader::TlsReader;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::Mutex;
use tracing::{error, info, Level};
use tun::Observer;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The name of the TUN/TAP interface
    #[arg(short, long, default_value = "lo0")]
    interface: String,

    /// The port to listen for redis handler
    #[arg(short, long, default_value = "6379")]
    redis_port: u16,

    #[arg(short, long, default_value = "false")]
    tls_mode: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    let args = Args::parse();

    let redis_handler = Arc::new(Mutex::new(RespHandler::new(args.redis_port)));

    let mut observer = Observer::new(tun::ObsConfig {
        ..Default::default()
    });

    observer.add_post_processor(Arc::new(Mutex::new(PrometheusPostProcessor::new())));
    observer.start_cleanup();

    tokio::spawn(run_prometheus_server());

    let res = if args.tls_mode {
        let tls_reader = TlsReader::new().await.expect("Failed to create TLS reader");
        observer.capture_packets(tls_reader, redis_handler).await
    } else {
        let reader =
            LivePacketReader::new(&args.interface).expect("Failed to create packet reader");
        observer.capture_packets(reader, redis_handler).await
    };

    match res {
        Ok(_) => info!("Observer stopped successfully"),
        Err(e) => error!("Error: {:?}", e),
    }

    observer.stop();

    Ok(())
}

async fn run_prometheus_server() -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], 9090));
    let listener = TcpListener::bind(&addr).await?;

    info!("Prometheus server listening on: {}", addr);

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
