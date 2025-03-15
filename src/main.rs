mod dissector;
mod live_packet_reader;
mod metrics;
mod packet_router;
mod probes;
mod tls_reader;

use clap::Parser;
use dissector::redis::RedisDissector;
use packet_router::{PacketRouter, RouterConfig};
use std::io;
use std::sync::Arc;
use tls_reader::TlsReader;
use tokio::sync::Mutex;
use tracing::{error, info, Level};

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

    // Create the Redis dissector
    let redis_dissector = Arc::new(Mutex::new(RedisDissector::new(args.redis_port)));

    // Create the packet router
    let router = PacketRouter::new(RouterConfig {
        ..Default::default()
    });

    router.start_cleanup();

    // Start the Prometheus metrics server
    tokio::spawn(metrics::run_prometheus_server());

    // Start capturing packets
    let tls_reader = TlsReader::new().await.expect("Failed to create TLS reader");
    let res = router.capture_packets(tls_reader, redis_dissector).await;

    match res {
        Ok(_) => info!("Packet router stopped successfully"),
        Err(e) => error!("Error: {:?}", e),
    }

    router.stop();

    Ok(())
}
