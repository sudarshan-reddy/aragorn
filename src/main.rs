mod live_packet_reader;
mod plugin;
mod post_processor;
mod tun;

use clap::Parser;
use live_packet_reader::LivePacketReader;
use plugin::redis::handler::RespHandler;
use post_processor::prometheus::PrometheusPostProcessor;
use std::io;
use std::sync::Arc;
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
}

#[tokio::main]
async fn main() -> io::Result<()> {
    tracing_subscriber::fmt()
        .with_max_level(Level::DEBUG)
        .init();
    let args = Args::parse();

    let redis_handler = Arc::new(Mutex::new(RespHandler::new(args.redis_port)));
    let active_packet_reader =
        LivePacketReader::new(&args.interface).expect("Failed to create packet reader");
    let mut observer = Observer::new(tun::ObsConfig {
        ..Default::default()
    });

    observer.add_post_processor(Arc::new(Mutex::new(PrometheusPostProcessor::new())));
    observer.start_cleanup();

    let res = observer
        .capture_packets(active_packet_reader, redis_handler)
        .await;

    match res {
        Ok(_) => info!("Observer stopped successfully"),
        Err(e) => error!("Error: {:?}", e),
    }

    observer.stop();

    Ok(())
}
