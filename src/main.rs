mod redis;
mod tun;

use clap::Parser;
use env_logger;
use redis::RespHandler;
use std::io;
use std::sync::Arc;
use tokio::sync::Mutex;
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
    env_logger::init();

    let args = Args::parse();

    let handler = Arc::new(Mutex::new(RespHandler::new(args.redis_port)));
    let observer = Observer::new();

    observer
        .capture_packets(&args.interface, handler)
        .await
        .unwrap();

    Ok(())
}
