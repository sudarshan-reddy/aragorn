mod tun;
use clap::Parser;
use env_logger;
use std::io;
use std::sync::Arc;
use tokio::{sync::Mutex, task};

use tun::{PrintHandler, Tun};

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// The name of the TUN/TAP interface
    #[arg(short, long, default_value = "tun0")]
    interface: String,

    /// Use TAP mode instead of TUN mode
    #[arg(long)]
    tap: bool,
}

#[tokio::main]
async fn main() -> io::Result<()> {
    env_logger::init();

    //let args = Args::parse();
    let tun_device = Arc::new(Mutex::new(Tun::new().unwrap()));

    let handler = Arc::new(Mutex::new(PrintHandler::new()));

    loop {
        let handler_clone = handler.clone();
        let tun_device = tun_device.clone();
        task::spawn(async move {
            if let Err(e) = tun_device.lock().await.handle_packet(handler_clone).await {
                log::error!("Failed to handle packet: {}", e);
            }
        })
        .await
        .unwrap();
    }
}
