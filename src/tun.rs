use anyhow::Result;
use std::io::Read;
use std::sync::Arc;
use tokio::sync::Mutex;
use tun::platform::Device;

pub struct Tun {
    inner: Arc<Mutex<Device>>,
}

pub trait Handler<T>: Send + Sync {
    async fn parse_packet(&self, buf: &[u8]) -> Result<T>;
    async fn process(&self, input: T) -> Result<()>;
}

pub struct PrintHandler;

impl PrintHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl Handler<Vec<u8>> for PrintHandler {
    async fn parse_packet(&self, buf: &[u8]) -> Result<Vec<u8>> {
        Ok(buf.to_vec())
    }

    async fn process(&self, input: Vec<u8>) -> Result<()> {
        println!("{:?}", input);
        Ok(())
    }
}

impl Tun {
    // TODO: Should probably make this async
    pub fn new() -> Result<Self> {
        let mut config = tun::Configuration::default();

        // TODO: Temp hard-coding. Get from Config file.
        config
            .address((10, 0, 0, 9))
            .netmask((255, 255, 255, 0))
            .destination((10, 0, 0, 2))
            .up();
        let device = tun::create(&config)?;

        Ok(Self {
            inner: Arc::new(Mutex::new(device)),
        })
    }

    pub async fn handle_packet<T>(&self, handler: Arc<Mutex<impl Handler<T>>>) -> Result<()>
    where
        T: Send + 'static,
    {
        let mut buf = [0u8; 1504];

        let mut dev = self.inner.lock().await;
        let nbytes = dev.read(&mut buf)?;
        let packet = handler.lock().await.parse_packet(&buf[..nbytes]).await?;
        handler.lock().await.process(packet).await?;
        Ok(())
    }
}
