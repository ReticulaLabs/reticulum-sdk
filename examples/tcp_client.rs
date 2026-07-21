use std::time::Duration;

use getrandom::SysRng;
use rand_core::UnwrapErr;
use reticulum_sdk::destination::{DestinationName, SingleInputDestination};
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::iface::tcp_client::TcpClient;
use reticulum_sdk::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> TCP CLIENT APP <<<");

    let transport = Transport::new(TransportConfig::default());

    let client_addr = transport
        .iface_manager()
        .lock()
        .await
        .spawn(TcpClient::new("127.0.0.1:4242"), TcpClient::spawn);

    let mut rng = UnwrapErr(SysRng);
    let id = PrivateIdentity::new_from_rand(&mut rng);

    let destination = SingleInputDestination::new(id, DestinationName::new("example", "app"));

    tokio::time::sleep(Duration::from_secs(3)).await;

    transport
        .send_direct(client_addr, destination.announce(&mut rng, None).unwrap())
        .await;

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
