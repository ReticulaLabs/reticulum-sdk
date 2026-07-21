use getrandom::SysRng;
use rand_core::UnwrapErr;
use reticulum_sdk::identity::PrivateIdentity;
use reticulum_sdk::iface::tcp_server::TcpServer;
use reticulum_sdk::transport::{Transport, TransportConfig};

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("trace")).init();

    log::info!(">>> TCP SERVER APP <<<");

    let mut rng = UnwrapErr(SysRng);
    let transport = Transport::new(TransportConfig::new(
        "server",
        &PrivateIdentity::new_from_rand(&mut rng),
        true,
    ));

    let _ = transport.iface_manager().lock().await.spawn(
        TcpServer::new("0.0.0.0:4242", transport.iface_manager()),
        TcpServer::spawn,
    );

    let _ = tokio::signal::ctrl_c().await;

    log::info!("exit");
}
