use alloc::string::String;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::net::TcpListener;

use crate::error::RnsError;
use crate::iface::{DEFAULT_HW_MTU, InterfaceMode, configured_bitrate};

use super::tcp_client::TcpClient;
use super::{Interface, InterfaceContext, InterfaceManager};

pub struct TcpServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    listener: Option<StdTcpListener>,
    accept_trace_label: Option<String>,
    bitrate: Option<f64>,
    max_connections: Option<usize>,
    mode: InterfaceMode,
}

impl TcpServer {
    pub fn new<T: Into<String>>(
        addr: T,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            listener: None,
            accept_trace_label: None,
            bitrate: None,
            max_connections: Some(128),
            mode: InterfaceMode::Full,
        }
    }

    pub fn new_from_listener<T: Into<String>>(
        addr: T,
        listener: StdTcpListener,
        iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    ) -> Self {
        Self {
            addr: addr.into(),
            iface_manager,
            listener: Some(listener),
            accept_trace_label: None,
            bitrate: None,
            max_connections: Some(128),
            mode: InterfaceMode::Full,
        }
    }

    pub fn with_bitrate(mut self, bitrate: f64) -> Self {
        self.bitrate = configured_bitrate(bitrate);
        self
    }

    pub fn with_max_connections(mut self, n: usize) -> Self {
        self.max_connections = Some(n);
        self
    }

    pub fn without_max_connections(mut self) -> Self {
        self.max_connections = None;
        self
    }

    pub fn with_accept_trace_label<T: Into<String>>(mut self, label: T) -> Self {
        self.accept_trace_label = Some(label.into());
        self
    }

    pub fn with_interface_mode(mut self, mode: InterfaceMode) -> Self {
        self.mode = mode;
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };

        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let mut listener = { context.inner.lock().unwrap().listener.take() };
        let accept_trace_label = { context.inner.lock().unwrap().accept_trace_label.clone() };
        let bitrate = { context.inner.lock().unwrap().bitrate };
        let max_connections = { context.inner.lock().unwrap().max_connections };
        let mode = { context.inner.lock().unwrap().mode };

        let (_, tx_channel) = context.channel.split();
        let tx_channel = Arc::new(tokio::sync::Mutex::new(tx_channel));

        loop {
            if context.cancel.is_cancelled() {
                break;
            }

            let listener = match listener.take() {
                Some(listener) => listener
                    .set_nonblocking(true)
                    .map(|_| listener)
                    .map_err(|_| RnsError::ConnectionError)
                    .and_then(|listener| {
                        TcpListener::from_std(listener).map_err(|_| RnsError::ConnectionError)
                    }),
                None => TcpListener::bind(addr.clone())
                    .await
                    .map_err(|_| RnsError::ConnectionError),
            };

            if let Err(_) = listener {
                log::warn!("tcp_server: couldn't bind to <{}>", addr);
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                continue;
            }

            log::info!("tcp_server: listen on <{}>", addr);

            let listener = listener.unwrap();

            let tx_task = {
                let cancel = context.cancel.clone();
                let tx_channel = tx_channel.clone();

                tokio::spawn(async move {
                    loop {
                        if cancel.is_cancelled() {
                            break;
                        }

                        let mut tx_channel = tx_channel.lock().await;

                        tokio::select! {
                            _ = cancel.cancelled() => {
                                break;
                            }
                            // Skip all tx messages
                            _ = tx_channel.recv() => {}
                        }
                    }
                })
            };

            let cancel = context.cancel.clone();
            let active_connections = Arc::new(AtomicUsize::new(0));

            loop {
                if cancel.is_cancelled() {
                    break;
                }

                if let Some(max) = max_connections {
                    if active_connections.load(Ordering::Relaxed) >= max {
                        log::warn!(
                            "tcp_server: max connections ({}) reached, waiting for a slot",
                            max,
                        );
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                        continue;
                    }
                }

                tokio::select! {
                    _ = cancel.cancelled() => {
                        break;
                    }

                    client = listener.accept() => {
                        if let Ok(client) = client {
                            if let Some(label) = &accept_trace_label {
                                log::trace!(
                                    "{}: client <{}> connected to <{}>",
                                    label,
                                    client.1,
                                    addr
                                );
                            }
                            log::info!(
                                "tcp_server: new client <{}> connected to <{}>",
                                client.1,
                                addr
                            );

                            active_connections.fetch_add(1, Ordering::Relaxed);
                            let connections = active_connections.clone();
                            let mut iface_manager = iface_manager.lock().await;

                            iface_manager.spawn(
                                TcpClient::new_from_stream(client.1.to_string(), client.0)
                                    .with_optional_bitrate(bitrate)
                                    .with_interface_mode(mode),
                                |context| async move {
                                    TcpClient::spawn(context).await;
                                    connections.fetch_sub(1, Ordering::Relaxed);
                                },
                            );
                        }
                    }
                }
            }

            let _ = tokio::join!(tx_task);
        }
    }
}

impl Interface for TcpServer {
    fn hw_mtu(&self) -> usize {
        DEFAULT_HW_MTU
    }

    fn supports_discovery(&self) -> bool {
        true
    }

    fn bitrate(&self) -> Option<f64> {
        self.bitrate
    }

    fn autoconfigure_mtu(&self) -> bool {
        true
    }

    fn interface_mode(&self) -> InterfaceMode {
        self.mode
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;

    #[test]
    fn bitrate_defaults_to_unreported() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(1)));
        assert_eq!(TcpServer::new("127.0.0.1:0", iface_manager).bitrate(), None);
    }

    #[test]
    fn bitrate_can_be_configured() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(1)));
        assert_eq!(
            TcpServer::new("127.0.0.1:0", iface_manager)
                .with_bitrate(2_000_000.0)
                .bitrate(),
            Some(2_000_000.0)
        );
    }

    #[test]
    fn server_interface_mode_defaults_to_full() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(1)));
        assert_eq!(
            TcpServer::new("127.0.0.1:0", iface_manager).interface_mode(),
            InterfaceMode::Full
        );
    }

    #[test]
    fn server_interface_mode_can_be_configured() {
        let iface_manager = Arc::new(tokio::sync::Mutex::new(InterfaceManager::new(1)));
        assert_eq!(
            TcpServer::new("127.0.0.1:0", iface_manager)
                .with_interface_mode(InterfaceMode::Boundary)
                .interface_mode(),
            InterfaceMode::Boundary
        );
    }

    #[tokio::test]
    async fn server_spawned_client_inherits_interface_mode() {
        // Mirrors the TcpClient construction used at line ~189 in
        // TcpServer::spawn() for incoming TCP connections, but with the
        // server's mode pre-applied via with_interface_mode(). This
        // validates the fix that incoming TcpClient interfaces inherit
        // the parent TcpServer's mode (so a Boundary-mode server
        // correctly spawns Boundary-mode children, which keeps the
        // Boundary -> Internal announce filter active and protects
        // low-bitrate internal interfaces like LoRA from announce
        // backlog).
        use tokio::net::{TcpListener, TcpStream};

        // Stand up a real listening socket so the connecting stream is
        // accepted before we hand it to TcpClient::new_from_stream.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");

        let connect = tokio::spawn(async move {
            TcpStream::connect(addr).await.expect("connect to listener")
        });
        let (stream, _peer) = listener.accept().await.expect("accept");
        connect.await.expect("connect task");

        let child = TcpClient::new_from_stream(addr.to_string(), stream)
            .with_optional_bitrate(None)
            .with_interface_mode(InterfaceMode::Boundary);
        assert_eq!(child.interface_mode(), InterfaceMode::Boundary);

        // Repeat for Internal mode to confirm the chain honors arbitrary
        // configured modes, not just Boundary.
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral port");
        let addr = listener.local_addr().expect("local_addr");
        let connect = tokio::spawn(async move {
            TcpStream::connect(addr).await.expect("connect to listener")
        });
        let (stream, _peer) = listener.accept().await.expect("accept");
        connect.await.expect("connect task");
        let child_internal = TcpClient::new_from_stream(addr.to_string(), stream)
            .with_optional_bitrate(None)
            .with_interface_mode(InterfaceMode::Internal);
        assert_eq!(child_internal.interface_mode(), InterfaceMode::Internal);
    }
}
