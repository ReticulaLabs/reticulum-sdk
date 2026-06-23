use alloc::string::String;
use std::net::TcpListener as StdTcpListener;
use std::sync::Arc;

use tokio::net::TcpListener;

use crate::error::RnsError;
use crate::iface::{configured_bitrate, DEFAULT_HW_MTU};

use super::tcp_client::TcpClient;
use super::{Interface, InterfaceContext, InterfaceManager};

pub struct TcpServer {
    addr: String,
    iface_manager: Arc<tokio::sync::Mutex<InterfaceManager>>,
    listener: Option<StdTcpListener>,
    accept_trace_label: Option<String>,
    bitrate: Option<f64>,
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
        }
    }

    pub fn with_bitrate(mut self, bitrate: f64) -> Self {
        self.bitrate = configured_bitrate(bitrate);
        self
    }

    pub fn with_accept_trace_label<T: Into<String>>(mut self, label: T) -> Self {
        self.accept_trace_label = Some(label.into());
        self
    }

    pub async fn spawn(context: InterfaceContext<Self>) {
        let addr = { context.inner.lock().unwrap().addr.clone() };

        let iface_manager = { context.inner.lock().unwrap().iface_manager.clone() };
        let mut listener = { context.inner.lock().unwrap().listener.take() };
        let accept_trace_label = { context.inner.lock().unwrap().accept_trace_label.clone() };
        let bitrate = { context.inner.lock().unwrap().bitrate };

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

            loop {
                if cancel.is_cancelled() {
                    break;
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

                            let mut iface_manager = iface_manager.lock().await;

                            iface_manager.spawn(
                                TcpClient::new_from_stream(client.1.to_string(), client.0)
                                    .with_optional_bitrate(bitrate),
                                TcpClient::spawn,
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
    fn hw_mtu() -> usize {
        DEFAULT_HW_MTU
    }

    fn bitrate(&self) -> Option<f64> {
        self.bitrate
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
}
