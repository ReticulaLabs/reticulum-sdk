use super::*;

use hmac::{Hmac, Mac};
use rmpv::{Value, decode::read_value, encode::write_value};
use sha2::Sha256;
use std::net::TcpListener as StdTcpListener;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

pub(super) const PY_CONN_CHALLENGE: &[u8] = b"#CHALLENGE#";
pub(super) const PY_CONN_WELCOME: &[u8] = b"#WELCOME#";
pub(super) const PY_CONN_FAILURE: &[u8] = b"#FAILURE#";
pub(super) const PY_CONN_AUTH_MAX_FRAME: usize = 256;
pub(super) const PY_CONN_MUTUAL_AUTH_TIMEOUT: Duration = Duration::from_millis(500);

pub(super) fn start_rpc_instance(
    config: &mut TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
) {
    config.rpc_enabled = false;
    config.rpc_connected = false;
    config.is_standalone_instance = false;

    if !config.rpc_instance {
        config.is_standalone_instance = true;
        return;
    }

    if config.rpc_key.is_none() {
        config.rpc_key = Some(config.identity.rpc_key());
    }

    match config.rpc_instance_type {
        RpcInstanceType::Tcp => start_tcp_rpc_instance(config, iface_manager, cancel),
        RpcInstanceType::Unix => {
            log::warn!(
                "tp({}): rpc_instance_type=unix is not implemented; running standalone",
                config.name
            );
            config.is_standalone_instance = true;
        }
    }
}

pub(super) fn start_tcp_rpc_instance(
    config: &mut TransportConfig,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
) {
    let addr = format!("{}:{}", config.rpc_bind_host, config.rpc_data_port);
    if config.rpc_bind_host != DEFAULT_RPC_BIND_HOST {
        if config.rpc_key.is_none() {
            let msg = format!(
                "tp({}): Refusing to listen on a non-loopback address ({}) without a defined rpc_key. \
                This is a dangerous configuration.", config.name, config.rpc_bind_host
            );
            if config.require_rpc_instance {
                panic!("{}", msg);
            }
            log::error!("{}", msg);
            return;
        }

        // This is generally only recommended for debugging or attaching
        // rnmcp to a backbone router for analysis.
        log::warn!(
            "tp({}): rpc_bind_host is set to \"{}\" instead of the default \"{}\". \
             Binding the RPC interface to a non-loopback address is not recommended.",
            config.name, config.rpc_bind_host, DEFAULT_RPC_BIND_HOST
        );
    }

    match StdTcpListener::bind(&addr) {
        Ok(listener) => {
            if config.require_rpc_instance {
                panic!("No rpc instance available, but application required it");
            }

            config.rpc_enabled = true;
            start_tcp_rpc_data_listener(
                config.name.clone(),
                addr.clone(),
                listener,
                iface_manager,
                cancel.clone(),
            );
            log::debug!("tp({}): started rpc instance on {}", config.name, addr);
        }
        Err(error) => {
            log::trace!(
                "rpc: tp({}) connecting local client to <{}>",
                config.name,
                addr
            );
            let iface_manager_for_task = iface_manager.clone();
            let client = TcpClient::new(addr.clone());
            tokio::spawn(async move {
                iface_manager_for_task
                    .lock()
                    .await
                    .spawn(client, TcpClient::spawn);
            });

            config.rpc_connected = true;
            config.retransmit = false;
            config.respond_to_probes = false;
            log::debug!(
                "tp({}): connected to rpc instance on {} after bind failed: {}",
                config.name,
                addr,
                error
            );
        }
    }
}

pub(super) fn start_tcp_rpc_data_listener(
    name: String,
    addr: String,
    listener: StdTcpListener,
    iface_manager: Arc<Mutex<InterfaceManager>>,
    cancel: CancellationToken,
) {
    tokio::spawn(async move {
        let listener = match listener
            .set_nonblocking(true)
            .map(|_| listener)
            .map_err(|error| error.to_string())
            .and_then(|listener| TcpListener::from_std(listener).map_err(|error| error.to_string()))
        {
            Ok(listener) => listener,
            Err(error) => {
                log::error!(
                    "rpc: tp({}) could not start data listener <{}>: {}",
                    name,
                    addr,
                    error
                );
                return;
            }
        };

        log::debug!(
            "rpc: tp({}) listening for data clients on <{}>",
            name,
            addr
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    break;
                }
                client = listener.accept() => {
                    match client {
                        Ok((stream, remote)) => {
                            log::trace!(
                                "rpc: client <{}> connected to <{}>",
                                remote,
                                addr
                            );
                            let iface_manager = iface_manager.clone();
                            tokio::spawn(async move {
                                handle_rpc_data_client(stream, remote.to_string(), iface_manager).await;
                            });
                        }
                        Err(error) => {
                            log::warn!(
                                "rpc: error accepting data client on <{}>: {}",
                                addr,
                                error
                            );
                        }
                    }
                }
            }
        }
    });
}

pub(super) async fn handle_rpc_data_client(
    stream: TcpStream,
    remote: String,
    iface_manager: Arc<Mutex<InterfaceManager>>,
) {
    iface_manager
        .lock()
        .await
        .spawn_rpc_instance_client(TcpClient::new_from_stream(remote, stream).with_interface_mode(InterfaceMode::Boundary), TcpClient::spawn);
}

pub(super) fn start_tcp_rpc(
    name: String,
    port: u16,
    bind_host: String,
    auth_key: Option<Vec<u8>>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_messages: broadcast::Sender<RxMessage>,
    cancel: CancellationToken,
) {
    let addr = format!("{}:{}", bind_host, port);
    tokio::spawn(async move {
        let listener = match TcpListener::bind(&addr).await {
            Ok(listener) => listener,
            Err(error) => {
                log::error!(
                    "rpc: tp({}) could not bind RPC control listener <{}>: {}",
                    name,
                    addr,
                    error
                );
                return;
            }
        };

        log::debug!(
            "rpc: tp({}) listening for RPC control clients on <{}>",
            name,
            addr
        );

        loop {
            tokio::select! {
                _ = cancel.cancelled() => {
                    break;
                }
                client = listener.accept() => {
                    match client {
                        Ok((stream, remote)) => {
                            log::trace!(
                                "rpc: RPC client <{}> connected to <{}>",
                                remote,
                                addr
                            );
                            let auth_key = auth_key.clone();
                            let handler = handler.clone();
                            let iface_messages = iface_messages.clone();
                            tokio::spawn(async move {
                                if let Err(error) =
                                    handle_rpc_client(stream, auth_key.as_deref(), handler, iface_messages)
                                        .await
                                {
                                    log::warn!(
                                        "rpc: RPC client <{}> failed: {}",
                                        remote,
                                        error
                                    );
                                }
                            });
                        }
                        Err(error) => {
                            log::warn!(
                                "rpc: error accepting RPC control client on <{}>: {}",
                                addr,
                                error
                            );
                        }
                    }
                }
            }
        }
    });
}

pub(super) async fn handle_rpc_client(
    mut stream: TcpStream,
    auth_key: Option<&[u8]>,
    handler: Arc<Mutex<TransportHandler>>,
    iface_messages: broadcast::Sender<RxMessage>,
) -> Result<(), String> {
    rpc_authenticate(&mut stream, auth_key).await?;

    let request = read_py_connection_frame(&mut stream, 64 * 1024).await?;
    let request = read_rpc_value(&request)?;

    if let Some(map) = request.as_map() {
        if let Some(listen_config) = rpc_map_value(map, "listen") {
            let destination_filter = listen_config
                .as_map()
                .and_then(|m| rpc_map_value(m, "destination"))
                .and_then(|v| v.as_slice())
                .and_then(|slice| {
                    if slice.len() == crate::hash::ADDRESS_HASH_SIZE {
                        let mut bytes = [0u8; crate::hash::ADDRESS_HASH_SIZE];
                        bytes.copy_from_slice(slice);
                        Some(AddressHash::new(bytes))
                    } else {
                        None
                    }
                });
            return handle_rpc_listen(stream, iface_messages, destination_filter).await;
        }
    }

    let response = if let Some(map) = request.as_map() {
        if rpc_map_str(map, "get") == Some("request_path") {
            handle_rpc_request_path(map, handler).await
        } else {
            let mut h = handler.lock().await;
            handle_rpc_request(&request, Some(&mut h))
        }
    } else {
        let mut h = handler.lock().await;
        handle_rpc_request(&request, Some(&mut h))
    };

    let encoded = write_rpc_value(&response)?;
    write_py_connection_frame(&mut stream, &encoded).await
}

pub(super) async fn handle_rpc_request_path(
    map: &[(Value, Value)],
    handler: Arc<Mutex<TransportHandler>>,
) -> Value {
    let Some(dest_bytes) = rpc_map_value(map, "destination_hash").and_then(|v| v.as_slice())
    else {
        return Value::Boolean(false);
    };
    if dest_bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return Value::Boolean(false);
    }

    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(&dest_bytes[..crate::hash::ADDRESS_HASH_SIZE]);
    let address_hash = AddressHash::new(hash);

    log::trace!(
        "tp(rpc_instance): RPC request_path destination_hash={:02x?}",
        hash,
    );

    {
        // RPC handlers are called infrequently; send directly.
        let mut h = handler.lock().await;
        let packet = h.path_requests.generate(&address_hash, None);
        h.send_ctx
            .send(TxMessage {
                tx_type: TxMessageType::Broadcast(None),
                packet,
            })
            .await;
        h.last_path_requests.insert(address_hash, time::Instant::now());
    }

    let timeout = Duration::from_secs(DEFAULT_PER_HOP_TIMEOUT_SECS * 3);
    let start = time::Instant::now();

    loop {
        if time::Instant::now().duration_since(start) >= timeout {
            break;
        }

        tokio::time::sleep(Duration::from_millis(100)).await;

        let h = handler.lock().await;
        let path_table = h.send_ctx.path_table.read().unwrap();
        if let Some(entry) = path_table.get(&address_hash) {
            return Value::Map(vec![
                (Value::from("found"), Value::from(true)),
                (Value::from("hops"), Value::from(entry.hops as u64)),
                (
                    Value::from("next_hop"),
                    Value::Binary(entry.received_from.as_slice().to_vec()),
                ),
                (
                    Value::from("interface"),
                    Value::Binary(entry.iface.as_slice().to_vec()),
                ),
            ]);
        }
    }

    Value::Map(vec![(Value::from("found"), Value::from(false))])
}

pub(super) async fn rpc_authenticate(
    stream: &mut TcpStream,
    auth_key: Option<&[u8]>,
) -> Result<(), String> {
    let challenge = rpc_challenge();
    write_py_connection_frame(stream, &challenge).await?;

    let response = read_py_connection_frame(stream, 256).await?;
    let authenticated = rpc_response_is_authenticated(&challenge, &response, auth_key)?;

    if authenticated {
        write_py_connection_frame(stream, PY_CONN_WELCOME).await?;
        rpc_answer_peer_challenge(stream, auth_key).await
    } else {
        let _ = write_py_connection_frame(stream, PY_CONN_FAILURE).await;
        Err("authentication failed".into())
    }
}

pub(super) fn rpc_challenge() -> Vec<u8> {
    let mut rng = UnwrapErr(SysRng);
    let mut random = [0u8; 40];
    rng.fill_bytes(&mut random);

    let mut challenge = Vec::with_capacity(PY_CONN_CHALLENGE.len() + 8 + random.len());
    challenge.extend_from_slice(PY_CONN_CHALLENGE);
    challenge.extend_from_slice(b"{sha256}");
    challenge.extend_from_slice(&random);
    challenge
}

pub(super) fn rpc_response_is_authenticated(
    challenge: &[u8],
    response: &[u8],
    auth_key: Option<&[u8]>,
) -> Result<bool, String> {
    let message = &challenge[PY_CONN_CHALLENGE.len()..];
    if let Some(auth_key) = auth_key {
        let expected = rpc_hmac_response(auth_key, message)?;
        let expected_raw = &expected[b"{sha256}".len()..];
        Ok(response == expected.as_slice() || response == expected_raw)
    } else {
        Ok(true)
    }
}

pub(super) async fn rpc_answer_peer_challenge(
    stream: &mut TcpStream,
    auth_key: Option<&[u8]>,
) -> Result<(), String> {
    let Some(peer_challenge) = read_py_connection_frame_if_ready(
        stream,
        PY_CONN_AUTH_MAX_FRAME,
        PY_CONN_MUTUAL_AUTH_TIMEOUT,
    )
    .await?
    else {
        return Ok(());
    };

    if !peer_challenge.starts_with(PY_CONN_CHALLENGE) {
        return Err(format!(
            "expected peer challenge, got {} bytes starting with {:02x}",
            peer_challenge.len(),
            peer_challenge.first().copied().unwrap_or_default()
        ));
    }

    let auth_key = auth_key.ok_or_else(|| {
        "peer requested mutual authentication, but no rpc_key is configured"
            .to_string()
    })?;
    let response = rpc_hmac_response(auth_key, &peer_challenge[PY_CONN_CHALLENGE.len()..])?;
    write_py_connection_frame(stream, &response).await?;

    let welcome = read_py_connection_frame(stream, PY_CONN_AUTH_MAX_FRAME).await?;
    if welcome == PY_CONN_WELCOME {
        Ok(())
    } else if welcome == PY_CONN_FAILURE {
        Err("peer rejected mutual authentication digest".into())
    } else {
        Err(format!(
            "expected mutual authentication welcome, got {} bytes",
            welcome.len()
        ))
    }
}

pub(super) fn rpc_hmac_response(auth_key: &[u8], message: &[u8]) -> Result<Vec<u8>, String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(auth_key).map_err(|error| error.to_string())?;
    mac.update(message);
    let digest = mac.finalize().into_bytes();

    let mut response = Vec::with_capacity(b"{sha256}".len() + digest.len());
    response.extend_from_slice(b"{sha256}");
    response.extend_from_slice(&digest);
    Ok(response)
}

pub(super) async fn handle_rpc_listen(
    mut stream: TcpStream,
    iface_messages: broadcast::Sender<RxMessage>,
    destination_filter: Option<AddressHash>,
) -> Result<(), String> {
    let mut rx = iface_messages.subscribe();

    let init = write_rpc_value(&Value::Map(vec![(
        Value::from("status"),
        Value::from("listening"),
    )]))?;
    write_py_connection_frame(&mut stream, &init).await?;

    loop {
        match rx.recv().await {
            Ok(msg) => {
                if let Some(ref filter) = destination_filter {
                    if msg.packet.destination != *filter {
                        continue;
                    }
                }

                let packet_info = Value::Map(vec![
                    (
                        Value::from("destination"),
                        Value::Binary(msg.packet.destination.as_slice().to_vec()),
                    ),
                    (
                        Value::from("hops"),
                        Value::from(msg.packet.header.hops as u64),
                    ),
                    (
                        Value::from("header_type"),
                        Value::from(msg.packet.header.header_type as u8 as u64),
                    ),
                    (
                        Value::from("destination_type"),
                        Value::from(msg.packet.header.destination_type as u8 as u64),
                    ),
                    (
                        Value::from("transport"),
                        msg.packet
                            .transport
                            .as_ref()
                            .map(|transport| Value::Binary(transport.as_slice().to_vec()))
                            .unwrap_or(Value::Nil),
                    ),
                    (
                        Value::from("packet_type"),
                        Value::from(msg.packet.header.packet_type as u8 as u64),
                    ),
                    (
                        Value::from("context"),
                        Value::from(msg.packet.context as u8 as u64),
                    ),
                    (
                        Value::from("payload_len"),
                        Value::from(msg.packet.data.len() as u64),
                    ),
                    (
                        Value::from("iface"),
                        Value::Binary(msg.address.as_slice().to_vec()),
                    ),
                    (
                        Value::from("snr"),
                        msg.snr.map(Value::from).unwrap_or(Value::Nil),
                    ),
                    (
                        Value::from("rssi"),
                        msg.rssi
                            .map(|v| Value::from(v as i64))
                            .unwrap_or(Value::Nil),
                    ),
                ]);

                let encoded = write_rpc_value(&packet_info)?;
                write_py_connection_frame(&mut stream, &encoded).await?;
            }
            Err(broadcast::error::RecvError::Lagged(n)) => {
                let lag = Value::Map(vec![(
                    Value::from("lagged"),
                    Value::from(n as u64),
                )]);
                let encoded = write_rpc_value(&lag)?;
                write_py_connection_frame(&mut stream, &encoded).await?;
            }
            Err(broadcast::error::RecvError::Closed) => {
                break;
            }
        }
    }
    Ok(())
}

pub(super) fn handle_rpc_request(request: &Value, mut handler: Option<&mut TransportHandler>) -> Value {
    let Some(map) = request.as_map() else {
        return Value::Boolean(false);
    };

    if let Some(operation) = rpc_map_str(map, "get") {
        return match operation {
            "path_table" => rpc_path_table(handler.as_deref_mut()),
            "rate_table" => rpc_rate_table(handler.as_deref_mut()),
            "interface_stats" => rpc_interface_stats(handler.as_deref_mut()),
            "next_hop_if_name" => rpc_next_hop_if_name(map, handler.as_deref()),
            "next_hop" => rpc_next_hop(map, handler.as_deref()),
            "packet_snr" => handler
                .and_then(|h| h.last_snr)
                .map(Value::from)
                .unwrap_or(Value::Nil),
            "packet_rssi" => handler
                .and_then(|h| h.last_rssi)
                .map(|v| Value::from(v as i64))
                .unwrap_or(Value::Nil),
            "packet_q" => Value::Nil,
            "first_hop_timeout" => rpc_first_hop_timeout(map, handler.as_deref()),
            "link_count" => Value::from(0),
            "blackholed_identities" => rpc_blackholed_identities(handler.as_deref_mut()),
            "is_blackholed" => rpc_is_blackholed(map, handler.as_deref_mut()),
            "interfaces" => rpc_interfaces(handler.as_deref_mut()),
            _ => {
                log::warn!(
                    "rpc: unsupported RPC get operation <{}>",
                    operation
                );
                Value::Boolean(false)
            }
        };
    }

    if let Some(operation) = rpc_map_str(map, "drop") {
        return match operation {
            "path" => rpc_drop_path(map, handler.as_deref_mut()),
            "all_via" => rpc_drop_all_via(map, handler.as_deref_mut()),
            "announce_queues" => rpc_drop_announce_queues(handler.as_deref_mut()),
            _ => {
                log::warn!(
                    "rpc: unsupported RPC drop operation <{}>",
                    operation
                );
                Value::Boolean(false)
            }
        };
    }

    if let Some(identity_bytes) =
        rpc_map_value(map, "blackhole_identity").and_then(|v| v.as_slice())
    {
        return rpc_blackhole_identity(identity_bytes, map, handler.as_deref_mut());
    }

    if let Some(identity_bytes) =
        rpc_map_value(map, "unblackhole_identity").and_then(|v| v.as_slice())
    {
        return rpc_unblackhole_identity(identity_bytes, handler.as_deref_mut());
    }

    if rpc_map_value(map, "destination_data").is_some()
        || rpc_map_value(map, "identity_data").is_some()
    {
        return Value::Boolean(false);
    }

    log::warn!("rpc: unsupported RPC request {:?}", request);
    Value::Boolean(false)
}

pub(super) fn rpc_path_table(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Array(vec![]);
    };
    let path_table = handler.send_ctx.path_table.read().unwrap();
    let now = std::time::Instant::now();
    let entries: Vec<Value> = path_table
        .entries()
        .map(|(hash, entry)| {
            let expires_secs = if entry.expires > now {
                (entry.expires - now).as_secs_f64()
            } else {
                0.0
            };
            Value::Map(vec![
                (Value::from("hash"), Value::Binary(hash.as_slice().to_vec())),
                (Value::from("hops"), Value::from(entry.hops as u64)),
                (
                    Value::from("via"),
                    Value::Binary(entry.received_from.as_slice().to_vec()),
                ),
                (
                    Value::from("interface"),
                    Value::Binary(entry.iface.as_slice().to_vec()),
                ),
                (Value::from("expires"), Value::from(expires_secs)),
            ])
        })
        .collect();
    Value::Array(entries)
}

pub(super) fn rpc_rate_table(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Array(vec![]);
    };
    let tok_now = time::Instant::now();
    let entries: Vec<Value> = handler
        .announce_limits
        .entries()
        .map(|(hash, entry)| {
            let last_secs = if tok_now > entry.last_announce {
                (tok_now - entry.last_announce).as_secs_f64()
            } else {
                0.0
            };
            let blocked_secs = if entry.blocked_until > tok_now {
                (entry.blocked_until - tok_now).as_secs_f64()
            } else {
                0.0
            };
            Value::Map(vec![
                (Value::from("hash"), Value::Binary(hash.as_slice().to_vec())),
                (Value::from("last"), Value::from(last_secs)),
                (
                    Value::from("rate_violations"),
                    Value::from(entry.violations as u64),
                ),
                (Value::from("blocked_until"), Value::from(blocked_secs)),
            ])
        })
        .collect();
    Value::Array(entries)
}

pub(super) fn rpc_blackholed_identities(handler: Option<&mut TransportHandler>) -> Value {
    match handler {
        Some(handler) => handler.blackhole_table.to_msgpack(),
        None => Value::Map(vec![]),
    }
}

pub(super) fn rpc_is_blackholed(
    map: &[(Value, Value)],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    if let Some(identity_bytes) =
        rpc_map_value(map, "identity_hash").and_then(|v| v.as_slice())
    {
        let identity_hash = AddressHash::new_from_slice(identity_bytes);
        Value::Boolean(handler.blackhole_table.contains(&identity_hash))
    } else {
        Value::Boolean(false)
    }
}

pub(super) fn rpc_drop_path(map: &[(Value, Value)], handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    let Some(destination) = rpc_destination_hash(map) else {
        return Value::Boolean(false);
    };
    let removed = handler
        .send_ctx
        .path_table
        .write()
        .unwrap()
        .remove(&destination);
    Value::Boolean(removed)
}

pub(super) fn rpc_drop_all_via(
    map: &[(Value, Value)],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::from(0);
    };
    let Some(via) = rpc_destination_hash(map) else {
        return Value::from(0);
    };
    let count = handler
        .send_ctx
        .path_table
        .write()
        .unwrap()
        .drop_all_via(&via);
    Value::from(count as u64)
}

pub(super) fn rpc_drop_announce_queues(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::from(0);
    };
    handler.announce_table.clear();
    Value::from(0)
}

pub(super) fn rpc_blackhole_identity(
    identity_bytes: &[u8],
    map: &[(Value, Value)],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    if identity_bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return Value::Boolean(false);
    }
    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(identity_bytes);
    let identity_hash = AddressHash::new(hash);

    let until = rpc_map_value(map, "duration")
        .and_then(|v| v.as_f64())
        .map(|secs| time::Instant::now() + time::Duration::from_secs_f64(secs));
    let reason = rpc_map_value(map, "reason")
        .and_then(|v| v.as_str())
        .map(|s| s.to_owned());

    let source = *handler.config.identity.address_hash();
    let added = handler
        .blackhole_table
        .add(identity_hash, source, until, reason);
    let removed = handler.remove_blackholed_paths();
    log::info!(
        "rpc: blackholed identity {}, removed {} path{}",
        identity_hash,
        removed,
        if removed == 1 { "" } else { "s" },
    );
    Value::Boolean(added)
}

pub(super) fn rpc_unblackhole_identity(
    identity_bytes: &[u8],
    handler: Option<&mut TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::Boolean(false);
    };
    if identity_bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return Value::Boolean(false);
    }
    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(identity_bytes);
    let identity_hash = AddressHash::new(hash);
    let removed = handler.blackhole_table.remove(&identity_hash);
    if removed {
        log::info!(
            "rpc: lifted blackhole for identity {}",
            identity_hash,
        );
    }
    Value::Boolean(removed)
}

/// Answer a `first_hop_timeout` request.
///
/// The reference answers this per destination
/// (`{"get": "first_hop_timeout", "destination_hash": ...}`) and includes the
/// time a full-size packet needs to leave over the next hop. We used to return
/// a flat per-hop constant and ignored the destination entirely, so a Python
/// client budgeting a link over a slow interface got a figure too small by the
/// whole first-hop transmission time.
pub(super) fn rpc_first_hop_timeout(map: &[(Value, Value)], handler: Option<&TransportHandler>) -> Value {
    let first_hop = handler.and_then(|handler| {
        let destination = rpc_destination_hash(map)?;
        handler
            .send_ctx
            .path_table
            .read()
            .unwrap()
            .next_hop_iface(&destination)
    });

    // This runs on the synchronous RPC path, so the interface lock is taken
    // opportunistically; if it is held, the latency term is skipped rather
    // than blocking the RPC listener.
    let latency = match handler.and_then(|h| h.send_ctx.iface_manager.try_lock().ok()) {
        Some(ifaces) => first_hop_transmission_secs(&ifaces, first_hop),
        None => 0.0,
    };

    // Kept as an integer when there is no latency term, so the encoding for the
    // common case is unchanged; a float only appears where the reference would
    // have produced one anyway.
    if latency > 0.0 {
        Value::from(latency + DEFAULT_PER_HOP_TIMEOUT_SECS as f64)
    } else {
        Value::from(DEFAULT_PER_HOP_TIMEOUT_SECS)
    }
}

pub(super) fn rpc_next_hop(map: &[(Value, Value)], handler: Option<&TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Nil;
    };
    let Some(destination) = rpc_destination_hash(map) else {
        return Value::Nil;
    };

    handler
        .send_ctx
        .path_table
        .read()
        .unwrap()
        .next_hop(&destination)
        .map(|next_hop| Value::Binary(next_hop.as_slice().to_vec()))
        .unwrap_or(Value::Nil)
}

pub(super) fn rpc_next_hop_if_name(
    map: &[(Value, Value)],
    handler: Option<&TransportHandler>,
) -> Value {
    let Some(handler) = handler else {
        return Value::from("None");
    };
    let Some(destination) = rpc_destination_hash(map) else {
        return Value::from("None");
    };

    handler
        .send_ctx
        .path_table
        .read()
        .unwrap()
        .next_hop_iface(&destination)
        .map(|iface| iface.to_string())
        .map(Value::from)
        .unwrap_or_else(|| Value::from("None"))
}

pub(super) fn rpc_destination_hash(map: &[(Value, Value)]) -> Option<AddressHash> {
    let value = rpc_map_value(map, "destination_hash")?;
    let bytes = value.as_slice()?;
    if bytes.len() != crate::hash::ADDRESS_HASH_SIZE {
        return None;
    }

    let mut hash = [0u8; crate::hash::ADDRESS_HASH_SIZE];
    hash.copy_from_slice(bytes);
    Some(AddressHash::new(hash))
}

pub(super) fn rpc_interfaces(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Array(vec![]);
    };
    let iface_manager = match handler.send_ctx.iface_manager.try_lock() {
        Ok(mgr) => mgr,
        Err(_) => return Value::Array(vec![]),
    };
    let entries: Vec<Value> = iface_manager
        .interface_info_list()
        .into_iter()
        .map(|info| {
            Value::Map(vec![
                (Value::from("type"), Value::from(info.interface_type)),
                (Value::from("name"), Value::from(info.name)),
                (
                    Value::from("identity"),
                    Value::Binary(info.address.as_slice().to_vec()),
                ),
                (Value::from("error_count"), Value::from(info.error_count)),
                (Value::from("mode"), Value::from(info.mode.as_str())),
            ])
        })
        .collect();
    Value::Array(entries)
}

pub(super) fn rpc_interface_stats(handler: Option<&mut TransportHandler>) -> Value {
    let Some(handler) = handler else {
        return Value::Map(vec![
            (Value::from("interfaces"), Value::Array(vec![])),
            (Value::from("rxb"), Value::from(0)),
            (Value::from("txb"), Value::from(0)),
            (Value::from("rxs"), Value::from(0)),
            (Value::from("txs"), Value::from(0)),
            (Value::from("rss"), Value::Nil),
        ]);
    };

    // Snapshot per-interface statistics.  The interface manager lock is
    // acquired synchronously (best-effort); on contention we fall back to an
    // empty interface list rather than blocking the RPC handler.
    let iface_manager = handler.send_ctx.iface_manager.clone();
    let stats = match iface_manager.try_lock() {
        Ok(mgr) => mgr.interface_stats_list(),
        Err(_) => Vec::new(),
    };

    let mut total_txb: u64 = 0;
    let mut total_rxb: u64 = 0;
    let interfaces: Vec<Value> = stats
        .into_iter()
        .map(|s| {
            total_txb += s.bytes_tx;
            total_rxb += s.bytes_rx;
            Value::Map(vec![
                (Value::from("name"), Value::from(s.name)),
                (Value::from("type"), Value::from(s.interface_type)),
                (Value::from("address"), Value::from(s.address.to_hex_string())),
                (Value::from("mode"), Value::from(s.mode.as_str())),
                (Value::from("status"), Value::Boolean(true)),
                (Value::from("clients"), Value::Nil),
                (Value::from("error_count"), Value::from(s.error_count)),
                (Value::from("packets_tx"), Value::from(s.packets_tx)),
                (Value::from("packets_rx"), Value::from(s.packets_rx)),
                (Value::from("txb"), Value::from(s.bytes_tx)),
                (Value::from("rxb"), Value::from(s.bytes_rx)),
                (Value::from("txbuffered"), Value::from(s.tx_queue as u64)),
                (Value::from("announce_queue"), Value::from(s.announce_queue as u64)),
                (Value::from("channel_load"), Value::from(s.channel_load)),
                (Value::from("gravity"), Value::from(s.gravity)),
                (
                    Value::from("bitrate"),
                    s.bitrate.map(Value::from).unwrap_or(Value::Nil),
                ),
                (
                    Value::from("mtu"),
                    s.mtu.map(|m| Value::from(m as u64)).unwrap_or(Value::Nil),
                ),
            ])
        })
        .collect();

    let rss = handler
        .last_rssi
        .map(|v| Value::from(v as i64))
        .unwrap_or(Value::Nil);

    Value::Map(vec![
        (Value::from("interfaces"), Value::Array(interfaces)),
        (Value::from("rxb"), Value::from(total_rxb)),
        (Value::from("txb"), Value::from(total_txb)),
        (Value::from("rxs"), Value::from(0)),
        (Value::from("txs"), Value::from(0)),
        (Value::from("rss"), rss),
    ])
}

pub(super) fn rpc_map_str<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a str> {
    rpc_map_value(map, name).and_then(Value::as_str)
}

pub(super) fn rpc_map_value<'a>(map: &'a [(Value, Value)], name: &str) -> Option<&'a Value> {
    map.iter()
        .find_map(|(key, value)| (key.as_str() == Some(name)).then_some(value))
}

pub(super) fn read_rpc_value(data: &[u8]) -> Result<Value, String> {
    read_msgpack_value(data).or_else(|msgpack_error| {
        read_python_pickle_value(data).map_err(|pickle_error| {
            format!(
                "unsupported RPC payload: MessagePack decode failed: {msgpack_error}; pickle decode failed: {pickle_error}"
            )
        })
    })
}

pub(super) fn read_msgpack_value(data: &[u8]) -> Result<Value, String> {
    let mut cursor = std::io::Cursor::new(data);
    let value = read_value(&mut cursor).map_err(|error| error.to_string())?;
    if cursor.position() as usize != data.len() {
        return Err("MessagePack payload has trailing bytes".into());
    }
    Ok(value)
}

pub(super) fn write_rpc_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::new();
    write_value(&mut encoded, value).map_err(|error| error.to_string())?;
    Ok(encoded)
}

pub(super) enum PickleStackItem {
    Mark,
    Value(Value),
}

pub(super) fn read_python_pickle_value(data: &[u8]) -> Result<Value, String> {
    let mut index = 0usize;
    let mut stack = Vec::<PickleStackItem>::new();

    while index < data.len() {
        let opcode = data[index];
        index += 1;

        match opcode {
            0x80 => {
                index = index
                    .checked_add(1)
                    .filter(|index| *index <= data.len())
                    .ok_or_else(|| "pickle protocol opcode is truncated".to_string())?;
            }
            0x95 => {
                index = index
                    .checked_add(8)
                    .filter(|index| *index <= data.len())
                    .ok_or_else(|| "pickle frame opcode is truncated".to_string())?;
            }
            b'}' => stack.push(PickleStackItem::Value(Value::Map(vec![]))),
            b'(' => stack.push(PickleStackItem::Mark),
            0x94 => {}
            0x8c => {
                let len = read_pickle_u8(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                let value = std::str::from_utf8(bytes)
                    .map_err(|error| error.to_string())
                    .map(Value::from)?;
                stack.push(PickleStackItem::Value(value));
            }
            b'X' => {
                let len = read_pickle_u32_le(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                let value = std::str::from_utf8(bytes)
                    .map_err(|error| error.to_string())
                    .map(Value::from)?;
                stack.push(PickleStackItem::Value(value));
            }
            b'C' => {
                let len = read_pickle_u8(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                stack.push(PickleStackItem::Value(Value::Binary(bytes.to_vec())));
            }
            b'B' => {
                let len = read_pickle_u32_le(data, &mut index)? as usize;
                let bytes = read_pickle_bytes(data, &mut index, len)?;
                stack.push(PickleStackItem::Value(Value::Binary(bytes.to_vec())));
            }
            b'N' => stack.push(PickleStackItem::Value(Value::Nil)),
            0x88 => stack.push(PickleStackItem::Value(Value::Boolean(true))),
            0x89 => stack.push(PickleStackItem::Value(Value::Boolean(false))),
            b']' => stack.push(PickleStackItem::Value(Value::Array(vec![]))),
            b'K' => stack.push(PickleStackItem::Value(Value::from(read_pickle_u8(
                data, &mut index,
            )?))),
            b'M' => stack.push(PickleStackItem::Value(Value::from(read_pickle_u16_le(
                data, &mut index,
            )?))),
            b'J' => stack.push(PickleStackItem::Value(Value::from(read_pickle_i32_le(
                data, &mut index,
            )?))),
            b'u' => pickle_set_items(&mut stack)?,
            b's' => pickle_set_item(&mut stack)?,
            b'.' => {
                let Some(PickleStackItem::Value(value)) = stack.pop() else {
                    return Err("pickle did not end with a value".into());
                };
                return Ok(value);
            }
            opcode => {
                return Err(format!("unsupported pickle opcode 0x{opcode:02x}"));
            }
        }
    }

    Err("pickle ended without STOP opcode".into())
}

#[cfg(test)]
pub(super) fn write_python_pickle_value(value: &Value) -> Result<Vec<u8>, String> {
    let mut encoded = vec![0x80, 0x05];
    write_python_pickle_payload(&mut encoded, value)?;
    encoded.push(b'.');
    Ok(encoded)
}

#[cfg(test)]
pub(super) fn write_python_pickle_payload(encoded: &mut Vec<u8>, value: &Value) -> Result<(), String> {
    match value {
        Value::Nil => encoded.push(b'N'),
        Value::Boolean(false) => encoded.push(0x89),
        Value::Boolean(true) => encoded.push(0x88),
        Value::Integer(integer) => {
            if let Some(value) = integer.as_u64() {
                if value <= u8::MAX as u64 {
                    encoded.push(b'K');
                    encoded.push(value as u8);
                } else if value <= u16::MAX as u64 {
                    encoded.push(b'M');
                    encoded.extend_from_slice(&(value as u16).to_le_bytes());
                } else if value <= i32::MAX as u64 {
                    encoded.push(b'J');
                    encoded.extend_from_slice(&(value as i32).to_le_bytes());
                } else {
                    return Err("integer response is too large for pickle encoder".into());
                }
            } else if let Some(value) = integer.as_i64() {
                if (i32::MIN as i64..=i32::MAX as i64).contains(&value) {
                    encoded.push(b'J');
                    encoded.extend_from_slice(&(value as i32).to_le_bytes());
                } else {
                    return Err("integer response is too large for pickle encoder".into());
                }
            }
        }
        Value::String(string) => {
            let Some(string) = string.as_str() else {
                return Err("invalid string response".into());
            };
            let bytes = string.as_bytes();
            if bytes.len() <= u8::MAX as usize {
                encoded.push(0x8c);
                encoded.push(bytes.len() as u8);
            } else {
                encoded.push(b'X');
                encoded.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            }
            encoded.extend_from_slice(bytes);
            encoded.push(0x94);
        }
        Value::Binary(bytes) => {
            if bytes.len() <= u8::MAX as usize {
                encoded.push(b'C');
                encoded.push(bytes.len() as u8);
            } else {
                encoded.push(b'B');
                encoded.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
            }
            encoded.extend_from_slice(bytes);
            encoded.push(0x94);
        }
        Value::Array(values) => {
            encoded.push(b']');
            encoded.push(0x94);
            if !values.is_empty() {
                encoded.push(b'(');
                for value in values {
                    write_python_pickle_payload(encoded, value)?;
                }
                encoded.push(b'e');
            }
        }
        Value::Map(values) => {
            encoded.push(b'}');
            encoded.push(0x94);
            if !values.is_empty() {
                encoded.push(b'(');
                for (key, value) in values {
                    write_python_pickle_payload(encoded, key)?;
                    write_python_pickle_payload(encoded, value)?;
                }
                encoded.push(b'u');
            }
        }
        _ => return Err("unsupported RPC response type".into()),
    }

    Ok(())
}

pub(super) fn pickle_set_items(stack: &mut Vec<PickleStackItem>) -> Result<(), String> {
    let mark_index = stack
        .iter()
        .rposition(|item| matches!(item, PickleStackItem::Mark))
        .ok_or_else(|| "pickle SETITEMS without MARK".to_string())?;
    let values = stack.split_off(mark_index + 1);
    stack.pop();

    let Some(PickleStackItem::Value(Value::Map(map))) = stack.last_mut() else {
        return Err("pickle SETITEMS target is not a dict".into());
    };
    let mut values = values.into_iter();
    while let Some(key) = values.next() {
        let Some(value) = values.next() else {
            return Err("pickle SETITEMS has odd item count".into());
        };
        let PickleStackItem::Value(key) = key else {
            return Err("pickle SETITEMS key is MARK".into());
        };
        let PickleStackItem::Value(value) = value else {
            return Err("pickle SETITEMS value is MARK".into());
        };
        map.push((key, value));
    }

    Ok(())
}

pub(super) fn pickle_set_item(stack: &mut Vec<PickleStackItem>) -> Result<(), String> {
    let Some(PickleStackItem::Value(value)) = stack.pop() else {
        return Err("pickle SETITEM missing value".into());
    };
    let Some(PickleStackItem::Value(key)) = stack.pop() else {
        return Err("pickle SETITEM missing key".into());
    };
    let Some(PickleStackItem::Value(Value::Map(map))) = stack.last_mut() else {
        return Err("pickle SETITEM target is not a dict".into());
    };
    map.push((key, value));
    Ok(())
}

pub(super) fn read_pickle_bytes<'a>(
    data: &'a [u8],
    index: &mut usize,
    len: usize,
) -> Result<&'a [u8], String> {
    let end = index
        .checked_add(len)
        .filter(|end| *end <= data.len())
        .ok_or_else(|| "pickle byte payload is truncated".to_string())?;
    let bytes = &data[*index..end];
    *index = end;
    Ok(bytes)
}

pub(super) fn read_pickle_u8(data: &[u8], index: &mut usize) -> Result<u8, String> {
    let bytes = read_pickle_bytes(data, index, 1)?;
    Ok(bytes[0])
}

pub(super) fn read_pickle_u16_le(data: &[u8], index: &mut usize) -> Result<u16, String> {
    let bytes = read_pickle_bytes(data, index, 2)?;
    Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
}

pub(super) fn read_pickle_u32_le(data: &[u8], index: &mut usize) -> Result<u32, String> {
    let bytes = read_pickle_bytes(data, index, 4)?;
    Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) fn read_pickle_i32_le(data: &[u8], index: &mut usize) -> Result<i32, String> {
    let bytes = read_pickle_bytes(data, index, 4)?;
    Ok(i32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

pub(super) async fn read_py_connection_frame_if_ready(
    stream: &mut TcpStream,
    max_size: usize,
    timeout: Duration,
) -> Result<Option<Vec<u8>>, String> {
    match time::timeout(timeout, stream.readable()).await {
        Ok(Ok(())) => {}
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Ok(None),
    }

    let mut header = [0u8; 4];
    let peeked = stream
        .peek(&mut header)
        .await
        .map_err(|error| error.to_string())?;
    if peeked < header.len() {
        return Ok(None);
    }

    let size = i32::from_be_bytes(header);
    if !(0..=max_size as i32).contains(&size) {
        return Ok(None);
    }

    read_py_connection_frame(stream, max_size).await.map(Some)
}

pub(super) async fn read_py_connection_frame(
    stream: &mut TcpStream,
    max_size: usize,
) -> Result<Vec<u8>, String> {
    let mut header = [0u8; 4];
    stream
        .read_exact(&mut header)
        .await
        .map_err(|error| error.to_string())?;

    let size = i32::from_be_bytes(header);
    let size = if size == -1 {
        let mut long_header = [0u8; 8];
        stream
            .read_exact(&mut long_header)
            .await
            .map_err(|error| error.to_string())?;
        u64::from_be_bytes(long_header)
            .try_into()
            .map_err(|_| "frame is too large".to_string())?
    } else if size >= 0 {
        size as usize
    } else {
        return Err("invalid frame length".into());
    };

    if size > max_size {
        return Err(format!("frame length {size} exceeds maximum {max_size}"));
    }

    let mut data = vec![0u8; size];
    stream
        .read_exact(&mut data)
        .await
        .map_err(|error| error.to_string())?;
    Ok(data)
}

pub(super) async fn write_py_connection_frame(stream: &mut TcpStream, data: &[u8]) -> Result<(), String> {
    let len = i32::try_from(data.len()).map_err(|_| "frame is too large".to_string())?;
    stream
        .write_all(&len.to_be_bytes())
        .await
        .map_err(|error| error.to_string())?;
    stream
        .write_all(data)
        .await
        .map_err(|error| error.to_string())?;
    stream.flush().await.map_err(|error| error.to_string())
}
