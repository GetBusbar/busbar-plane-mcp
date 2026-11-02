// SPDX-License-Identifier: Apache-2.0
//! MCP's actual HTTP/stdio transport composition and local TLS tool catalogue.
use busbar_contract::conn::{ConnWake, DeclaredConns};
use busbar_contract::transport::{EgressTrust, TransportSettings};
use busbar_core_connector::doors::Dispatched;
use busbar_core_connector::registry::{Entry, Transports};
use busbar_core_connector::{Connector, Judged, Verdict};
use busbar_plugin_loader::dispatch::kinds::transport::Transport;
use busbar_plugin_loader::dispatch::{
    load_linked, Bind, ConnTable, DispatchConfig, Dispatcher, LinkedRow, NoSink,
};
use std::io::{Read, Write};
use std::net::{TcpListener, ToSocketAddrs};
use std::sync::{Arc, OnceLock};

struct Catalogue {
    authority: String,
    pem: String,
    der: Vec<u8>,
}
fn catalogue() -> &'static Catalogue {
    static CATALOGUE: OnceLock<Catalogue> = OnceLock::new();
    CATALOGUE.get_or_init(|| {
        let certificate = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("MCP TLS identity");
        let der = certificate.cert.der().to_vec();
        let pem = certificate.cert.pem();
        let key =
            rustls::pki_types::PrivatePkcs8KeyDer::from(certificate.signing_key.serialize_der());
        let tls = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![certificate.cert.der().clone()], key.into())
        .expect("MCP TLS server");
        let tls = Arc::new(tls);
        let listener = TcpListener::bind("127.0.0.1:0").expect("MCP catalogue listener");
        let authority = format!("localhost:{}", listener.local_addr().unwrap().port());
        std::thread::spawn(move || {
            for tcp in listener.incoming() {
                let tcp = tcp.expect("MCP catalogue accepts");
                tcp.set_read_timeout(Some(std::time::Duration::from_secs(30)))
                    .unwrap();
                tcp.set_write_timeout(Some(std::time::Duration::from_secs(30)))
                    .unwrap();
                let tls = Arc::clone(&tls);
                std::thread::spawn(move || {
                    let connection =
                        rustls::ServerConnection::new(tls).expect("MCP server session");
                    let mut stream = rustls::StreamOwned::new(connection, tcp);
                    let mut seen = Vec::new();
                    let mut bytes = [0; 4096];
                    loop {
                        if let Some(reply) = server(&seen) {
                            stream.write_all(&reply).expect("MCP catalogue reply");
                            stream.flush().expect("MCP catalogue flush");
                            stream.conn.send_close_notify();
                            let _ = stream.flush();
                            return;
                        }
                        match stream.read(&mut bytes) {
                            Ok(0) | Err(_) => return,
                            Ok(n) => seen.extend_from_slice(&bytes[..n]),
                        }
                    }
                });
            }
        });
        Catalogue {
            authority,
            pem,
            der,
        }
    })
}
pub fn authority() -> &'static str {
    &catalogue().authority
}
pub fn anchors() -> &'static str {
    &catalogue().pem
}
pub fn peer_key_pin() -> String {
    busbar_core_connector::tls::client::peer_key_pin(&catalogue().der).expect("MCP leaf SPKI")
}
fn reactor() -> tokio::runtime::Handle {
    static IO: OnceLock<tokio::runtime::Handle> = OnceLock::new();
    IO.get_or_init(|| {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("MCP I/O reactor");
        let handle = runtime.handle().clone();
        std::thread::spawn(move || runtime.block_on(std::future::pending::<()>()));
        handle
    })
    .clone()
}
pub fn host(wake: ConnWake, anchors: Option<&str>) -> Arc<dyn DeclaredConns> {
    if let Some(anchors) = anchors {
        assert_eq!(anchors, self::anchors());
    }
    busbar_core_connector::io::install_process_reactor(reactor());
    let dispatcher = Arc::new(Dispatcher::new(DispatchConfig::default()));
    dispatcher.install_runtime(reactor());
    dispatcher.install_io(busbar_core_connector::hostio::process());
    let doors: [(&str, busbar_contract::abi::mechanism::door::DoorFn); 3] = [
        ("tcp", busbar_transport_tcp::linked::door),
        ("http", busbar_transport_http::door::door),
        ("stdio", busbar_transport_stdio::door::door),
    ];
    let entries = doors
        .into_iter()
        .map(|(name, door)| {
            let plugin = load_linked::<Transport>(
                &LinkedRow::of(door).expect("real transport Statement"),
                Bind {
                    instance: Arc::from(format!("mcp-catalogue-{name}")),
                    max_inflight_cap: 1024,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns: ConnTable::NoNeeds,
                },
            )
            .expect("real MCP transport loads");
            let transport =
                Dispatched::open_on(plugin, &TransportSettings::default(), dispatcher.clone())
                    .expect("real MCP transport opens");
            Entry {
                door: Arc::new(transport),
                alpn: Vec::new(),
            }
        })
        .collect();
    let transports = Transports::new(entries).expect("MCP TCP/HTTP/stdio compose");
    let trust = EgressTrust {
        extra_anchors: vec![catalogue().der.clone()],
        ..Default::default()
    };
    let tls = busbar_core_connector::tls::client::build_client_config(&trust).expect("MCP trust");
    let judge = |target: &str,
                 _class: u32,
                 _done: Judged|
     -> Option<Result<std::net::SocketAddr, Verdict>> {
        Some(
            target
                .to_socket_addrs()
                .ok()
                .and_then(|mut addresses| addresses.find(|a| a.ip().is_loopback()))
                .ok_or(busbar_contract::abi::host::service::DEST_UNRESOLVABLE),
        )
    };
    Arc::new(Connector::serving(
        transports,
        Arc::new(judge),
        Some(Arc::new(tls)),
        wake,
    ))
}

fn server(seen: &[u8]) -> Option<Vec<u8>> {
    let end = seen.windows(4).position(|w| w == b"\r\n\r\n")? + 4;
    let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
    let len = head
        .lines()
        .find_map(|l| l.strip_prefix("content-length:"))
        .and_then(|n| n.trim().parse::<usize>().ok())
        .unwrap_or(0);
    if seen.len() < end + len {
        return None;
    }
    let asked: serde_json::Value =
        serde_json::from_slice(&seen[end..end + len]).unwrap_or(serde_json::Value::Null);
    let reply = serde_json::json!({
        "jsonrpc": "2.0",
        "id": asked["id"],
        "result": {"tools": [{
            "name": "read_file",
            "inputSchema": {"type": "object", "properties": {"path": {"type": "string", "x-mcp-header": "Path"}}}
        }]}
    })
    .to_string();
    let mut out = format!(
        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\r\n",
        reply.len()
    )
    .into_bytes();
    out.extend_from_slice(reply.as_bytes());
    Some(out)
}
