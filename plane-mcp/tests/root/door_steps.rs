// SPDX-License-Identifier: Apache-2.0
// Copyright (C) 2026 Busbar Inc and contributors

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod tool_door {
    use std::collections::BTreeMap;
    use std::sync::Arc;

    use axum::http::StatusCode;
    use busbar_contract::abi::mechanism::door::DoorFn;
    use busbar_contract::caps::ReasonCode;
    use busbar_contract::conn::{DeclaredConns, PollConns};
    use busbar_kernel::cost::CostModel;
    use busbar_kernel::governance::signing::{TokenSigner, DEFAULT_KID};
    use busbar_kernel::governance::{GovState, NewKeySpec};
    use busbar_kernel::plane_driver::{refusal_status, EndPost, PlaneMoney};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use crate::root::loader::dispatch::kinds::plane::Plane;
    use crate::root::loader::dispatch::{
        load_linked, Bind, DispatchConfig, Dispatcher, LinkedRow, NoSink,
    };
    use crate::root::plane_node::{Node, NodeEndPost};
    use crate::root::serve::planes_tests::{composed_services, money, PUBLISHING};
    use crate::root::serve::{compose_planes, door_routes};

    static CARD: std::sync::LazyLock<crate::root::kernel::RootHistory> =
        std::sync::LazyLock::new(|| {
            let holder = crate::root::kernel::RootHistory::default();
            holder.apply(
                crate::root::kernel::card_from_config(
                    std::iter::empty::<(&str, busbar_contract::billing::RawTierRates)>(),
                    0,
                    true,
                ),
                1_000,
            );
            holder
        });

    pub(crate) const ADMIN_TOKEN: &str = "admintok";

    pub(crate) const PUBLIC_URL: &str = "http://127.0.0.1";

    pub(crate) fn surface(key: &str) -> &'static str {
        include_str!("fixtures/tool_door_wire.txt")
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .find_map(|l| {
                let (k, v) = l.split_once('=')?;
                (k.trim() == key).then(|| v.trim())
            })
            .unwrap_or_else(|| panic!("fixtures/tool_door_wire.txt has no `{key}` row"))
    }

    pub(crate) fn sentence(key: &str) -> String {
        surface(key).replace("{PLANE}", &surface("plane_key").to_ascii_uppercase())
    }

    pub(crate) fn endpoint_section() -> &'static str {
        surface("endpoint_section")
    }

    pub(crate) fn endpoint() -> String {
        format!("/{}", endpoint_section())
    }

    pub(crate) fn protocol_version() -> &'static str {
        surface("protocol_version")
    }

    pub(crate) fn line_door() -> DoorFn {
        static DOOR: std::sync::OnceLock<DoorFn> = std::sync::OnceLock::new();
        *DOOR.get_or_init(|| {
            #[cfg(distribution_root)]
            crate::dist_root_install::install();
            let section = endpoint_section();
            let dispatcher = Arc::new(Dispatcher::new(
                DispatchConfig::default(),
                busbar_kernel::host_services::caller_binding(),
            ));
            crate::root::connector::install_io(&dispatcher);

            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            crate::LINKED
                .plane_doors
                .iter()
                .copied()
                .find(|&door| {
                    let Ok(row) = LinkedRow::of(door) else {
                        return false;
                    };
                    load_linked::<Plane>(
                        &row,
                        Bind {
                            instance: Arc::from("line-door-probe"),
                            max_inflight_cap: 64,
                            sink: Arc::new(NoSink),
                            dispatcher: dispatcher.adopter(),
                            conns: crate::root::loader::dispatch::ConnTable::Probe,
                        },
                    )
                    .is_ok_and(|plane| plane.served().owns.contains(&section))
                })
                .expect("a linked plane door owns the endpoint section")
        })
    }

    pub(crate) const CALL: &str = r#"{"jsonrpc":"2.0","id":30,"method":"tools/call","params":{"name":"fs_read_file","arguments":{},"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    const LIST: &str = r#"{"jsonrpc":"2.0","id":9,"method":"tools/list","params":{"_meta":{"io.modelcontextprotocol/protocolVersion":"2026-07-28","io.modelcontextprotocol/clientCapabilities":{}}}}"#;

    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    pub(crate) fn section(port: u16) -> serde_yaml::Value {
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"http://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: pinned_pubkey, key: \"sha256/K=\" }}\n  \
         tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    pub(crate) const TOOL_DESCRIPTION: &str = "reads a file from disk";

    pub(crate) fn tool_schema() -> serde_json::Value {
        serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}})
    }

    pub(crate) fn tool_digest() -> String {
        surface("tool_digest").to_string()
    }

    pub(crate) fn tool_listing() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()}
        ])
    }

    pub(crate) async fn send(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
    ) -> (StatusCode, Vec<u8>) {
        send_as(router, token, body, "tools/call", Some("fs_read_file")).await
    }

    pub(crate) async fn send_as(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, Vec<u8>) {
        let (status, _, body) = send_headed(router, token, body, method, name).await;
        (status, body)
    }

    pub(crate) async fn send_headed(
        router: &axum::Router,
        token: Option<&str>,
        body: &str,
        method: &str,
        name: Option<&str>,
    ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
        use tower::ServiceExt as _;
        let mut req = axum::http::Request::builder()
            .method("POST")
            .uri(endpoint())
            .header("content-type", "application/json")
            .header("accept", "application/json")
            .header(surface("protocol_header"), protocol_version())
            .header(surface("method_header"), method);
        if let Some(name) = name {
            req = req.header(surface("name_header"), name);
        }
        if let Some(token) = token {
            req = req.header("authorization", format!("Bearer {token}"));
        }
        let req = req
            .body(axum::body::Body::from(body.to_string()))
            .expect("a request");
        let response = router
            .clone()
            .oneshot(req)
            .await
            .expect("the router answers");
        let status = response.status();
        let headers = response.headers().clone();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        (status, headers, bytes.to_vec())
    }

    pub(crate) async fn tool_server() -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_listing(Arc::new(std::sync::Mutex::new(tool_listing()))).await
    }

    pub(crate) async fn tool_server_listing(
        tools: Arc<std::sync::Mutex<serde_json::Value>>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_answering(Arc::new(move |request: &str| {
            if request.contains("\"tools/list\"") {
                let list = tools.lock().map(|t| t.clone()).unwrap_or_default();
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": list}})
                    .to_string()
            } else {
                ANSWER.to_string()
            }
        }))
        .await
    }

    pub(crate) async fn tool_server_answering(
        answer: Arc<dyn Fn(&str) -> String + Send + Sync>,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        tool_server_replying(Arc::new(move |request: &str| (200, answer(request)))).await
    }

    pub(crate) type Replies = Arc<dyn Fn(&str) -> (u16, String) + Send + Sync>;

    pub(crate) const STALL: u16 = 0;

    pub(crate) async fn tool_server_replying(
        answer: Replies,
    ) -> (u16, tokio::sync::mpsc::UnboundedReceiver<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        let port = listener.local_addr().expect("its address").port();
        let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            while let Ok((socket, _)) = listener.accept().await {
                tokio::spawn(tool_connection(socket, sent.clone(), Arc::clone(&answer)));
            }
        });
        (port, heard)
    }

    async fn tool_request<S: tokio::io::AsyncRead + Unpin>(
        socket: &mut S,
        sent: tokio::sync::mpsc::UnboundedSender<String>,
    ) -> Option<String> {
        tool_request_counted(socket, sent, None).await
    }

    async fn tool_request_counted<S: tokio::io::AsyncRead + Unpin>(
        socket: &mut S,
        sent: tokio::sync::mpsc::UnboundedSender<String>,
        count: Option<&std::sync::atomic::AtomicUsize>,
    ) -> Option<String> {
        let mut buf = vec![0u8; 16 * 1024];
        let mut got = Vec::new();
        loop {
            let n = socket.read(&mut buf).await.ok()?;
            if let Some(count) = count {
                count.fetch_add(n, std::sync::atomic::Ordering::SeqCst);
            }
            if n == 0 {
                return None;
            }
            got.extend_from_slice(&buf[..n]);
            let text = String::from_utf8_lossy(&got).to_string();
            if let Some(at) = text.find("\r\n\r\n") {
                let length = text[..at]
                    .lines()
                    .find_map(|l| {
                        let (name, value) = l.split_once(':')?;
                        name.eq_ignore_ascii_case("content-length")
                            .then(|| value.trim().parse::<usize>().ok())
                            .flatten()
                    })
                    .unwrap_or(0);
                if got.len() >= at + 4 + length {
                    let _ = sent.send(text.clone());
                    return Some(text);
                }
            }
        }
    }

    async fn tool_reply<S: tokio::io::AsyncWrite + Unpin>(
        socket: &mut S,
        status: u16,
        answer: String,
    ) {
        if status == STALL {
            tokio::time::sleep(std::time::Duration::from_secs(120)).await;
            return;
        }
        let reply = format!(
            "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\n\
             connection: close\r\n\r\n{answer}",
            answer.len()
        );
        let _ = socket.write_all(reply.as_bytes()).await;
        let _ = socket.shutdown().await;
    }

    async fn tool_connection<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        mut socket: S,
        sent: tokio::sync::mpsc::UnboundedSender<String>,
        answer: Replies,
    ) {
        if let Some(request) = tool_request(&mut socket, sent).await {
            let (status, answer) = answer(&request);
            tool_reply(&mut socket, status, answer).await;
        }
    }

    type TlsToolSocket = tokio_rustls::server::TlsStream<tokio::net::TcpStream>;
    type TlsToolHandler = Arc<
        dyn Fn(
                TlsToolSocket,
                tokio::sync::mpsc::UnboundedSender<String>,
            ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
            + Send
            + Sync,
    >;

    pub(crate) struct TlsToolServer {
        pub(crate) port: u16,
        pub(crate) heard: tokio::sync::mpsc::UnboundedReceiver<String>,
        pub(crate) pin: String,
        tls: Arc<rustls::ClientConfig>,
        pub(super) ca_der: Vec<u8>,
        pub(crate) ca_pem: String,
        pub(crate) client_cert_pem: String,
        pub(crate) client_key_pem: String,
        pub(crate) client_presented: Arc<std::sync::atomic::AtomicBool>,
        pub(crate) http_bytes: Arc<std::sync::atomic::AtomicUsize>,
        task: Option<tokio::task::JoinHandle<()>>,
    }

    impl TlsToolServer {
        pub(crate) async fn new() -> Self {
            Self::listing(Arc::new(std::sync::Mutex::new(tool_listing()))).await
        }

        pub(crate) async fn answering(answer: Arc<dyn Fn(&str) -> String + Send + Sync>) -> Self {
            Self::replying(Arc::new(move |request| (200, answer(request)))).await
        }

        pub(crate) async fn listing(tools: Arc<std::sync::Mutex<serde_json::Value>>) -> Self {
            Self::answering(Arc::new(move |request| {
                if request.contains("\"tools/list\"") {
                    let list = tools.lock().map(|t| t.clone()).unwrap_or_default();
                    serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"tools":list}}).to_string()
                } else {
                    ANSWER.to_string()
                }
            }))
            .await
        }

        pub(crate) async fn replying(answer: Replies) -> Self {
            let handler: TlsToolHandler = Arc::new(move |socket, sent| {
                Box::pin(tool_connection(socket, sent, Arc::clone(&answer)))
            });
            Self::with_handler(handler, None).await
        }

        pub(crate) async fn once() -> Self {
            let handler: TlsToolHandler = Arc::new(|socket, sent| {
                let answer: Replies = Arc::new(|request| {
                    (
                        200,
                        if request.contains("\"tools/list\"") {
                            serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"tools":tool_listing()}}).to_string()
                        } else {
                            ANSWER.to_string()
                        },
                    )
                });
                Box::pin(tool_connection(socket, sent, answer))
            });
            Self::with_handler(handler, Some(1)).await
        }

        pub(crate) async fn gated(
            release: tokio::sync::watch::Receiver<bool>,
            answer: impl Into<String>,
        ) -> Self {
            let answer = answer.into();
            let handler: TlsToolHandler = Arc::new(move |mut socket, sent| {
                let mut release = release.clone();
                let answer = answer.clone();
                Box::pin(async move {
                    let Some(request) = tool_request(&mut socket, sent).await else {
                        return;
                    };
                    let answer = if request.contains("\"tools/list\"") {
                        serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"tools":tool_listing()}}).to_string()
                    } else {
                        let _ = release.wait_for(|ready| *ready).await;
                        answer
                    };
                    tool_reply(&mut socket, 200, answer).await;
                })
            });
            Self::with_handler(handler, None).await
        }

        pub(crate) async fn member_ca_fixture(name: &str, expired: bool, mutual: bool) -> Self {
            Self::member_ca_fixture_gate(name, expired, mutual, None).await
        }

        pub(crate) async fn member_ca_gated(release: tokio::sync::watch::Receiver<bool>) -> Self {
            Self::member_ca_fixture_gate("127.0.0.1", false, false, Some(release)).await
        }

        async fn member_ca_fixture_gate(
            name: &str,
            expired: bool,
            mutual: bool,
            gate: Option<tokio::sync::watch::Receiver<bool>>,
        ) -> Self {
            let answer: Replies = Arc::new(|request| {
                (
                    200,
                    if request.contains("\"tools/list\"") {
                        serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"tools":tool_listing()}}).to_string()
                    } else {
                        ANSWER.to_string()
                    },
                )
            });
            let http_bytes = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let count = Arc::clone(&http_bytes);
            let handler: TlsToolHandler = Arc::new(move |mut socket, sent| {
                let answer = Arc::clone(&answer);
                let count = Arc::clone(&count);
                let gate = gate.clone();
                Box::pin(async move {
                    if let Some(request) =
                        tool_request_counted(&mut socket, sent, Some(&count)).await
                    {
                        if request.contains("\"tools/call\"") {
                            if let Some(mut gate) = gate {
                                drop(
                                    gate.wait_for(|ready| *ready)
                                        .await
                                        .expect("old response release remains alive"),
                                );
                            }
                        }
                        let (status, body) = answer(&request);
                        tool_reply(&mut socket, status, body).await;
                    }
                })
            });
            let mut fixture =
                Self::with_handler_security(handler, None, name, expired, mutual).await;
            fixture.http_bytes = http_bytes;
            fixture
        }

        async fn with_handler(handler: TlsToolHandler, limit: Option<usize>) -> Self {
            Self::with_handler_security(handler, limit, "127.0.0.1", false, false).await
        }

        async fn with_handler_security(
            handler: TlsToolHandler,
            limit: Option<usize>,
            name: &str,
            expired: bool,
            mutual: bool,
        ) -> Self {
            use rcgen::PublicKeyData as _;
            busbar_core_connector::tls::install_crypto_provider();
            let ca_key = rcgen::KeyPair::generate().expect("a CA key");
            let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("CA params");
            ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).expect("the CA");
            let issuer = rcgen::Issuer::new(ca_params, ca_key);
            let leaf_key = rcgen::KeyPair::generate().expect("a leaf key");
            let mut params = rcgen::CertificateParams::new(vec![name.into()]).expect("server SAN");
            if expired {
                params.not_before = rcgen::date_time_ymd(2000, 1, 1);
                params.not_after = rcgen::date_time_ymd(2001, 1, 1);
            }
            let leaf = params.signed_by(&leaf_key, &issuer).expect("the leaf");
            let client_key = rcgen::KeyPair::generate().expect("client key");
            let client = rcgen::CertificateParams::new(vec!["member-client".into()])
                .unwrap()
                .signed_by(&client_key, &issuer)
                .expect("client certificate");
            let pin =
                busbar_contract::transport::trust::key_pin(&leaf_key.subject_public_key_info());
            let builder = rustls::ServerConfig::builder();
            let builder = if mutual {
                let mut roots = rustls::RootCertStore::empty();
                roots.add(ca.der().clone()).expect("client root");
                builder.with_client_cert_verifier(
                    rustls::server::WebPkiClientVerifier::builder(Arc::new(roots))
                        .build()
                        .unwrap(),
                )
            } else {
                builder.with_no_client_auth()
            };
            let server = builder
                .with_single_cert(
                    vec![leaf.der().clone()],
                    rustls_pki_types::PrivateKeyDer::try_from(leaf_key.serialize_der())
                        .expect("leaf key"),
                )
                .expect("the TLS server");
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(server));
            let tls = busbar_core_connector::tls::client::build_client_config(
                &busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: vec![ca.der().to_vec()],
                    ..Default::default()
                },
            )
            .expect("normal certificate verification with the fixture CA added");
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("a TLS port");
            let port = listener.local_addr().unwrap().port();
            let (sent, heard) = tokio::sync::mpsc::unbounded_channel();
            let client_presented = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let observed_client = Arc::clone(&client_presented);
            let task = tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                let mut accepted = 0usize;
                while let Ok((socket, _)) = listener.accept().await {
                    let acceptor = acceptor.clone();
                    let sent = sent.clone();
                    let handler = Arc::clone(&handler);
                    let observed_client = Arc::clone(&observed_client);
                    connections.spawn(async move {
                        if let Ok(tls) = acceptor.accept(socket).await {
                            if tls
                                .get_ref()
                                .1
                                .peer_certificates()
                                .is_some_and(|chain| !chain.is_empty())
                            {
                                observed_client.store(true, std::sync::atomic::Ordering::SeqCst);
                            }
                            handler(tls, sent).await;
                        }
                    });
                    accepted += 1;
                    if limit.is_some_and(|bound| accepted >= bound) {
                        break;
                    }
                    while connections.try_join_next().is_some() {}
                }
                drop(listener);
                while connections.join_next().await.is_some() {}
            });
            Self {
                port,
                heard,
                pin,
                tls: Arc::new(tls),
                ca_der: ca.der().to_vec(),
                ca_pem: ca.pem(),
                client_cert_pem: client.pem(),
                client_key_pem: client_key.serialize_pem(),
                client_presented,
                http_bytes: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
                task: Some(task),
            }
        }

        pub(crate) fn section(&self) -> serde_yaml::Value {
            let mut value = section(self.port);
            value["fs"]["url"] =
                serde_yaml::Value::String(format!("https://127.0.0.1:{}/rpc", self.port));
            value["fs"]["pin"] = serde_yaml::to_value(serde_json::json!({
                "mechanism":"cert_spki", "key":self.pin
            }))
            .unwrap();
            value
        }

        pub(crate) fn footing(&self) -> Footing<'static> {
            Footing {
                tls: Some(Arc::clone(&self.tls)),
                ..Footing::own()
            }
        }

        pub(crate) fn footing_with_peers(&self, peers: &[&Self]) -> Footing<'static> {
            let anchors = std::iter::once(&self.ca_der)
                .chain(peers.iter().map(|p| &p.ca_der))
                .cloned()
                .collect();
            let tls = busbar_core_connector::tls::client::build_client_config(
                &busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: anchors,
                    ..Default::default()
                },
            )
            .expect("normal verification with all fixture CAs added");
            Footing {
                tls: Some(Arc::new(tls)),
                ..Footing::own()
            }
        }

        pub(crate) async fn rig(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Rig {
            self.try_rig(instance, tools, configure)
                .await
                .unwrap_or_else(|e| panic!("the TLS door composes: {e}"))
        }

        pub(crate) async fn try_rig(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Result<Rig, String> {
            self.try_rig_with_footing(instance, tools, None, self.footing(), configure)
                .await
        }

        pub(crate) async fn rig_with_footing(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Rig {
            self.try_rig_with_footing(instance, tools, None, footing, configure)
                .await
                .unwrap_or_else(|e| panic!("the TLS door composes: {e}"))
        }

        pub(crate) async fn rig_with_grants(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            allowed_pools: Option<Vec<String>>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Rig {
            self.try_rig_with_footing(instance, tools, allowed_pools, self.footing(), configure)
                .await
                .unwrap_or_else(|e| panic!("the granted TLS door composes: {e}"))
        }

        async fn try_rig_with_footing(
            &self,
            instance: &'static str,
            tools: serde_yaml::Value,
            allowed_pools: Option<Vec<String>>,
            mut footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Result<Rig, String> {
            if footing.tls.is_none() {
                footing.tls = Some(Arc::clone(&self.tls));
            }
            let row = super::door_boundary::row();
            super::door_boundary::registry(row);
            let slot = super::door_boundary::slot_over(row, tools.clone());
            Rig::try_with(
                instance,
                self.port,
                allowed_pools,
                None,
                Some(tools),
                footing,
                &|app| super::door_boundary::dispatched(configure(app), row, &slot),
            )
            .await
        }

        pub(crate) async fn close(mut self) {
            if let Some(task) = self.task.take() {
                task.abort();
                let _ = task.await;
            }
        }
    }

    impl Drop for TlsToolServer {
        fn drop(&mut self) {
            if let Some(task) = &self.task {
                task.abort();
            }
        }
    }

    async fn down_port() -> u16 {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("a loopback port");
        listener.local_addr().expect("its address").port()
    }

    pub(crate) struct Rig {
        pub(crate) router: axum::Router,

        pub(crate) admin: axum::Router,
        pub(crate) gov: Arc<GovState>,
        pub(crate) app: Arc<busbar_kernel::state::App>,
        pub(crate) key: Arc<busbar_contract::records::VirtualKey>,
        pub(crate) token: String,
        money_steps: Arc<PlaneMoney>,
        post: Arc<NodeEndPost>,
        pub(crate) book: crate::root::durability::NodeBook,
        pub(crate) plane_key: String,

        pub(crate) audience: Option<String>,

        pub(crate) store: Arc<busbar_kernel::persistence::facade::CoreStore>,

        pub(crate) tokens: Arc<super::TokenEndpoint>,

        pub(crate) door_table: Vec<(
            String,
            String,
            busbar_contract::abi::mechanism::route::RouteAuth,
        )>,

        pub(crate) plane: crate::root::boot::DoorPlane,

        pub(crate) clock: Arc<std::sync::atomic::AtomicU64>,

        pub(crate) wall: Arc<std::sync::atomic::AtomicU64>,
        pub(crate) work_observations: Arc<std::sync::Mutex<Vec<ObservedWork>>>,
        pub(crate) instance: &'static str,

        pub(crate) live: Arc<crate::root::serve::DoorApply>,
    }

    impl Rig {
        async fn new(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
        ) -> Self {
            Self::with(
                instance,
                port,
                allowed_pools,
                None,
                None,
                Footing::own(),
                &|app| app,
            )
            .await
        }

        pub(crate) async fn with(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Self {
            Self::try_with(
                instance,
                port,
                allowed_pools,
                block,
                tools,
                footing,
                configure,
            )
            .await
            .unwrap_or_else(|e| panic!("the door plane composes: {e}"))
        }

        pub(crate) async fn try_with(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Result<Self, String> {
            Self::try_with_async(
                instance,
                port,
                allowed_pools,
                block,
                tools,
                footing,
                &async |app| configure(app),
            )
            .await
        }

        pub(crate) async fn try_with_async(
            instance: &'static str,
            port: u16,
            allowed_pools: Option<Vec<String>>,
            block: Option<serde_yaml::Value>,
            tools: Option<serde_yaml::Value>,
            footing: Footing<'_>,
            configure: &impl std::ops::AsyncFn(busbar_kernel::state::App) -> busbar_kernel::state::App,
        ) -> Result<Self, String> {
            let judge = crate::root::connector::guard_for(&busbar_kernel::config::Destinations {
                block_private_addresses: footing.guarded,
                blocked: vec![BLOCKED_HOST.to_string()],
                ..Default::default()
            })
            .expect("the guard");

            let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
            let governance_store = match &footing.ledger {
                Ledger::Store(store) => store.clone(),
                Ledger::Rows(rows, _) => crate::root::real_store::core_over(rows.clone()).await,
                _ => crate::root::real_store::core().await,
            };
            let gov = Arc::new(
                GovState::new_with_core(
                    governance_store.clone(),
                    Some(ADMIN_TOKEN.to_string()),
                    Some(signer),
                )
                .await
                .expect("governance"),
            );

            let (gov, key, token) = match footing.book {
                Some(first) => (
                    Arc::clone(&first.gov),
                    Arc::clone(&first.key),
                    first.token.clone(),
                ),
                None => {
                    let (key, token) = gov
                        .mint_signed_async(
                            NewKeySpec {
                                name: "agent".to_string(),
                                allowed_pools,
                                ..Default::default()
                            },
                            4_000_000_000,
                            1_700_000_000,
                        )
                        .await
                        .expect("mint");
                    gov.hydrate_budgets_async(&CostModel::flat(1), 0)
                        .await
                        .expect("hydrate");
                    (
                        gov,
                        Arc::new(key),
                        token.expose(&busbar_kernel::seal::lend()).to_string(),
                    )
                }
            };
            let clock = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let wall = Arc::new(std::sync::atomic::AtomicU64::new(0));
            let (late, store) = records_composed(
                footing.ledger,
                Arc::clone(&gov),
                (&clock, &wall),
                Arc::clone(&judge) as Arc<dyn busbar_kernel::host_services::DestJudge>,
            );
            let work_observations = Arc::new(std::sync::Mutex::new(Vec::new()));
            let dispatcher = Arc::new(Dispatcher::with_services(
                DispatchConfig::default(),
                Arc::new(Clocked {
                    inner: late.served(),
                    wall: Arc::clone(&wall),
                    work_observations: Arc::clone(&work_observations),
                }),
                busbar_kernel::host_services::caller_binding(),
            ));

            crate::root::connector::install_io(&dispatcher);

            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());

            let connector = if let Some(tls) = &footing.tls {
                let entries = crate::root::connector::entries_on(
                    &dispatcher,
                    crate::LINKED_TRANSPORT_DOORS,
                    &busbar_contract::transport::TransportSettings::default(),
                )
                .expect("the linked transport doors open");
                Arc::new(
                    busbar_core_connector::Connector::serving(
                        busbar_core_connector::registry::Transports::new(entries)
                            .expect("the transport view"),
                        busbar_core_connector::process::judge(judge, &[]),
                        Some(Arc::clone(tls)),
                        dispatcher.conn_waker(),
                    )
                    .pooling(busbar_core_connector::pool::PoolPosture::NONE)
                    .proxying(
                        busbar_core_connector::proxy::from_env().expect("the proxy environment"),
                    )
                    .resolving_spawn_secrets(busbar_core_connector::spawn_env::linked_spawn_secret),
                )
            } else {
                busbar_core_connector::process::build_with_secrets(
                    || {
                        crate::root::connector::entries_on(
                            &dispatcher,
                            crate::LINKED_TRANSPORT_DOORS,
                            &busbar_contract::transport::TransportSettings::default(),
                        )
                    },
                    judge,
                    &[],
                    dispatcher.conn_waker(),
                    busbar_core_connector::pool::PoolPosture::NONE,
                    busbar_core_connector::spawn_env::linked_spawn_secret,
                )
                .expect("the connector builds")
            };
            let plane = bound(
                instance,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(
                    Arc::clone(&connector) as Arc<dyn DeclaredConns>,
                )),
            );
            let caller = plane.instance();
            let section_key = plane.served().section;
            assert_eq!(
                section_key,
                surface("section"),
                "the door opens with the section its grammar reads"
            );

            let node = Arc::new(Node::new());
            let journal_budget = busbar_kernel::persistence::journal::BufferBudget {
                records: 4096,
                bytes: 4 * 1024 * 1024,
            };
            let journal = busbar_kernel::persistence::journal::RuntimeJournal::open(
                store.clone(),
                busbar_kernel::door::op_id().counter(),
                journal_budget,
            )
            .await
            .expect("native node journal opens");
            let mut book = crate::root::durability::node_book(journal, journal_budget)
                .await
                .expect("native node book opens");
            let durability_token = crate::root::kernel::new_kernel().durability_token();
            Arc::get_mut(&mut book.durability)
                .expect("bootstrap owns its native book")
                .get_mut()
                .unwrap()
                .restore_amendments(gov.amendments(), &durability_token)
                .await
                .expect("restore this fixture's native amendment journal");
            crate::root::durability::bind_amendments(&book.durability, gov.amendments())
                .await
                .expect("bind content handoffs to this same native journal");
            node.bind_book(Arc::clone(&book.durability));
            let post = Arc::new(NodeEndPost::new(Arc::clone(&node)));
            let site = Arc::clone(&post);
            let book_money = Arc::clone(&gov);
            let plane_money = move || {
                Arc::new(PlaneMoney::new(
                    Arc::clone(&book_money),
                    Arc::clone(&site) as Arc<dyn EndPost>,
                ))
            };

            let mut sections = BTreeMap::new();

            if let Some(block) = block {
                sections.insert(plane.served().owns[0], block);
            }
            sections.insert(section_key, tools.unwrap_or_else(|| section(port)));
            let providers = BTreeMap::new();
            let secrets: std::sync::Arc<dyn busbar_contract::secret::SecretResolve> =
                std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only());

            let mut linked = crate::LINKED.auths.to_vec();
            let name = "busbar-auth-oauth";
            linked.push((name, name, busbar_auth_oauth::door));
            let tokens = Arc::new(super::TokenEndpoint::answering(|body: &str| {
                let scope = body
                    .split('&')
                    .find_map(|pair| pair.strip_prefix("scope="))
                    .unwrap_or_default();
                // RFC 8693 replies declare both the issued kind and its presentation type.
                serde_json::json!({
                    "access_token": format!("tok-{scope}"),
                    "token_type": "Bearer",
                    "issued_token_type": "urn:ietf:params:oauth:token-type:access_token",
                    "expires_in": 3600,
                })
                .to_string()
            }));
            let auths = crate::root::door_steps::OutboundAuths::new(
                Arc::clone(&dispatcher),
                &linked,
                None,
                crate::root::loader::dispatch::ConnTable::Host(crate::root::connector::admit(
                    Arc::clone(&tokens) as Arc<dyn DeclaredConns>,
                )),
                busbar_kernel::diagnostics::Catalogue::NEUTRAL,
            );
            let reach = crate::root::door_steps::DoorReach {
                providers: &providers,
                secrets: std::sync::Arc::clone(&secrets),
                auths: Arc::new(auths),
                conns: Arc::clone(&connector) as Arc<dyn PollConns>,
                models: None,
                stream_ceiling_secs: 600,
                catalog: None,
                upgrades: Vec::new(),
            };
            let egress = crate::root::serve::DoorEgress {
                reach: &reach,
                journal: Arc::clone(&post) as Arc<dyn busbar_kernel_egress::ports::Journal>,
            };
            let doors = [(instance.to_string(), plane)];

            let live_app: Arc<std::sync::OnceLock<Arc<busbar_kernel::state::App>>> = Arc::default();
            let stage = crate::root::serve::HookStage {
                host: {
                    let live_app = Arc::clone(&live_app);
                    Arc::new(move || {
                        busbar_kernel::plane_driver::engine_host(
                            live_app
                                .get()
                                .expect("the rig's App is built before any unit"),
                        )
                    })
                },
                gov: Arc::clone(&gov),
                journal: None,
            };

            let tables = busbar_kernel::plane_driver::serve::ServeTables::default();
            let mut app = {
                #[cfg(distribution_root)]
                crate::dist_root_install::install();
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                    .expect("the actual store statement reads")
                    .expect("the actual store exports its statement");
                let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .expect("the actual store statement is valid")
                    .name;
                let mut manifest = crate::root::test_plugins::manifest(
                    "store",
                    &module,
                    crate::root::test_plugins::FIXTURE_PUBLISHER,
                );
                manifest.statement = Some(hex::encode(statement));
                let release = crate::root::test_plugins::key(0x5a);
                let directory = crate::root::test_plugins::scratch(&format!(
                    "door-steps-{}",
                    busbar_kernel::door::op_id().counter()
                ));
                let library = std::fs::read(library_path).expect("the actual store library reads");
                let archive = crate::root::test_plugins::signed(&release, manifest, &library);
                std::fs::write(directory.join("store.tar.gz"), archive)
                    .expect("stage the actual store");
                crate::root::linked::register_stores(&crate::LINKED);
                busbar_kernel::preflight::install_linked_auth(
                    crate::LINKED.auths,
                    crate::root::auth_bindings::operator_words(),
                );
                let settings = crate::root::test_plugins::application_store_settings(&directory);
                let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                    "providers": {}, "models": {}, "auth": {"chain": [], "admin_auth": []},
                    "store": {"module": module, "settings": settings},
                }))
                .expect("the door deployment parses");
                let mut cfg = busbar_kernel::config::resolve(&deploy, &Default::default())
                    .expect("the door deployment resolves");
                cfg.per_request_fee = footing.fee_cents.unwrap_or(1);
                if let Some(groups) = footing.groups {
                    cfg.groups = groups.clone();
                }
                if let Some(fees) = footing.plane_fees {
                    cfg.plane_fees = fees.clone();
                }
                let rules = std::sync::Arc::new(crate::root::door_steps::Rules::default())
                    as std::sync::Arc<dyn busbar_kernel::appbuild::RootRules>;
                let opened = gov
                    .core_store_handle()
                    .expect("the generation keeps its native governance authority");
                let (app, rotate, limits) =
                    busbar_kernel::appbuild::build_app_from_config_with_store(
                        cfg,
                        crate::root::test_plugins::trusted_config_with_key(
                            &directory,
                            &crate::root::test_plugins::key(0x5a),
                        ),
                        None,
                        Default::default(),
                        Default::default(),
                        (None, None),
                        None,
                        &rules,
                        Some(opened),
                        false,
                    )
                    .await
                    .expect("the actual root builds the door generation");
                limits.stage_boot();
                crate::root::door_steps::tests::boot_fixture_prices(&app).await;
                limits.keep().await.expect("the product limits commit");
                if let Some(rotate) = rotate {
                    rotate.await;
                }
                app
            };
            let mut served = compose_planes(
                &doors,
                &dispatcher,
                &late,
                &sections,
                Some(PUBLIC_URL),
                &plane_money,
                Some(&egress),
                Some(&stage),
                &tables,
            )
            .await?;
            let _ = caller;
            let composed = &mut served.planes[0];
            assert!(
                composed.live.current().egress.is_some(),
                "its egress is sealed"
            );
            let money_steps = Arc::clone(&composed.money);
            let live = Arc::clone(&composed.live);
            let plane_key = composed.facts.plane.clone();
            let audience = composed.snapshot.audience.clone();
            served.post = Some(Arc::clone(&post));
            app.auth = Arc::new(
                busbar_kernel::auth::AuthMiddleware::new(
                    &busbar_kernel::config::AuthCfg {
                        chain: vec![busbar_kernel::config::AuthChainEntry::bare(
                            busbar_kernel::config::KEYS_MODULE,
                        )],
                        ..busbar_kernel::config::AuthCfg::default_none()
                    },
                    &app.hook_env.registry,
                    &app.secret_resolver,
                )
                .expect("the actual root constructs the keys middleware"),
            );
            app.amendments = Arc::clone(gov.amendments());
            app.governance = Some(Arc::clone(&gov));
            app.serve_tables = tables.clone();
            app.cost = Arc::new(CostModel::flat(1));
            let app = crate::root::real_store::hydrated(Arc::new(configure(app).await)).await;
            let _ = live_app.set(Arc::clone(&app));

            if let Some(kernel) = late.kernel() {
                let _attached = kernel
                    .attach_standing(busbar_kernel::plane_driver::standing_over(Arc::clone(&app)));
            }

            served.spawn_ticks();
            let [(_, plane)] = doors;

            let doors = door_routes(served, || CARD.pin(), &[], &[]).expect("its claims mount");
            let door_table = doors
                .iter()
                .map(|d| (d.path.clone(), d.method.as_str().to_string(), d.auth))
                .collect();
            let (router, admin, _handle) = busbar_kernel::build_split_routers_serving(
                Arc::clone(&app),
                doors,
                1 << 20,
                0,
                false,
            );
            Ok(Rig {
                router,
                admin,
                gov,
                app,
                key,
                token,
                money_steps,
                post,
                book,
                plane_key,
                audience,
                store,
                tokens,
                door_table,
                plane,
                clock,
                wall,
                work_observations,
                instance,
                live,
            })
        }

        pub(crate) fn bound_token(&self) -> String {
            self.bound_token_for(&self.token)
        }

        pub(crate) fn bound_token_for(&self, plain: &str) -> String {
            use busbar_kernel::governance::signing::TokenVerifier;
            let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
            let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
            let claims = verifier
                .verify(plain, 1_700_000_000, None)
                .expect("plain claims");
            let audience = self.audience.as_deref().expect("the real door's audience");
            signer.mint_for_audience(
                &claims.sub,
                claims.exp,
                claims.generation.as_deref(),
                audience,
                Some("client-1"),
            )
        }

        pub(crate) async fn admitted(&self) -> u64 {
            self.gov
                .usage_for_async(&self.app.cost, &self.key.id, busbar_kernel::store::now())
                .await
                .expect("a read")
                .expect("the key exists")
                .requests
        }

        pub(crate) fn all_ended(&self) -> bool {
            self.money_steps.open_units() == 0 && self.post.open_units() == 0
        }
    }

    pub(crate) async fn rig_with(
        instance: &'static str,
        port: u16,
        allowed_pools: Option<Vec<String>>,
        configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
    ) -> Rig {
        Rig::with(
            instance,
            port,
            allowed_pools,
            None,
            None,
            Footing::own(),
            configure,
        )
        .await
    }

    pub(crate) async fn rig_on(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        footing: Footing<'_>,
    ) -> Rig {
        Rig::with(instance, port, None, None, Some(tools), footing, &|app| app).await
    }

    pub(crate) async fn rig_tools(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
        configure: &dyn Fn(busbar_kernel::state::App) -> busbar_kernel::state::App,
    ) -> Rig {
        let row = super::door_boundary::row();
        super::door_boundary::registry(row);
        let slot = super::door_boundary::slot_over(row, tools.clone());
        Rig::with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            &|app| super::door_boundary::dispatched(configure(app), row, &slot),
        )
        .await
    }

    pub(crate) async fn try_rig_tools(
        instance: &'static str,
        port: u16,
        tools: serde_yaml::Value,
    ) -> Result<Rig, String> {
        let row = super::door_boundary::row();
        super::door_boundary::registry(row);
        let slot = super::door_boundary::slot_over(row, tools.clone());
        Rig::try_with(
            instance,
            port,
            None,
            None,
            Some(tools),
            Footing::own(),
            &|app| super::door_boundary::dispatched(app, row, &slot),
        )
        .await
    }

    fn records_composed(
        ledger: Ledger,
        signer: Arc<GovState>,
        (clock, wall): (
            &Arc<std::sync::atomic::AtomicU64>,
            &Arc<std::sync::atomic::AtomicU64>,
        ),
        dest: Arc<dyn busbar_kernel::host_services::DestJudge>,
    ) -> (
        Arc<crate::root::serve::LateServices>,
        Arc<busbar_kernel::persistence::facade::CoreStore>,
    ) {
        let store = signer.core_store_handle().expect("native signer authority");
        let (origin, ahead) = (std::time::Instant::now(), Arc::clone(clock));
        let wall_ahead = Arc::clone(wall);
        let kernel = busbar_kernel::host_services::KernelServices::new()
            .with_dest_judge(dest)
            .with_mono_clock(Arc::new(move || {
                u64::try_from(origin.elapsed().as_nanos())
                    .unwrap_or(u64::MAX)
                    .saturating_add(ahead.load(std::sync::atomic::Ordering::SeqCst))
            }))
            .with_wall_clock(Arc::new(move || {
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX))
                    .saturating_add(wall_ahead.load(std::sync::atomic::Ordering::SeqCst))
            }))
            .with_signer(signer.clone())
            .with_pool(Arc::new(busbar_kernel::host_services::BlockingPool::new(
                tokio::runtime::Handle::current(),
                busbar_kernel::host_records::QUEUE_CAP,
            )));
        let kernel = Arc::new(match ledger {
            Ledger::Rows(_, max_live) => {
                kernel.with_work_bounds(busbar_kernel::host_work::WorkBounds {
                    max_live,
                    ..Default::default()
                })
            }
            _ => kernel,
        });
        if !matches!(ledger, Ledger::Unbound) {
            assert!(kernel.attach_persistence(store.clone()));
        }
        let late = crate::root::serve::LateServices::new();
        late.install_kernel(Arc::clone(&kernel), kernel)
            .expect("installed once");
        (late, store)
    }

    /// The host services as the door reads them, the wall clock `clock.now` answers read `wall`
    /// milliseconds ahead, as the kernel's work book reads it: every other service is `inner`'s.
    #[derive(Clone)]
    pub(crate) struct ObservedWork {
        pub(crate) instance: String,
        pub(crate) reference: Vec<u8>,
        pub(crate) observation: busbar_contract::abi::mechanism::inspection::WorkObservation,
    }

    struct Clocked {
        inner: Arc<dyn busbar_contract::services::HostServices>,
        wall: Arc<std::sync::atomic::AtomicU64>,
        work_observations: Arc<std::sync::Mutex<Vec<ObservedWork>>>,
    }

    impl busbar_contract::services::HostServices for Clocked {
        fn inspect(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            query: &busbar_contract::abi::mechanism::inspection::InspectionQuery,
        ) -> busbar_contract::abi::mechanism::inspection::InspectionResult {
            use busbar_contract::abi::mechanism::inspection::{
                InspectionObservation, InspectionQuery,
            };
            let result = self.inner.inspect(caller, unit, query);
            if let (
                InspectionQuery::Work { reference },
                Ok(InspectionObservation::Work(observation)),
            ) = (query, &result)
            {
                self.work_observations
                    .lock()
                    .expect("the observation log")
                    .push(ObservedWork {
                        instance: caller.namespace().to_string(),
                        reference: reference.clone(),
                        observation: *observation,
                    });
            }
            result
        }

        fn now(&self) -> busbar_contract::services::Reading {
            let mut reading = self.inner.now();
            let ahead = self.wall.load(std::sync::atomic::Ordering::SeqCst);
            reading.wall_ns = reading
                .wall_ns
                .saturating_add(ahead.saturating_mul(1_000_000));
            reading
        }
        fn dest_judge(
            &self,
            dest: &str,
            class: u32,
            flags: u32,
            later: Option<busbar_contract::services::Later>,
        ) -> busbar_contract::services::Ran {
            self.inner.dest_judge(dest, class, flags, later)
        }
        fn records_get(
            &self,
            caller: &busbar_contract::services::Caller,
            kind: &str,
            key: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_get(caller, kind, key, later)
        }
        fn records_list(
            &self,
            caller: &busbar_contract::services::Caller,
            list: busbar_contract::services::RecordsList,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_list(caller, list, later)
        }
        fn records_claim(
            &self,
            caller: &busbar_contract::services::Caller,
            kind: &str,
            key: &[u8],
            ttl_ms: u64,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_claim(caller, kind, key, ttl_ms, later)
        }
        fn sign(
            &self,
            caller: &busbar_contract::services::Caller,
            data: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner.sign(caller, data)
        }
        fn trust_sight(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            hash: &str,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.trust_sight(caller, counterparty, hash, later)
        }
        fn trust_unreached(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_unreached(caller, counterparty)
        }
        fn trust_sight_item(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            item: &str,
            digest: &str,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner
                .trust_sight_item(caller, counterparty, item, digest, later)
        }
        fn trust_decide(
            &self,
            caller: &busbar_contract::services::Caller,
            ticket: busbar_contract::abi::mechanism::ticket::Ticket,
            key: busbar_contract::services::TrustKeyRef<'_>,
            expected: Option<&str>,
            approve: bool,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner
                .trust_decide(caller, ticket, key, expected, approve, later)
        }
        fn trust_state(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_state(caller, counterparty)
        }
        fn trust_serves(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            item: Option<&str>,
            digest: Option<&str>,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_serves(caller, counterparty, item, digest)
        }
        fn trust_due(
            &self,
            caller: &busbar_contract::services::Caller,
        ) -> busbar_contract::services::Stored {
            self.inner.trust_due(caller)
        }
        fn trust_verify(
            &self,
            caller: &busbar_contract::services::Caller,
            counterparty: &str,
            payload: &[u8],
            signatures: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner
                .trust_verify(caller, counterparty, payload, signatures)
        }
        fn entitlement_check(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            target: &str,
        ) -> busbar_contract::services::Stored {
            self.inner.entitlement_check(caller, unit, target)
        }
        fn session_emit(
            &self,
            caller: &busbar_contract::services::Caller,
            session: u64,
            bytes: &[u8],
        ) -> busbar_contract::services::Stored {
            self.inner.session_emit(caller, session, bytes)
        }
        fn ticket_mint(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ttl_secs: u64,
            record: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner
                .ticket_mint(caller, unit, ttl_secs, record, later)
        }
        fn ticket_take(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
        ) -> busbar_contract::services::Stored {
            self.inner.ticket_take(caller, unit)
        }
        fn random_fill(&self, len: u64) -> busbar_contract::services::Stored {
            self.inner.random_fill(len)
        }
        fn records_secret(
            &self,
            kind: &str,
            id: &str,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.records_secret(kind, id, later)
        }
        fn unit_nest(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ask: busbar_contract::services::NestAsk,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.unit_nest(caller, unit, ask, later)
        }
        fn work_open(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            kind: &str,
            record: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_open(caller, unit, kind, record, later)
        }
        fn work_find(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            reference: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_find(caller, unit, reference, later)
        }
        fn work_settle(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            handle: u64,
            record: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_settle(caller, unit, handle, record, later)
        }
        fn work_resume(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            handle: u64,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.work_resume(caller, unit, handle, later)
        }
        fn disk_append(
            &self,
            dest: &busbar_contract::services::DiskDest,
            bytes: Vec<u8>,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.disk_append(dest, bytes, later)
        }
        fn verify_lookup(
            &self,
            caller: &busbar_contract::services::Caller,
            key: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.verify_lookup(caller, key, later)
        }
        fn verify_store(
            &self,
            caller: &busbar_contract::services::Caller,
            key: &[u8],
            entry: &[u8],
            ttl_ms: u64,
        ) -> busbar_contract::services::Stored {
            self.inner.verify_store(caller, key, entry, ttl_ms)
        }
        fn content_scan(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            content: &[u8],
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.content_scan(caller, unit, content, later)
        }
        fn hook_call(
            &self,
            caller: &busbar_contract::services::Caller,
            unit: Option<u64>,
            ask: busbar_contract::services::HookAsk,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.hook_call(caller, unit, ask, later)
        }
        fn snapshot_read(
            &self,
            caller: &busbar_contract::services::Caller,
            scope: u32,
            later: busbar_contract::services::Later,
        ) -> busbar_contract::services::Ran {
            self.inner.snapshot_read(caller, scope, later)
        }
    }

    pub(crate) struct Footing<'a> {
        pub(crate) ledger: Ledger,
        pub(crate) book: Option<&'a Rig>,
        pub(crate) groups: Option<&'a BTreeMap<String, busbar_kernel::config::GroupCfg>>,
        pub(crate) plane_fees: Option<&'a busbar_kernel::config::PlaneFeesMap>,
        pub(crate) fee_cents: Option<i64>,

        pub(crate) guarded: bool,

        pub(crate) tls: Option<Arc<rustls::ClientConfig>>,
    }

    impl Footing<'_> {
        pub(crate) fn own() -> Self {
            Footing {
                ledger: Ledger::Memory,
                book: None,
                groups: None,
                plane_fees: None,
                fee_cents: None,
                guarded: false,
                tls: None,
            }
        }
    }

    pub(crate) const BLOCKED_HOST: &str = "blocked.example";

    pub(crate) enum Ledger {
        Memory,

        Store(Arc<busbar_kernel::persistence::facade::CoreStore>),

        Rows(Arc<Rows>, usize),

        Unbound,
    }

    /// Actual native Store with a bounded refusal of work settlement candidates.
    pub(crate) struct Rows(
        Arc<dyn busbar_contract::persistence::PersistenceBackend>,
        pub(crate) std::sync::atomic::AtomicU32,
    );
    impl Rows {
        pub(crate) async fn open() -> Arc<Self> {
            Arc::new(Self(
                crate::root::real_store::native_backend().await,
                std::sync::atomic::AtomicU32::new(0),
            ))
        }
    }
    impl busbar_contract::persistence::PersistenceBackend for Rows {
        fn info(&self) -> busbar_contract::persistence::BackendInfo {
            self.0.info()
        }
        fn read(
            &self,
            request: Arc<busbar_contract::persistence::Read>,
        ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ReadResult>
        {
            self.0.read(request)
        }
        fn scan(
            &self,
            request: Arc<busbar_contract::persistence::Scan>,
        ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Page> {
            self.0.scan(request)
        }
        fn clock(
            &self,
            dataset: busbar_contract::persistence::DatasetId,
        ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::ClockObservation>
        {
            self.0.clock(dataset)
        }
        fn commit(
            &self,
            candidate: busbar_contract::persistence::PreparedCandidate,
        ) -> busbar_contract::persistence::Call<'_, busbar_contract::persistence::Decision>
        {
            Box::pin(async move {
                use busbar_contract::persistence::{Failure, Mutation};
                let schema = busbar_kernel::host_work::WORK_SCHEMA.as_str().as_bytes();
                let settles = candidate.candidate().mutations.iter().any(|mutation| matches!(mutation, Mutation::Put { address, value } if address.key.windows(schema.len()).any(|bytes| bytes == schema) && value.expose(&busbar_kernel::seal::lend()).get(1) == Some(&busbar_contract::abi::host::service::WORK_SETTLED)));
                if settles
                    && self
                        .1
                        .fetch_update(
                            std::sync::atomic::Ordering::SeqCst,
                            std::sync::atomic::Ordering::SeqCst,
                            |n| n.checked_sub(1),
                        )
                        .is_ok()
                {
                    return Err(Failure::Refused);
                }
                self.0.commit(candidate).await
            })
        }
    }

    fn bound(
        instance: &str,
        dispatcher: &Arc<Dispatcher>,
        conns: crate::root::loader::dispatch::ConnTable,
    ) -> crate::root::boot::DoorPlane {
        let row = LinkedRow::of(line_door()).expect("the door states its Statement");
        Arc::new(
            load_linked::<Plane>(
                &row,
                Bind {
                    instance: Arc::from(instance),
                    max_inflight_cap: 64,
                    sink: Arc::new(NoSink),
                    dispatcher: dispatcher.adopter(),
                    conns,
                },
            )
            .expect("the linked door binds"),
        )
    }

    #[test]
    fn an_obsolete_manifest_pin_is_still_refused_before_a_door_opens() {
        let row = super::door_boundary::row();
        let error = (row
            .parse_section
            .expect("the door parses its owned section"))(row, &section(9))
        .expect_err("pinned_pubkey does not authenticate a server in this build");
        assert!(
            error.contains("pinned_pubkey") && error.contains("authenticates nothing"),
            "{error}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_peer_key_is_refused_before_the_tls_tool_server_receives_http() {
        use rcgen::PublicKeyData as _;
        let _one = PUBLISHING.lock().await;
        let mut server = TlsToolServer::new().await;
        let mut tools = server.section();
        let another = rcgen::KeyPair::generate().expect("another real key");
        tools["fs"]["pin"]["key"] = serde_yaml::Value::String(
            busbar_contract::transport::trust::key_pin(&another.subject_public_key_info()),
        );
        let rig = server
            .rig("serve-door-tools-wrong-peer", tools, &|app| app)
            .await;
        let (status, bytes) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        let body: serde_json::Value = serde_json::from_slice(&bytes).expect("a shaped failure");
        assert_eq!(
            status,
            StatusCode::OK,
            "the unreachable peer is a tool error: {body}"
        );
        assert_eq!(body["id"], 30, "the caller's own id: {body}");
        assert_eq!(
            body["result"]["isError"], true,
            "the peer was never served: {body}"
        );
        assert!(
            server.heard.try_recv().is_err(),
            "a wrong peer pin must fail before HTTP reaches the server"
        );
        assert!(rig.all_ended(), "the refused unit is closed");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_is_served_through_the_tool_door_and_its_money_posted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-served";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        let token = rig.bound_token();
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, Some(&token), CALL).await;
        assert_eq!(
            status,
            StatusCode::OK,
            "served through the door: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "from the server",
            "the server's tool result, relayed: {body}"
        );

        let verify = heard
            .recv()
            .await
            .expect("the server was asked for its tool list");
        assert!(verify.starts_with("POST /rpc "), "{verify}");
        assert!(
            verify.contains("\"tools/list\""),
            "the verify fetch: {verify}"
        );

        let head = heard.recv().await.expect("the server was dialled");
        assert!(head.starts_with("POST /rpc "), "{head}");
        assert!(head.contains("\"tools/call\""), "the relayed call: {head}");

        assert_eq!(rig.admitted().await, 1, "one admitted request");
        assert!(rig.all_ended(), "its facts closed at its end");

        {
            let (_, chained) = crate::root::serve::planes_tests::chained_records(
                &rig.store,
                rig.instance,
                surface("record_kind_call"),
                busbar_contract::abi::plane::RecordChain {
                    kind: 0,
                    framing: busbar_contract::abi::plane::CHAIN_LENGTH_PREFIXED,
                    flags: busbar_contract::abi::plane::CHAIN_DIGESTS_SCOPE,
                    _reserved: 0,
                },
                1,
            )
            .await;
            assert_eq!(
                chained.len(),
                1,
                "the call's one chained record: {chained:?}"
            );
        }

        let records = rig
            .book
            .durability
            .lock()
            .expect("unpoisoned")
            .audit_records
            .clone();
        let counted = |class: &str| -> Vec<busbar_contract::Count> {
            records
                .iter()
                .flat_map(|r| r.usage.lines.iter())
                .filter(|l| l.class.as_str() == class)
                .map(|l| l.quantity)
                .collect()
        };
        assert_eq!(
            counted(surface("class_tool_calls")),
            vec![1],
            "the one tool call the plane reported, on the unit's one record: {records:?}"
        );

        assert_eq!(
            counted(surface("class_bytes")),
            vec![ANSWER.len() as u64],
            "the bytes of the server's answer the plane reported: {records:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unkeyed_tools_call_is_refused_before_anything_is_charged_or_dialled() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-unkeyed";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, None, CALL).await;
        let refused = u16::try_from(refusal_status(ReasonCode::Unauthenticated)).expect("a status");
        assert_eq!(
            status.as_u16(),
            refused,
            "{}",
            String::from_utf8_lossy(&body)
        );
        assert_eq!(rig.admitted().await, 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_body_that_does_not_decode_is_refused_before_it_is_admitted() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-undecodable";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), "{not json").await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "the status the plane's decode stated: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("the plane's JSON-RPC");
        assert_eq!(
            body["error"]["code"],
            busbar_contract::jsonrpc::PARSE_ERROR,
            "the plane's own words for the arrival it refused (REFUSAL_ARRIVE): {body}"
        );
        assert_eq!(rig.admitted().await, 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_outside_the_callers_grant_is_refused_before_it_dials() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-ungranted";
        let mut server = TlsToolServer::new().await;
        let rig = server
            .rig_with_grants(instance, server.section(), Some(Vec::new()), &|app| app)
            .await;
        let heard = &mut server.heard;

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status.as_u16(), 404, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "not_granted", "{body}");
        assert_eq!(body["id"], 30, "the caller's id: {body}");
        assert_eq!(rig.admitted().await, 0, "nothing charged");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "no unit left open");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tools_call_to_a_server_that_is_down_ends_inside_its_unit() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-down";
        let server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        server.close().await;

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        let answer: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(status, StatusCode::OK, "{answer}");
        assert_eq!(
            answer["result"]["isError"], true,
            "an upstream failure: {answer}"
        );
        assert!(rig.all_ended(), "the unit ended inside itself");
    }

    pub(crate) fn assert_member_passthrough_refused(error: &str, instance: &str, member: &str) {
        let expected = format!(
            "`tools.{member}`: `upstream_credentials: passthrough` is refused: it would present \
             the caller's own busbar credential (the virtual key or busbar-audience token they \
             authenticated to busbar with) to this MCP server, and a caller's busbar credential \
             never travels upstream. Use `token_exchange:` (busbar exchanges its own subject \
             token for a down-scoped token bound to this server's `aud:`), or `own` (the default: \
             busbar presents no caller credential)."
        );
        assert!(
            error.starts_with(&format!("{instance}: plugin ")),
            "{error}"
        );
        let (_, reason) = error
            .split_once(" open failed: ")
            .expect("the plugin refused its open");
        assert_eq!(
            reason, expected,
            "the registration's exact security refusal"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_passthrough_registration_is_refused_before_the_callers_credential_can_leave() {
        const EXACT: &str = concat!(
            module_path!(),
            "::a_passthrough_registration_is_refused_before_the_callers_credential_can_leave"
        );
        let Some(case) = super::isolated_fixture_cases(EXACT, &["refused", "own"]) else {
            return;
        };
        let _one = PUBLISHING.lock().await;
        let mut server = TlsToolServer::new().await;
        if case == "refused" {
            let mut forwarded = server.section();
            forwarded["fs"]["upstream_credentials"] = "passthrough".into();
            let refusal = server
                .try_rig("door-passthrough-refused", forwarded, &|app| app)
                .await
                .err()
                .expect("the plane forbids lending its caller's busbar credential");
            assert_member_passthrough_refused(&refusal, "door-passthrough-refused", "fs");
            assert!(
                server.heard.try_recv().is_err(),
                "a refused configuration sends no upstream request"
            );
            server.close().await;
            super::isolated_fixture_done(EXACT, &case);
            return;
        }
        let rig = server
            .rig("door-own-credential", server.section(), &|app| app)
            .await;
        let token = rig.bound_token();
        let (status, body) = send(&rig.router, Some(&token), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a served answer");
        assert_eq!(
            body["result"]["content"][0]["text"], "from the server",
            "{body}"
        );
        let (mut call, mut list) = (None, None);
        while let Ok(request) = server.heard.try_recv() {
            if request.contains("\"tools/call\"") {
                call = Some(request);
            } else if request.contains("\"tools/list\"") {
                list = Some(request);
            }
        }
        for (what, request) in [("call", call), ("verify-on-call list", list)] {
            let request = request
                .unwrap_or_else(|| panic!("the server heard the {what}"))
                .to_ascii_lowercase();
            assert!(
                !request.contains("authorization:"),
                "{what}: no credential at all: {request}"
            );
            assert!(
                !request.contains(&token.to_ascii_lowercase()),
                "the caller's token never leaves"
            );
        }
        server.close().await;
        super::isolated_fixture_done(EXACT, &case);
    }

    async fn grant(rig: &Rig, scopes: &[(&str, &str)]) {
        let mut key = (*rig.key).clone();
        key.allowed_scopes = Some(
            scopes
                .iter()
                .map(|(kind, value)| busbar_contract::records::ScopeRef {
                    kind: surface(kind).to_string(),
                    value: (*value).to_string(),
                })
                .collect(),
        );
        rig.gov
            .core_store_handle()
            .unwrap()
            .identity()
            .put_key(&key)
            .await
            .expect("the native key commits");
        rig.gov.refresh_async().await.expect("the book refreshes");
    }

    pub(crate) fn form_value(body: &str, key: &str) -> String {
        body.split('&')
            .find_map(|pair| pair.strip_prefix(&format!("{key}=")))
            .unwrap_or_default()
            .to_string()
    }

    pub(crate) fn exchanges(rig: &Rig) -> Vec<(String, String)> {
        rig.tokens
            .opened
            .lock()
            .expect("unpoisoned")
            .iter()
            .map(|(_, target, _, body)| (target.clone(), body.clone()))
            .collect()
    }

    pub(crate) fn three_tools() -> serde_json::Value {
        serde_json::json!([
            {"name": "read_file", "description": TOOL_DESCRIPTION, "inputSchema": tool_schema()},
            {"name": "write_file", "description": "writes a file to disk", "inputSchema": tool_schema()},
            {"name": "stat", "description": "reads a file's metadata", "inputSchema": tool_schema()},
        ])
    }

    const SUBJECT_VAR: &str = "BUSBAR_DOOR_EXCHANGE_TEST_SUBJECT";

    pub(crate) const TOKEN_URL: &str = "https://as.example/token";

    fn exchange_section(server: &TlsToolServer) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             allow_private: true\n  aud: \"https://127.0.0.1:{port}\"\n  \
             token_exchange:\n    token_url: \"{TOKEN_URL}\"\n    \
             subject_token: {{ env: {SUBJECT_VAR} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n    \
             write_file: {{ schema_hash: \"{}\" }}\n    stat: {{ schema_hash: \"{}\" }}\n",
            tool_digest(),
            surface("write_digest"),
            surface("stat_digest"),
        ))
        .expect("a section")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_token_exchange_registration_presents_the_token_exchanged_for_the_callers_down_scope()
    {
        const EXACT: &str = concat!(module_path!(), "::a_token_exchange_registration_presents_the_token_exchanged_for_the_callers_down_scope");
        let Some(case) = crate::root::door_steps::tests::isolated_fixture_cases(
            EXACT,
            &["door-exchange-granted", "door-exchange-wildcard"],
        ) else {
            return;
        };
        let _one = PUBLISHING.lock().await;
        std::env::set_var(SUBJECT_VAR, "busbar-own-subject-token");
        let granted: &[(&str, &str)] = &[
            ("scope_server", "fs"),
            ("scope_tool", "fs_read_file"),
            ("scope_tool", "fs_write_file"),
            ("scope_tool", "git_log"),
        ];
        for (instance, grants, down_scope) in [
            (
                "door-exchange-granted",
                Some(granted),
                "fs_read_file+fs_write_file",
            ),
            ("door-exchange-wildcard", None, "fs_read_file"),
        ] {
            if case != instance {
                continue;
            }
            let mut server =
                TlsToolServer::listing(Arc::new(std::sync::Mutex::new(three_tools()))).await;
            let port = server.port;
            let rig = server
                .rig(instance, exchange_section(&server), &|app| app)
                .await;
            let heard = &mut server.heard;
            if let Some(grants) = grants {
                grant(&rig, grants).await;
            }
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "{instance}: {}",
                String::from_utf8_lossy(&body)
            );
            let (mut call, mut list) = (None, None);
            while let Ok(r) = heard.try_recv() {
                if r.contains("\"tools/call\"") {
                    call = Some(r.to_ascii_lowercase());
                } else if r.contains("\"tools/list\"") {
                    list = Some(r.to_ascii_lowercase());
                }
            }
            let call = call.expect("the server heard the call");
            assert!(
                call.contains(&format!("authorization: bearer tok-{down_scope}")),
                "{instance}: the call presents the token for the caller's down-scope: {call}"
            );
            let list = list.expect("the server heard the verify-on-call list");
            assert!(
                list.contains("authorization: bearer tok-fs_read_file+fs_stat+fs_write_file"),
                "{instance}: the door's own fetch presents the registration's token: {list}"
            );
            let field = busbar_contract::abi::auth::SCOPE_REQUEST_FIELD;
            assert!(
                !call.contains(field) && !list.contains(field),
                "the host's scope field never reaches the server"
            );
            let exchanges = exchanges(&rig);
            let scopes: Vec<String> = exchanges
                .iter()
                .map(|(_, r)| form_value(r, "scope"))
                .collect();
            assert_eq!(
                scopes,
                ["fs_read_file+fs_stat+fs_write_file", down_scope],
                "{instance}: one exchange per scope"
            );
            for (target, r) in &exchanges {
                assert_eq!(target, TOKEN_URL);
                assert_eq!(
                    form_value(r, "grant_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange"
                );
                assert_eq!(
                    form_value(r, "requested_token_type"),
                    "urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Aaccess_token"
                );
                assert_eq!(form_value(r, "subject_token"), "busbar-own-subject-token");
                assert_eq!(
                    form_value(r, "resource"),
                    format!("https%3A%2F%2F127.0.0.1%3A{port}")
                );
                assert!(
                    !r.contains(&rig.token) && !r.contains(&rig.bound_token()),
                    "the caller's credential never reaches the authorization server"
                );
            }
            assert!(rig.all_ended(), "every unit ended");
            server.close().await;
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_tool_pool_fails_over_through_the_one_walk_and_repeats_only_what_it_names() {
        const EXACT: &str = concat!(
            module_path!(),
            "::a_tool_pool_fails_over_through_the_one_walk_and_repeats_only_what_it_names"
        );
        let Some(case) = crate::root::door_steps::tests::isolated_fixture_cases(
            EXACT,
            &["repeatable", "single"],
        ) else {
            return;
        };
        let _one = PUBLISHING.lock().await;
        let listing = || {
            serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                .to_string()
        };
        let calls = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut n = 0;
            while let Ok(r) = heard.try_recv() {
                n += usize::from(r.contains("\"tools/call\""));
            }
            n
        };
        let tools = |bad: &TlsToolServer, good: &TlsToolServer, repeatable: &str| {
            let mut value = bad.section();
            value["fs2"] = good.section()["fs"].clone();
            value["pools"] = serde_yaml::to_value(serde_json::json!({
                "twins": { "members": ["fs","fs2"], "repeatable":
                    if repeatable.is_empty() { Vec::<&str>::new() } else { vec![repeatable] },
                    "member_granted": true }
            }))
            .expect("the same pool data");
            value
        };
        let instance = "door-tool-pool";
        for (repeatable, twin_answers) in [("read_file", true), ("", false)] {
            if case != if twin_answers { "repeatable" } else { "single" } {
                continue;
            }
            let mut bad = TlsToolServer::replying(Arc::new(move |r: &str| {
                if r.contains("\"tools/list\"") {
                    (200, listing())
                } else {
                    (503, "{}".to_string())
                }
            }))
            .await;
            let mut good = TlsToolServer::new().await;
            let rig = bad
                .rig_with_footing(
                    instance,
                    tools(&bad, &good, repeatable),
                    bad.footing_with_peers(&[&good]),
                    &|app| app,
                )
                .await;
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            let body = String::from_utf8_lossy(&body).to_string();
            assert_eq!(
                body.contains("from the server"),
                twin_answers,
                "repeatable [{repeatable}]: {status} {body}"
            );
            assert_eq!(calls(&mut bad.heard), 1, "the primary is called once");
            assert_eq!(
                calls(&mut good.heard),
                usize::from(twin_answers),
                "the twin hears the call only when the pool repeats the tool"
            );
            assert!(rig.all_ended(), "the unit ended inside itself");
            bad.close().await;
            good.close().await;
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn verify_on_call_judges_the_live_list_reuses_a_fresh_look_and_fails_closed() {
        const EXACT: &str = concat!(
            module_path!(),
            "::verify_on_call_judges_the_live_list_reuses_a_fresh_look_and_fails_closed"
        );
        let Some(case) = crate::root::door_steps::tests::isolated_fixture_cases(
            EXACT,
            &["cached", "drift", "unavailable"],
        ) else {
            return;
        };
        let _one = PUBLISHING.lock().await;
        let tools = |server: &TlsToolServer, ttl: &str| {
            let mut value = server.section();
            value["fs"]["verify_ttl"] = ttl.into();
            value
        };
        let drain = |heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>| {
            let mut got = Vec::new();
            while let Ok(r) = heard.try_recv() {
                got.push(if r.contains("\"tools/list\"") {
                    "list"
                } else if r.contains("\"tools/call\"") {
                    "call"
                } else {
                    "other"
                });
            }
            got
        };

        let instance = "door-verify-on-call";
        if case == "cached" {
            let mut server = TlsToolServer::new().await;
            let rig = server.rig(instance, tools(&server, "1h"), &|app| app).await;
            let heard = &mut server.heard;
            for _ in 0..2 {
                let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
                assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
            }
            assert_eq!(
                drain(heard),
                vec!["list", "call", "call"],
                "one fetch, two calls"
            );
            drop(rig);
            server.close().await;
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }

        if case == "drift" {
            let listed = Arc::new(std::sync::Mutex::new(tool_listing()));
            let mut server = TlsToolServer::listing(Arc::clone(&listed)).await;
            let rig = server.rig(instance, tools(&server, "0s"), &|app| app).await;
            let heard = &mut server.heard;
            let (status, _) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            assert_eq!(
                status,
                StatusCode::OK,
                "the control: the approved list serves"
            );
            *listed.lock().expect("the list") = serde_json::json!([
                {"name": "read_file", "description": TOOL_DESCRIPTION,
                 "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "exfil": {"type": "string"}}}}
            ]);
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
            let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
            assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");
            assert_eq!(
                drain(heard),
                vec!["list", "call", "list"],
                "the drifted call was refused before it was sent"
            );
            drop(rig);
            server.close().await;
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }

        if case == "unavailable" {
            let server = TlsToolServer::new().await;
            let rig = server.rig(instance, tools(&server, "0s"), &|app| app).await;
            server.close().await;
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
            let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
            assert_eq!(
                body["result"]["isError"], true,
                "an upstream failure: {body}"
            );
            assert!(rig.all_ended(), "the refused unit ended");
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_tool_list_re_check_gives_up_at_the_registrations_timeout() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-verify-timeout";
        let server = TlsToolServer::replying(Arc::new(|_| (STALL, String::new()))).await;
        let mut section = server.section();
        section["fs"]["verify_ttl"] = "0s".into();
        section["fs"]["timeout"] = "1s".into();
        let rig = server.rig(instance, section, &|app| app).await;

        let (status, body) = tokio::time::timeout(
            std::time::Duration::from_secs(10),
            send(&rig.router, Some(&rig.bound_token()), CALL),
        )
        .await
        .expect("the re-check gave up inside 10s: the registration's `timeout: 1s` is its budget");
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(
            body["result"]["isError"], true,
            "an upstream failure: {body}"
        );
        assert!(rig.all_ended(), "the refused unit ended");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_metadata_url_in_the_arguments_is_refused_before_the_call_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-argguard";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        let heard = &mut server.heard;
        let call = |url: &str| {
            serde_json::json!({
                "jsonrpc": "2.0", "id": 31, "method": "tools/call",
                "params": {
                    "name": "fs_read_file",
                    "arguments": { "path": "notes.txt", "fetch": url },
                    "_meta": {
                        "io.modelcontextprotocol/protocolVersion": protocol_version(),
                        "io.modelcontextprotocol/clientCapabilities": {}
                    }
                }
            })
            .to_string()
        };
        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &call("http://169.254.169.254/latest/meta-data/"),
        )
        .await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["code"], -32000, "{body}");
        assert_eq!(
            body["error"]["data"]["reason"], "tool_argument_refused",
            "{body}"
        );
        let message = body["error"]["message"].as_str().unwrap_or_default();
        assert!(
            message.starts_with("tool argument /fetch carries a URL the schema does not declare"),
            "{message}"
        );
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );
        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &call("https://docs.example.com/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        server.close().await;
    }

    fn fetching(url: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 32, "method": "tools/call",
            "params": {
                "name": "fs_read_file",
                "arguments": { "path": "notes.txt", "fetch": url },
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": {}
                }
            }
        })
        .to_string()
    }

    async fn refused_in_the_arguments(instance: &'static str, urls: &[&str]) {
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        let heard = &mut server.heard;
        for url in urls {
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), &fetching(url)).await;
            let shown = String::from_utf8_lossy(&body);
            assert_eq!(status.as_u16(), 403, "`{url}` must be refused: {shown}");
            let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
            assert_eq!(body["error"]["code"], -32000, "`{url}`: {body}");
            assert_eq!(
                body["error"]["data"]["reason"], "tool_argument_refused",
                "`{url}`: {body}"
            );
        }
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "no refused call reached the wire: {wire:?}"
        );
        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &fetching("https://docs.example.com/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_host_the_deployment_refuses_is_refused_in_the_arguments() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-blocked";
        let (plain, secure) = (
            format!("http://{BLOCKED_HOST}/x"),
            format!("https://{BLOCKED_HOST}:8443/y"),
        );
        refused_in_the_arguments(instance, &[&plain, &secure]).await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn every_internal_address_the_guard_refuses_is_refused_in_the_arguments() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-internal";
        refused_in_the_arguments(
            instance,
            &[
                "http://198.18.0.1/x",
                "http://192.0.0.8/x",
                "http://0.1.2.3/x",
                "http://[::ffff:198.18.0.1]/x",
                "http://[::1%25lo]/x",
                "http://[fe80::1%25eth0]/x",
                "http://224.0.0.1/x",
                "http://255.255.255.255/x",
                "http://[ff02::1]/x",
            ],
        )
        .await;
    }

    const ODD_HOSTS: [(&str, &str); 6] = [
        (
            "\u{ff4c}\u{ff4f}\u{ff43}\u{ff41}\u{ff4c}\u{ff48}\u{ff4f}\u{ff53}\u{ff54}",
            "localhost",
        ),
        ("\u{2460}\u{2461}\u{2466}.0.0.1", "127.0.0.1"),
        (
            "\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}.\u{2460}\u{2465}\u{2468}.\u{2461}\u{2464}\u{2463}",
            "169.254.169.254",
        ),
        ("LOCALHOST\u{3002}", "localhost"),
        ("\u{ff10}\u{ff58}\u{ff17}\u{ff46}\u{ff0e}\u{ff11}", "0x7f.1"),
        (
            "\u{ff10}\u{ff11}\u{ff17}\u{ff17}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff10}\u{ff11}",
            "017700000001",
        ),
    ];

    async fn odd_hosts_refused_as_their_ascii_hosts(
        instance: &'static str,
        spellings: &[fn(&str) -> String],
        zero: &[&str],
    ) {
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        let heard = &mut server.heard;
        let refusal = |status: StatusCode, body: &[u8], url: &str| {
            let shown = String::from_utf8_lossy(body);
            assert_eq!(status.as_u16(), 403, "`{url}` must be refused: {shown}");
            let body: serde_json::Value = serde_json::from_slice(body).expect("JSON-RPC");
            assert_eq!(
                body["error"]["data"]["reason"], "tool_argument_refused",
                "`{url}`: {body}"
            );
            (
                body["error"]["code"].clone(),
                body["error"]["data"]["reason"].clone(),
                body["error"]["message"].clone(),
            )
        };
        for (odd, plain) in ODD_HOSTS {
            for spell in spellings {
                let (odd_url, plain_url) = (spell(odd), spell(plain));
                let (status, body) =
                    send(&rig.router, Some(&rig.bound_token()), &fetching(&odd_url)).await;
                let odd_refusal = refusal(status, &body, &odd_url);
                let (status, body) =
                    send(&rig.router, Some(&rig.bound_token()), &fetching(&plain_url)).await;
                let plain_refusal = refusal(status, &body, &plain_url);
                assert_eq!(
                    odd_refusal, plain_refusal,
                    "`{odd_url}` beside `{plain_url}`"
                );
            }
        }
        for url in zero {
            let (status, body) = send(&rig.router, Some(&rig.bound_token()), &fetching(url)).await;
            refusal(status, &body, url);
        }
        let mut wire = Vec::new();
        while let Ok(r) = heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "no refused call reached the wire: {wire:?}"
        );

        let (status, body) = send(
            &rig.router,
            Some(&rig.bound_token()),
            &fetching("https://b\u{fc}cher.example/notes"),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_odd_host_spelling_in_the_arguments_is_refused_as_its_ascii_host() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-destjudge-odd-hosts";
        odd_hosts_refused_as_their_ascii_hosts(
            instance,
            &[|h| format!("http://{h}/latest/meta-data/")],
            &["http://0x/latest/meta-data/"],
        )
        .await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_listing_is_answered_by_the_plane_with_no_walk_and_no_charge() {
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-local";
        let mut server = TlsToolServer::new().await;
        let rig = server.rig(instance, server.section(), &|app| app).await;
        let heard = &mut server.heard;

        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            LIST,
            "tools/list",
            None,
        )
        .await;
        assert_eq!(
            status,
            StatusCode::OK,
            "answered by the plane: {}",
            String::from_utf8_lossy(&body)
        );
        let body: serde_json::Value = serde_json::from_slice(&body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 9, "{body}");
        assert_eq!(
            body["result"]["tools"][0]["name"], "fs_read_file",
            "the catalogue's one tool: {body}"
        );
        assert_eq!(rig.admitted().await, 0, "a local answer charges nothing");
        assert!(heard.try_recv().is_err(), "nothing dialled");
        assert!(rig.all_ended(), "every unit ended");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_metadata_document_is_rendered_from_the_doors_facts_and_is_no_unit() {
        use tower::ServiceExt as _;
        let _one = PUBLISHING.lock().await;
        let instance = "serve-door-tools-metadata";
        let mut server = TlsToolServer::new().await;
        let port = server.port;
        let block: serde_yaml::Value = serde_yaml::from_str(&format!(
            "canonical_uri: \"http://127.0.0.1{}\"\n\
                 authorization_servers: [\"https://login.example.com\"]\n\
                 scopes_supported: [\"tools:call\"]\n",
            endpoint()
        ))
        .expect("a block");
        let rig = Rig::with(
            instance,
            port,
            None,
            Some(block),
            Some(server.section()),
            server.footing(),
            &|app| app,
        )
        .await;
        let req = axum::http::Request::builder()
            .method("GET")
            .uri(format!(
                "/.well-known/oauth-protected-resource{}",
                endpoint()
            ))
            .body(axum::body::Body::empty())
            .expect("a request");
        let response = rig.router.clone().oneshot(req).await.expect("answers");
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response
                .headers()
                .get("cache-control")
                .and_then(|v| v.to_str().ok()),
            Some("public, max-age=3600")
        );
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 16)
            .await
            .expect("the body");
        let doc: serde_json::Value = serde_json::from_slice(&bytes).expect("a JSON document");
        assert_eq!(
            doc,
            serde_json::json!({
                "resource": format!("http://127.0.0.1{}", endpoint()),
                "authorization_servers": ["https://login.example.com"],
                "scopes_supported": ["tools:call"],
                "bearer_methods_supported": ["header"],
            })
        );
        assert_eq!(rig.admitted().await, 0, "nothing admitted");
        assert!(rig.all_ended(), "no unit was opened");
        assert!(server.heard.try_recv().is_err(), "nothing dialled");
        server.close().await;
    }

    #[tokio::test]
    async fn the_tool_door_claims_its_endpoint_only_under_a_public_url() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let money = money().await;
        let compose = |instance: &'static str, public_url: Option<&'static str>| {
            let server = &server;
            let money = money.clone();
            async move {
                let dispatcher = Arc::new(Dispatcher::new(
                    DispatchConfig::default(),
                    busbar_kernel::host_services::caller_binding(),
                ));
                crate::root::connector::install_io(&dispatcher);

                let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
                let plane = bound(
                    instance,
                    &dispatcher,
                    crate::root::loader::dispatch::ConnTable::Probe,
                );
                let mut sections = BTreeMap::new();
                sections.insert(plane.served().section, server.section());
                compose_planes(
                    &[(instance.to_string(), plane)],
                    &dispatcher,
                    &composed_services(),
                    &sections,
                    public_url,
                    &|| money.clone(),
                    None,
                    None,
                    &busbar_kernel::plane_driver::serve::ServeTables::default(),
                )
                .await
                .expect("the door plane composes")
            }
        };
        {
            let bare = "serve-door-tools-claims-bare";
            let served = compose(bare, None).await;
            assert!(
                served.planes[0].snapshot.claims.is_empty(),
                "no public base URL, no claim"
            );
        }
        {
            let block = "serve-door-tools-claims-block";
            let dispatcher = Arc::new(Dispatcher::new(
                DispatchConfig::default(),
                busbar_kernel::host_services::caller_binding(),
            ));
            crate::root::connector::install_io(&dispatcher);

            let _ = dispatcher.lend_seal(busbar_kernel::seal::lend());
            let plane = bound(
                block,
                &dispatcher,
                crate::root::loader::dispatch::ConnTable::Probe,
            );
            let mut sections = BTreeMap::new();
            sections.insert(plane.served().section, server.section());
            assert_eq!(
                plane.served().owns,
                [endpoint_section()],
                "the endpoint block it owns beside"
            );
            sections.insert(
            plane.served().owns[0],
            serde_yaml::from_str(
                &format!("canonical_uri: \"https://gw.example{}\"\nauthorization_servers: [\"https://login.example\"]\n", endpoint()),
            )
            .expect("a block"),
        );
            let served = compose_planes(
                &[(block.to_string(), plane)],
                &dispatcher,
                &composed_services(),
                &sections,
                None,
                &|| money.clone(),
                None,
                None,
                &busbar_kernel::plane_driver::serve::ServeTables::default(),
            )
            .await
            .expect("the door plane composes");
            let snapshot = &served.planes[0].snapshot;
            assert_eq!(
                snapshot.audience.as_deref(),
                Some(format!("https://gw.example{}", endpoint()).as_str())
            );
            assert!(
                snapshot
                    .claims
                    .iter()
                    .any(|c| c.verb == "POST" && c.target == endpoint()),
                "the endpoint is claimed under its block"
            );
        }
        let public = "serve-door-tools-claims-public";
        let served = compose(public, Some(PUBLIC_URL)).await;
        assert!(
            served.planes[0]
                .snapshot
                .claims
                .iter()
                .any(|c| c.verb == "POST" && c.target == endpoint()),
            "the endpoint is claimed under the public base URL"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_roots_ask_is_relayed_to_the_caller_and_no_retry_is_sent() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-mrtr-roots";
        let mut server = TlsToolServer::answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else {
                r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"r":{"method":"roots/list"}},"requestState":"s"}}"#
                    .to_string()
            }
        }))
        .await;
        let mut tools = server.section();
        tools["fs"]["grants"] = serde_yaml::to_value(serde_json::json!({"roots":true})).unwrap();
        let rig = server.rig(instance, tools, &|app| app).await;
        let heard = &mut server.heard;
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["r"]["method"], "roots/list",
            "the ask reaches the caller verbatim: {body}"
        );
        assert_ne!(body["result"]["requestState"], "s", "{body}");
        let verify = heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = heard
            .try_recv()
            .expect("the first round reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            heard.try_recv().is_err(),
            "busbar sent no retry of its own: it answers nothing on the caller's behalf"
        );
        assert_eq!(rig.admitted().await, 1, "one unit, one charge");
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod door_boundary {
    use std::sync::Arc;

    use busbar_contract::abi::mechanism::route::RouteAuth;
    use busbar_kernel::governance::signing::{TokenSigner, TokenVerifier, DEFAULT_KID};
    use busbar_kernel::plane_driver::registry::{BuildCtx, PlaneDecl};
    use busbar_kernel::state::App;

    use super::tool_door::{section, TlsToolServer, ADMIN_TOKEN, PUBLIC_URL};
    use crate::root::serve::planes_tests::PUBLISHING;

    pub(crate) fn row() -> &'static PlaneDecl {
        use crate::root::loader::dispatch::kinds::plane::{linked_probe, registration};
        busbar_kernel::plane_driver::door::fold(
            registration(linked_probe(
                super::tool_door::line_door(),
                "door-boundary-row",
                busbar_kernel::host_services::caller_binding(),
            ))
            .expect("the linked door binds"),
        )
        .expect("the door folds")
    }

    pub(crate) fn registry(row: &'static PlaneDecl) {
        let mut rows = busbar_kernel::plane_driver::registry::plane_decls().to_vec();
        rows.retain(|installed| installed.key != row.key);
        rows.push(row);
        busbar_kernel::plane_driver::registry::publish_planes(&rows);
    }

    pub(crate) fn dispatched(
        mut app: App,
        row: &'static PlaneDecl,
        slot: &Arc<dyn std::any::Any + Send + Sync>,
    ) -> App {
        app.plane_sections
            .get_or_insert_with(Default::default)
            .insert(row.config_section);
        for (path, wire) in (row.claims)(&**slot) {
            app.planes = Arc::new((*app.planes).clone().mount(row.key, &path, wire));
        }
        if let Some(admission) = (row.admission)(&**slot) {
            app.planes = Arc::new((*app.planes).clone().admit(row.key, admission));
        }

        app.plane_slots.insert(row.key, Arc::clone(slot));
        app.plane_slots.insert(
            busbar_kernel::state::runtime_slot_key(row.key),
            Arc::clone(slot),
        );
        app
    }

    fn slot(row: &'static PlaneDecl, port: u16) -> Arc<dyn std::any::Any + Send + Sync> {
        slot_over(row, section(port))
    }

    pub(crate) fn slot_over(
        row: &'static PlaneDecl,
        value: serde_yaml::Value,
    ) -> Arc<dyn std::any::Any + Send + Sync> {
        let value = crate::root::serve::plane_settings(&value);
        let tools = busbar_kernel::plane_driver::door::DoorSection::new(
            row.door,
            row.config_section,
            value,
        );
        let defs = tools.as_defs();
        (row.build)(
            row,
            &BuildCtx {
                endpoint_slot: None,
                plane_defs: &defs,
                public_url: Some(PUBLIC_URL),
                prior: None,
                providers: None,
            },
        )
        .expect("the door builds from its section")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn plane_slot_holds_the_one_built_object_of_each_configured_plane() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-slot";
        let server = TlsToolServer::new().await;
        let port = server.port;
        let row = row();
        registry(row);
        let slot = slot_over(row, server.section());
        let rig = super::tool_door::Rig::with(
            instance,
            port,
            None,
            None,
            Some(server.section()),
            server.footing(),
            &|app| dispatched(app, row, &slot),
        )
        .await;
        let held = rig
            .app
            .plane_slot(row.key)
            .expect("the configured door has a slot")
            .clone();
        assert!(Arc::ptr_eq(&held, &slot), "one construction, read back");
        assert!(
            (row.admission)(&*held).is_some(),
            "the slot is the door's own object: its admission reads it"
        );
        let claims = (row.claims)(&*held);
        assert!(!claims.is_empty(), "the door claims its paths");
        for (path, _) in claims {
            assert!(
                rig.door_table.iter().any(|(p, _, _)| *p == path),
                "`{path}`, claimed off the door's slot, must be a route the root mounted: {:?}",
                rig.door_table
            );
        }
        server.close().await;
    }

    #[cfg(linked_driver_proofs)]
    async fn pools_door_walk(audience: &str) -> Vec<String> {
        use crate::root::serve::plane_llm_door::hook_seat_tests::{rig as pools_rig, RigOpts};
        let instance = "door-boundary-pools";
        let rig = pools_rig(
            instance,
            RigOpts {
                members: &[(1, 1)],
                ..RigOpts::default()
            },
        )
        .await;
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(
            &rig.key_id,
            4_000_000_000,
            generation.as_deref(),
            audience,
            Some("client-1"),
        );

        fn concrete(pattern: &str) -> String {
            let mut out = String::new();
            for seg in pattern.split('/').skip(1) {
                out.push('/');
                if seg.starts_with('{') && seg.ends_with('}') {
                    out.push_str(match seg {
                        "{name}" => "p",
                        "{provider}" => "oai0",
                        "{model}" => "m0",
                        s if s.starts_with("{*") => "probe",
                        other => panic!(
                            "route pattern segment {other} has no fixture value: give it one, \
                             never skip the route"
                        ),
                    });
                } else {
                    out.push_str(seg);
                }
            }
            if out.is_empty() {
                "/".to_string()
            } else {
                out
            }
        }
        let body = serde_json::json!({
            "model": "p",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        });
        let mut routes = busbar_kernel::base_data_core_lines(&rig.app)
            .into_iter()
            .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
            .collect::<Vec<_>>();
        routes.extend(rig.door_table.iter().cloned());
        let mut walked: Vec<String> = Vec::new();
        for (pattern, verb, auth) in &routes {
            if *auth == RouteAuth::None {
                continue;
            }
            let path = concrete(pattern);
            let (anon, _, _) = rig.send_bare(verb, &path, Some(body.clone()), &[]).await;
            let header = format!("Bearer {bound}");
            let (with_bound, _, _) = rig
                .send_bare(
                    verb,
                    &path,
                    Some(body.clone()),
                    &[("authorization", header.as_str())],
                )
                .await;
            assert_eq!(
                with_bound, anon,
                "an audience-bound door token is no credential on {verb} {path}"
            );
            let (plain, _, _) = rig.send(verb, &path, Some(body.clone())).await;
            assert_ne!(
                plain, anon,
                "the plain sibling is admitted on {verb} {path}"
            );
            walked.push(path);
        }

        for path in ["/p/v1/messages", "/oai0/m0/v1/messages"] {
            let (anon, _, _) = rig.send_bare("POST", path, Some(body.clone()), &[]).await;
            assert_eq!(
                anon, 401,
                "an anonymous caller is refused on the convenience route POST {path}"
            );
            let header = format!("Bearer {bound}");
            let (with_bound, _, _) = rig
                .send_bare(
                    "POST",
                    path,
                    Some(body.clone()),
                    &[("authorization", header.as_str())],
                )
                .await;
            assert_eq!(
                with_bound, anon,
                "an audience-bound door token is no credential on POST {path}"
            );
            let (plain, _, _) = rig.send("POST", path, Some(body.clone())).await;
            assert!(
                plain != 401 && plain != 403,
                "a keyed caller is admitted on the convenience route POST {path}: {plain}"
            );
            walked.push(path.to_string());
        }
        walked
    }

    #[cfg(linked_driver_proofs)]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_audience_bound_token_is_confined_to_its_door_plane_through_the_composition() {
        const POOLS: &str = "BUSBAR_DOOR_BOUNDARY_POOLS_AUDIENCE";
        const RESULT: &str = "DOOR-BOUNDARY-POOLS ";
        if let Ok(audience) = std::env::var(POOLS) {
            let moved = pools_door_walk(&audience).await;
            println!("{RESULT}{}", serde_json::to_string(&moved).unwrap());
            return;
        }
        let _one = PUBLISHING.lock().await;
        let instance = "door-boundary-confined";
        let server = TlsToolServer::new().await;
        let port = server.port;
        let upstream_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base_url = format!("http://{}", upstream_listener.local_addr().unwrap());
        let upstream = tokio::spawn(async move {
            let router = axum::Router::new().fallback(|| async {
                axum::Json(serde_json::json!({
                    "id":"msg-door-boundary", "type":"message", "role":"assistant",
                    "model":"test-model", "content":[{"type":"text","text":"hello"}],
                    "stop_reason":"end_turn", "stop_sequence":null,
                    "usage":{"input_tokens":1,"output_tokens":1}
                }))
            });
            axum::serve(upstream_listener, router).await.unwrap();
        });
        let row = row();
        registry(row);
        let slot = slot_over(row, server.section());
        let (audience, metadata) = (row.admission)(&*slot)
            .map(|a| (a.audience, a.resource_metadata))
            .expect("the door binds an audience under the public base URL");
        let rig = super::tool_door::Rig::try_with_async(
            instance,
            port,
            None,
            None,
            Some(server.section()),
            server.footing(),
            &async |app| {
                std::env::set_var("BUSBAR_DOOR_BOUNDARY_UPSTREAM_KEY", "busbar-upstream-key");
                let library_path = crate::root::test_plugins::application_store_library();
                let statement = crate::root::loader::dispatch::rendering_of_library(&library_path)
                    .unwrap()
                    .expect("the actual store states itself");
                let module = busbar_contract::abi::mechanism::rendering::read(&statement)
                    .unwrap()
                    .name;
                let settings = crate::root::test_plugins::application_store_settings(
                    std::path::Path::new(&app.plugins_cfg.dir),
                );
                let deploy = busbar_kernel::config::deploy_from_deserializer(serde_json::json!({
                    "providers":{"anthropic":{"api_key":{"env":"BUSBAR_DOOR_BOUNDARY_UPSTREAM_KEY"}}},
                    "models":{"test-model":{"provider":"anthropic"}},
                    "pools":{"pa":{"members":[{"model":"test-model","weight":1}]}},
                    "auth":{"chain":[],"admin_auth":[]},
                    "store":{"module":module,"settings":settings},
                    "advanced":{"allow_destinations":["127.0.0.1"]}
                })).expect("the actual model deployment parses");
                let defs = std::collections::HashMap::from([(
                    "anthropic".to_string(),
                    serde_yaml::from_str::<busbar_kernel::config::ProviderDef>(&format!(
                        "protocol: anthropic\nbase_url: {base_url}\n"
                    ))
                    .expect("the actual upstream definition parses"),
                )]);
                let cfg = busbar_kernel::config::resolve(&deploy, &defs)
                    .expect("the actual model deployment resolves");
                let rules = Arc::clone(&app.root_rules);
                let (mut next, rotate, limits) = crate::root::real_store::build_app(
                    cfg,
                    app.plugins_cfg.clone(),
                    None,
                    Default::default(),
                    Default::default(),
                    (None, None),
                    Some(&app),
                    &rules,
                )
                .await
                .expect("the actual root installs the model and its pool");
                limits.keep().await.expect("the model limits commit");
                if let Some(rotate) = rotate {
                    rotate.await;
                }
                next.auth = Arc::clone(&app.auth);
                next.serve_tables = app.serve_tables.clone();
                next.cost = Arc::clone(&app.cost);
                dispatched(next, row, &slot)
            },
        ).await.expect("the door plane composes");

        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let verifier = TokenVerifier::single(signer.kid(), signer.verifying_key());
        let generation = verifier
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound_token = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );

        let mut routes = busbar_kernel::base_data_core_lines(&rig.app)
            .into_iter()
            .map(|(path, method, auth)| (path, method.as_str().to_string(), auth))
            .collect::<Vec<_>>();
        routes.extend(rig.door_table.iter().cloned());
        let admissible: Vec<String> = rig
            .door_table
            .iter()
            .filter(|(_, _, auth)| *auth != RouteAuth::None)
            .map(|(p, _, _)| p.clone())
            .collect();
        assert!(!admissible.is_empty(), "the door mounts its endpoint");
        let metadata_path = metadata
            .split_once("://")
            .and_then(|(_, rest)| rest.find('/').map(|at| rest[at..].to_string()))
            .expect("the metadata document's path");
        let declared_public: Vec<String> = vec![
            "/healthz".to_string(),
            "/auth/token".to_string(),
            metadata_path,
        ];
        for public in &declared_public {
            assert!(
                routes
                    .iter()
                    .any(|(path, _, auth)| path == public && *auth == RouteAuth::None),
                "{public} is declared unauthenticated-by-design but no route mounts it with \
                 RouteAuth::None — the bypass set this names is not the one the router built"
            );
        }
        let boot_plugin_paths: Vec<String> = busbar_kernel::boot_route_paths_of(&rig.app);

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let router = rig.router.clone();
        let handle = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = reqwest::Client::new();

        fn concrete(pattern: &str) -> String {
            let mut out = String::new();
            for seg in pattern.split('/').skip(1) {
                out.push('/');
                if seg.starts_with('{') && seg.ends_with('}') {
                    out.push_str(match seg {
                        "{name}" => "pa",
                        "{provider}" => "anthropic",
                        "{model}" => "test-model",
                        other => panic!(
                            "route pattern segment {other} has no fixture value: give it one, \
                             never skip the route"
                        ),
                    });
                } else {
                    out.push_str(seg);
                }
            }
            if out.is_empty() {
                "/".to_string()
            } else {
                out
            }
        }
        let body = serde_json::json!({
            "model": "pa",
            "messages": [{"role": "user", "content": "hi"}],
            "max_tokens": 16
        })
        .to_string();
        let send = |method: reqwest::Method, url: String, bearer: Option<String>| {
            let mut req = client.request(method, url).body(body.clone());
            if let Some(b) = bearer {
                req = req.header("authorization", format!("Bearer {b}"));
            }
            req.send()
        };

        let (mut checked, mut door_checked) = (0usize, 0usize);
        for (pattern, verb, auth) in &routes {
            let path = concrete(pattern);
            if *auth == RouteAuth::None {
                assert!(
                    declared_public.contains(pattern),
                    "{pattern} is mounted RouteAuth::None but is not in declared_public — an \
                     unauthenticated route must be a deliberate, reviewed act"
                );
                continue;
            }
            let method = reqwest::Method::from_bytes(verb.as_bytes()).unwrap();
            let url = format!("http://{addr}{path}");
            if admissible.contains(pattern) {
                let anon = send(method.clone(), url.clone(), None).await.unwrap();
                assert_eq!(anon.status(), 401, "anonymous on the door, {verb} {path}");
                assert!(
                    anon.headers()
                        .get("www-authenticate")
                        .and_then(|v| v.to_str().ok())
                        .is_some_and(
                            |v| v.starts_with("Bearer ") && v.contains("resource_metadata=")
                        ),
                    "a 401 on an OAuth protected resource carries a Bearer challenge naming its \
                     resource_metadata, {verb} {path}"
                );
                let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                    .await
                    .unwrap();
                assert_ne!(
                    bound.status(),
                    401,
                    "the bound token is admitted, {verb} {path}"
                );
                let plain = send(method.clone(), url.clone(), Some(rig.token.clone()))
                    .await
                    .unwrap();
                assert_eq!(
                    plain.status(),
                    401,
                    "a plain key is inadmissible, {verb} {path}"
                );
                door_checked += 1;
                continue;
            }

            let anon = send(method.clone(), url.clone(), None)
                .await
                .unwrap()
                .status();
            let bound = send(method.clone(), url.clone(), Some(bound_token.clone()))
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "an audience-bound door token is no credential on {verb} {path}"
            );
            let plain = send(method, url, Some(rig.token.clone()))
                .await
                .unwrap()
                .status();
            assert_ne!(
                plain, anon,
                "the plain sibling is admitted on {verb} {path}"
            );
            checked += 1;
        }
        assert_eq!(
            door_checked,
            routes
                .iter()
                .filter(|(p, _, _)| admissible.contains(p))
                .count(),
            "every admissible mounted route was walked"
        );
        assert!(
            door_checked > 0,
            "the door's half of the boundary was asserted"
        );

        let exact = std::thread::current().name().unwrap().to_string();
        let audience_for_child = audience.clone();
        let output = tokio::task::spawn_blocking(move || {
            std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &exact, "--nocapture"])
                .env(POOLS, audience_for_child)
                .output()
                .expect("run the pools deployment with its own native price owner")
        })
        .await
        .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "the pools boundary walk failed: {stdout}\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let moved: Vec<String> = serde_json::from_str(
            stdout
                .lines()
                .find_map(|line| line.strip_prefix(RESULT))
                .expect("the pools child completed its guarded route walk"),
        )
        .unwrap();
        checked += moved.len();

        for path in [
            "/v1/models",
            "/v1beta/models",
            "/p/v1/messages",
            "/oai0/m0/v1/messages",
        ] {
            assert!(
                moved.iter().any(|walked| walked == path),
                "{path} moved onto the pools door and must be walked guarded there: {moved:?}"
            );
        }

        assert!(
            checked >= 5,
            "the walk covered only {checked} guarded routes — it is not seeing the router"
        );
        for path in &boot_plugin_paths {
            let url = format!("http://{addr}{path}");
            let anon = client.get(&url).send().await.unwrap().status();
            let bound = client
                .get(&url)
                .header("authorization", format!("Bearer {bound_token}"))
                .send()
                .await
                .unwrap()
                .status();
            assert_eq!(
                bound, anon,
                "a bound token is no credential on plugin route {path}"
            );
        }
        handle.abort();
        upstream.abort();
        let _ = upstream.await;
        server.close().await;
    }

    fn fixture_operator_chain(
        app: &busbar_kernel::state::App,
        auth_cfg: &busbar_kernel::config::AuthCfg,
    ) -> Arc<busbar_kernel::auth::AdminAuthChain> {
        let mut modules = busbar_kernel::auth::AdminAuthChain::build(
            auth_cfg,
            &app.hook_env.registry,
            &app.secret_resolver,
        )
        .expect("the actual root opens the admin chain");

        modules.operator = busbar_kernel::auth::open_operator(
            &app.hook_env.registry,
            app.governance
                .as_ref()
                .and_then(|gov| gov.admin_token_hash()),
            &app.identity_providers,
        )
        .expect("the actual operator opens against its configured credential");
        Arc::new(modules)
    }

    async fn admin(
        rig: &super::tool_door::Rig,
        method: &str,
        path: &str,
    ) -> (u16, serde_json::Value) {
        admin_on(&rig.app, method, path).await
    }

    async fn admin_on(
        app: &Arc<busbar_kernel::state::App>,
        method: &str,
        path: &str,
    ) -> (u16, serde_json::Value) {
        use tower::ServiceExt as _;
        let req = axum::http::Request::builder()
            .method(method)
            .uri(format!("/api/v1/admin{path}"))
            .header("x-admin-token", ADMIN_TOKEN)
            .body(axum::body::Body::empty())
            .expect("a request");
        let router = busbar_core_admin::build_router(Arc::clone(app));
        let response = router.oneshot(req).await.expect("answers");
        let status = response.status().as_u16();
        let bytes = axum::body::to_bytes(response.into_body(), 1 << 20)
            .await
            .expect("the body");
        (status, serde_json::from_slice(&bytes).unwrap_or_default())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_trust_verbs_report_the_drift_an_operator_has_to_work() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-trust-verbs";
        let schema =
            serde_json::json!({"type": "object", "properties": {"path": {"type": "string"}}});
        let description = "reads a file from disk";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": description, "inputSchema": schema}
        ])));
        let mut server = super::tool_door::TlsToolServer::listing(Arc::clone(&listed)).await;
        let digest = super::tool_door::surface("tool_digest");
        let tools = server.section();
        let row = row();
        registry(row);
        let slot = slot_over(row, tools.clone());

        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let rig = server
            .rig(instance, tools, &|mut app| {
                let auth_cfg = busbar_kernel::config::AuthCfg {
                    admin_auth: chain
                        .iter()
                        .map(busbar_kernel::config::AuthChainEntry::bare)
                        .collect(),
                    ..busbar_kernel::config::AuthCfg::default_none()
                };
                app.admin_modules = fixture_operator_chain(&app, &auth_cfg);
                app.admin_chain = chain.clone();
                dispatched(app, row, &slot)
            })
            .await;

        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "connect is mounted and served by the door: {body}"
        );
        assert_eq!(body["state"], "approved", "{body}");
        assert_eq!(body["observed_tools"], 1, "{body}");
        assert_eq!(body["capabilities"][0]["status"], "approved", "{body}");
        assert_eq!(body["capabilities"][0]["approved_digest"], digest, "{body}");
        assert!(
            server
                .heard
                .try_recv()
                .is_ok_and(|r| r.contains("\"tools/list\"")),
            "the server was asked for its tool list"
        );

        let audience = (row.admission)(&*slot).expect("an audience").audience;
        let signer = TokenSigner::from_secret_bytes(&[7u8; 32], DEFAULT_KID);
        let generation = TokenVerifier::single(signer.kid(), signer.verifying_key())
            .verify(&rig.token, 1_700_000_000, None)
            .expect("plain claims")
            .generation;
        let bound = signer.mint_for_audience(
            &rig.key.id,
            4_000_000_000,
            generation.as_deref(),
            &audience,
            Some("client-1"),
        );
        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&body));
        let heard_now: Vec<String> = std::iter::from_fn(|| server.heard.try_recv().ok()).collect();
        assert!(
            heard_now.len() == 1 && heard_now[0].contains("\"tools/call\""),
            "the connect's look is fresh, so the call fetches no list: {heard_now:?}"
        );

        let (status, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            (body["serving"].clone(), body["contacted"].clone()),
            (true.into(), true.into()),
            "{body}"
        );

        *listed.lock().expect("the list") = serde_json::json!([
            {"name": "read_file", "description": description,
             "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}, "webhook_url": {"type": "string"}}}}
        ]);
        let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            status, 200,
            "a refresh that finds a drift succeeded: {body}"
        );
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]), "{body}");
        let _ = server.heard.try_recv();

        let (status, body) = admin(&rig, "GET", "/tools/fs/changes").await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(body["state"], "quarantined", "{body}");
        assert_eq!(body["changed"], serde_json::json!(["read_file"]));
        assert!(
            server.heard.try_recv().is_err(),
            "`changes` contacts nothing"
        );

        let (_, body) = admin(&rig, "GET", "/tools/fs/health").await;
        assert_eq!(body["serving"], false, "{body}");

        let (status, body) =
            super::tool_door::send(&rig.router, Some(&bound), super::tool_door::CALL).await;
        assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&body));
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(body["error"]["data"]["reason"], "quarantined", "{body}");

        let mut wire = Vec::new();
        while let Ok(r) = server.heard.try_recv() {
            wire.push(r);
        }
        assert!(
            wire.iter().all(|r| !r.contains("\"tools/call\"")),
            "the refused call never reached the wire: {wire:?}"
        );

        for (method, path) in [
            ("POST", "/tools/nope/connect"),
            ("GET", "/tools/nope/changes"),
            ("GET", "/tools/nope/health"),
        ] {
            let (status, body) = admin(&rig, method, path).await;
            assert_eq!(status, 404, "{method} {path}: {body}");
            assert_eq!(body["error"]["code"], "not_found", "{body}");
        }
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_fetches_with_the_members_binding_and_never_for_a_passthrough_member() {
        const EXACT: &str = concat!(
            module_path!(),
            "::connect_fetches_with_the_members_binding_and_never_for_a_passthrough_member"
        );
        let Some(case) = super::isolated_fixture_cases(EXACT, &["exchange", "passthrough"]) else {
            return;
        };
        let _one = PUBLISHING.lock().await;
        std::env::set_var(
            "BUSBAR_DOOR_CONNECT_TEST_SUBJECT",
            "busbar-own-connect-subject",
        );
        let listed = || {
            Arc::new(std::sync::Mutex::new(serde_json::json!([
                {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
                 "inputSchema": super::tool_door::tool_schema()}
            ])))
        };
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let row = row();
        registry(row);

        if case == "exchange" {
            let instance = "door-connect-exchange";
            let mut server = super::tool_door::TlsToolServer::listing(listed()).await;
            let mut tools = connect_section(&server, true);
            tools["fs"]["token_exchange"]["subject_token"]["env"] =
                "BUSBAR_DOOR_CONNECT_TEST_SUBJECT".into();
            let slot = slot_over(row, tools.clone());
            let rig = server
                .rig(instance, tools, &|mut app| {
                    let auth_cfg = busbar_kernel::config::AuthCfg {
                        admin_auth: chain
                            .iter()
                            .map(busbar_kernel::config::AuthChainEntry::bare)
                            .collect(),
                        ..busbar_kernel::config::AuthCfg::default_none()
                    };
                    app.admin_modules = fixture_operator_chain(&app, &auth_cfg);
                    app.admin_chain = chain.clone();
                    dispatched(app, row, &slot)
                })
                .await;
            let (status, body) = admin(&rig, "POST", "/tools/fs/connect").await;
            assert_eq!(status, 200, "{body}");
            assert_eq!(body["state"], "approved", "{body}");
            let list = server
                .heard
                .try_recv()
                .expect("the server was asked for its tool list")
                .to_ascii_lowercase();
            assert!(
                list.contains("authorization: bearer tok-fs_read_file"),
                "connect presents the token exchanged for the registration's approved set: {list}"
            );
            let exchanges = super::tool_door::exchanges(&rig);
            assert_eq!(exchanges.len(), 1, "{exchanges:?}");
            assert_eq!(
                super::tool_door::form_value(&exchanges[0].1, "subject_token"),
                "busbar-own-connect-subject",
                "busbar's own subject token"
            );
            server.close().await;
            super::isolated_fixture_done(EXACT, &case);
            return;
        }

        let mut server = super::tool_door::TlsToolServer::listing(listed()).await;
        let mut tools = server.section();
        tools["fs"]["upstream_credentials"] = "passthrough".into();
        let error = match server
            .try_rig("door-connect-passthrough", tools, &|mut app| {
                let auth_cfg = busbar_kernel::config::AuthCfg {
                    admin_auth: chain
                        .iter()
                        .map(busbar_kernel::config::AuthChainEntry::bare)
                        .collect(),
                    ..busbar_kernel::config::AuthCfg::default_none()
                };
                app.admin_modules = fixture_operator_chain(&app, &auth_cfg);
                app.admin_chain = chain.clone();
                app
            })
            .await
        {
            Ok(_) => panic!("caller credential forwarding must be refused"),
            Err(error) => error,
        };
        super::tool_door::assert_member_passthrough_refused(
            &error,
            "door-connect-passthrough",
            "fs",
        );
        assert!(server.heard.try_recv().is_err(), "connect fetched nothing");
        server.close().await;
        super::isolated_fixture_done(EXACT, &case);
    }

    const APPLY_SUBJECT_VAR: &str = "BUSBAR_DOOR_APPLY_CONNECT_TEST_SUBJECT";

    fn connect_section(
        server: &super::tool_door::TlsToolServer,
        exchanged: bool,
    ) -> serde_yaml::Value {
        let mut tools = server.section();
        if exchanged {
            tools["fs"]["aud"] = format!("https://127.0.0.1:{}", server.port).into();
            tools["fs"]["token_exchange"] = serde_yaml::from_str(&format!(
                "token_url: \"{}\"\nsubject_token: {{ env: {APPLY_SUBJECT_VAR} }}\n",
                super::tool_door::TOKEN_URL,
            ))
            .expect("the exchange binding");
        }
        tools
    }

    async fn connect_across_an_apply(
        instance: &'static str,
        server: &mut super::tool_door::TlsToolServer,
        before: serde_yaml::Value,
        after: serde_yaml::Value,
    ) -> (u16, serde_json::Value, String) {
        std::env::set_var(APPLY_SUBJECT_VAR, "busbar-own-apply-subject");
        busbar_kernel::preflight::install_linked_auth(
            crate::LINKED.auths,
            crate::root::auth_bindings::operator_words(),
        );
        let chain = vec![busbar_kernel::config::operator_provider().to_string()];
        let row = row();
        registry(row);
        let booted = slot_over(row, before.clone());
        let rig = server
            .rig(instance, before, &|mut app| {
                let auth_cfg = busbar_kernel::config::AuthCfg {
                    admin_auth: chain
                        .iter()
                        .map(busbar_kernel::config::AuthChainEntry::bare)
                        .collect(),
                    ..busbar_kernel::config::AuthCfg::default_none()
                };
                app.admin_modules = fixture_operator_chain(&app, &auth_cfg);
                app.admin_chain = chain.clone();
                dispatched(app, row, &booted)
            })
            .await;

        let (before_status, before_body) = admin(&rig, "POST", "/tools/fs/connect").await;
        assert_eq!(
            before_status, 200,
            "the pre-apply connect settles: {before_body}"
        );
        while server.heard.try_recv().is_ok() {}
        let generation = rig.live.current().generation;

        let next_slot = slot_over(row, after.clone());
        let mut applied = dispatched((*rig.app).clone(), row, &next_slot);

        applied.plane_slots.insert(instance, next_slot);
        let applied = Arc::new(applied);
        rig.live.apply(&applied).await;
        assert_eq!(
            rig.live.current().generation,
            generation + 1,
            "the door took the apply"
        );
        assert_eq!(
            rig.live.current().section["fs"],
            after["fs"],
            "the serving generation took the applied member and its binding"
        );
        let (status, body) = admin_on(&applied, "POST", "/tools/fs/connect").await;
        let list = server
            .heard
            .try_recv()
            .unwrap_or_default()
            .to_ascii_lowercase();
        (status, body, list)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_after_an_apply_presents_the_binding_the_apply_gave_the_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-connect-apply-added";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
             "inputSchema": super::tool_door::tool_schema()}
        ])));
        let mut server = super::tool_door::TlsToolServer::listing(listed).await;
        let before = connect_section(&server, false);
        let after = connect_section(&server, true);
        let (status, body, list) =
            connect_across_an_apply(instance, &mut server, before, after).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            list.contains("authorization: bearer tok-fs_read_file"),
            "connect presents the token the applied binding exchanged: {list}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn connect_after_an_apply_that_keeps_the_member_presents_its_binding() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-connect-apply-kept";
        let listed = Arc::new(std::sync::Mutex::new(serde_json::json!([
            {"name": "read_file", "description": super::tool_door::TOOL_DESCRIPTION,
             "inputSchema": super::tool_door::tool_schema()}
        ])));
        let mut server = super::tool_door::TlsToolServer::listing(listed).await;
        let before = connect_section(&server, true);
        let after = connect_section(&server, true);
        let (status, body, list) =
            connect_across_an_apply(instance, &mut server, before, after).await;
        assert_eq!(status, 200, "{body}");
        assert!(
            list.contains("authorization: bearer tok-fs_read_file"),
            "connect presents the token the member's binding exchanged: {list}"
        );
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod spent_ledger {
    use std::sync::Arc;

    fn durable_cfg(tag: &str) -> (std::path::PathBuf, serde_json::Value) {
        let directory = crate::root::test_plugins::scratch(&format!(
            "{tag}-{}",
            busbar_kernel::door::op_id().counter(),
        ));
        let file = directory.join("continuations.sqlite");
        let settings = serde_json::json!({"db_path":file});
        (file, settings)
    }

    async fn open_durable(
        settings: &serde_json::Value,
    ) -> Arc<busbar_kernel::persistence::facade::CoreStore> {
        use crate::root::loader::dispatch::kinds::store_v4::StoreV4;
        use crate::root::loader::dispatch::{
            load_dropped, rendering_of_library, Bind, ConnTable, DispatchConfig, Dispatcher, NoSink,
        };
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_SQLITE_CDYLIB")
                .expect("BUSBAR_TEST_SQLITE_CDYLIB must name the actual built SQLite product"),
        );
        let stated = rendering_of_library(&path)
            .expect("the actual durable store statement reads")
            .expect("the actual durable store exports its statement");
        let dispatcher = Arc::new(Dispatcher::new(
            DispatchConfig::default(),
            busbar_kernel::host_services::caller_binding(),
        ));
        let plugin = load_dropped::<StoreV4>(
            &path,
            &stated,
            Bind {
                instance: format!("door-spent-{}", busbar_kernel::door::op_id().counter()).into(),
                max_inflight_cap: 1024,
                sink: Arc::new(NoSink),
                dispatcher: dispatcher.adopter(),
                conns: ConnTable::NoNeeds,
            },
        )
        .expect("the actual durable store loads through the memory ABI");
        let backend = crate::root::loader::store_v4::LoadedPersistence::open(
            plugin,
            dispatcher,
            &serde_json::to_vec(settings).unwrap(),
            crate::root::loader::store_v4::Limits {
                descriptor_bytes: 32 * 1024 * 1024,
                output_items: 4096,
                output_bytes: 32 * 1024 * 1024,
                decode_bytes: 32 * 1024 * 1024,
            },
        )
        .await
        .expect("actual SQLite native Store opens its retained file");
        use busbar_contract::persistence::PersistenceBackend;
        assert_ne!(
            backend.info().durability,
            busbar_contract::persistence::Durability::Ephemeral,
            "replay and restart require actual durable product storage"
        );
        crate::root::real_store::core_over(Arc::new(backend)).await
    }

    use super::tool_door::{protocol_version, send_as, Footing, Ledger, Rig, TlsToolServer};
    use crate::root::serve::planes_tests::PUBLISHING;

    const INSTANCE: &str = "door-spent-ledger";

    const SERVER: &str = "bank";
    const PROMPT: &str = "transfer";

    const RENDERED: &str = "Transfer 10 to alice";

    const ALREADY_SPENT: &str = "state_already_spent";

    fn tools(server: &TlsToolServer) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "{SERVER}:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             prompts_allow:\n    {PROMPT}:\n      template: \"{RENDERED}\"\n      \
             ask_caller:\n        - confirm: {{ method: \"elicitation/create\", \
             params: {{ message: \"Confirm the transfer\" }} }}\n"
        ))
        .expect("a section")
    }

    fn gated() -> String {
        format!("{SERVER}_{PROMPT}")
    }

    async fn node(server: &TlsToolServer, ledger: Ledger, book: Option<&Rig>) -> Rig {
        server
            .rig_with_footing(
                INSTANCE,
                tools(server),
                Footing {
                    ledger,
                    book,
                    ..Footing::own()
                },
                &|app| app,
            )
            .await
    }

    type Answer = (u16, serde_json::Value);

    async fn call(rig: &Rig, mut params: serde_json::Value) -> Answer {
        params["_meta"] = serde_json::json!({
            "io.modelcontextprotocol/protocolVersion": protocol_version(),
            "io.modelcontextprotocol/clientCapabilities":
                { "sampling": {}, "elicitation": {}, "roots": { "listChanged": true } },
        });
        let body = serde_json::json!({
            "jsonrpc": "2.0", "id": 1, "method": "prompts/get", "params": params,
        });
        let (status, bytes) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &body.to_string(),
            "prompts/get",
            Some(&gated()),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&bytes).unwrap_or_default(),
        )
    }

    async fn ask(rig: &Rig) -> String {
        let (status, body) = call(rig, serde_json::json!({ "name": gated() })).await;
        assert_eq!(
            status, 200,
            "the opening round must ask, not refuse: {body}"
        );
        assert!(
            body.pointer("/result/messages").is_none(),
            "the opening round must not render the gated prompt: {body}"
        );
        body.pointer("/result/requestState")
            .and_then(|v| v.as_str())
            .unwrap_or_else(|| panic!("the opening round must issue continuation state: {body}"))
            .to_string()
    }

    async fn redeem(rig: &Rig, state: &str) -> Answer {
        call(
            rig,
            serde_json::json!({
                "name": gated(),
                "requestState": state,
                "inputResponses": { "confirm": { "action": "accept", "content": {} } },
            }),
        )
        .await
    }

    fn proceeded(answer: &Answer) -> bool {
        answer.0 == 200
            && answer.1.pointer("/result/messages/0/content/text") == Some(&RENDERED.into())
    }

    fn refused_as_spent(answer: &Answer) -> bool {
        answer.0 == 400
            && answer
                .1
                .pointer("/error/data/reason")
                .and_then(|r| r.as_str())
                == Some(ALREADY_SPENT)
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_second_fleet_node_cannot_redeem_an_approval_the_first_already_spent() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let (file, cfg) = durable_cfg("door-askstate-fleet");
        let node_a = node(&server, Ledger::Store(open_durable(&cfg).await), None).await;
        let node_b = node(
            &server,
            Ledger::Store(open_durable(&cfg).await),
            Some(&node_a),
        )
        .await;
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            refused_as_spent(&second),
            "a second node of the deployment redeemed an approval already spent: {second:?}; the \
             shared durable database: {}",
            file.display()
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_restarted_node_cannot_redeem_an_approval_the_previous_process_spent() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let (_file, cfg) = durable_cfg("door-askstate-restart");
        let before = node(&server, Ledger::Store(open_durable(&cfg).await), None).await;
        let state = ask(&before).await;
        let first = redeem(&before, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let after = node(
            &server,
            Ledger::Store(open_durable(&cfg).await),
            Some(&before),
        )
        .await;
        drop(before);
        let second = redeem(&after, &state).await;
        assert!(
            refused_as_spent(&second),
            "a restart handed a spent approval back: {second:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_fresh_approval_is_not_refused_by_a_ledger_holding_another() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let (_file, cfg) = durable_cfg("door-askstate-distinct");
        let node_a = node(&server, Ledger::Store(open_durable(&cfg).await), None).await;
        let node_b = node(
            &server,
            Ledger::Store(open_durable(&cfg).await),
            Some(&node_a),
        )
        .await;
        let first = ask(&node_a).await;
        let spent = redeem(&node_a, &first).await;
        assert!(
            proceeded(&spent),
            "the first approval dispatches: {spent:?}"
        );
        let second = ask(&node_a).await;
        assert_ne!(first, second, "two mints differ");
        let answer = redeem(&node_b, &second).await;
        assert!(
            proceeded(&answer),
            "a freshly minted approval is not the one spent: {answer:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_node_refuses_its_own_replay_with_no_durable_store_configured() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let solo = node(&server, Ledger::Unbound, None).await;
        let state = ask(&solo).await;
        let first = redeem(&solo, &state).await;
        assert!(
            proceeded(&first),
            "the first redemption dispatches: {first:?}"
        );
        let second = redeem(&solo, &state).await;
        assert!(
            refused_as_spent(&second),
            "single use per node must hold with no store: {second:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn two_nodes_sharing_no_store_each_redeem_once_which_is_the_documented_ram_posture() {
        let _one = PUBLISHING.lock().await;
        let server = TlsToolServer::new().await;
        let node_a = node(&server, Ledger::Unbound, None).await;
        let node_b = node(&server, Ledger::Unbound, Some(&node_a)).await;
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let second = redeem(&node_b, &state).await;
        assert!(
            proceeded(&second),
            "with no shared ledger node B has nothing to consult: {second:?}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_memory_store_shares_no_ledger_which_is_the_documented_contract() {
        const CHILD: &str = "BUSBAR_DOOR_INDEPENDENT_MEMORY_NODE";
        const DONE: &str = "INDEPENDENT-MEMORY-REDEEMED";
        #[derive(serde::Serialize, serde::Deserialize)]
        struct Handoff {
            port: u16,
            ca: Vec<u8>,
            tools: serde_yaml::Value,
            key: busbar_contract::records::VirtualKey,
            token: String,
            state: String,
        }
        let _one = PUBLISHING.lock().await;
        if std::env::var_os(CHILD).is_some() {
            use std::io::Read as _;
            let mut bytes = zeroize::Zeroizing::new(Vec::new());
            std::io::stdin().read_to_end(&mut bytes).unwrap();
            let handoff: Handoff = serde_json::from_slice(&bytes).unwrap();
            let tls = busbar_core_connector::tls::client::build_client_config(
                &busbar_contract::transport::trust::EgressTrust {
                    extra_anchors: vec![handoff.ca],
                    ..Default::default()
                },
            )
            .expect("the second node verifies the same actual server");
            let backend = crate::root::real_store::native_backend().await;
            assert_eq!(
                backend.info().durability,
                busbar_contract::persistence::Durability::Ephemeral,
                "the second node owns an actual independent native Memory store"
            );
            let core = crate::root::real_store::core_over(backend).await;
            core.identity()
                .put_key(&handoff.key)
                .await
                .expect("seed the same native caller before opening its governance and auth host");
            let row = super::door_boundary::row();
            super::door_boundary::registry(row);
            let slot = super::door_boundary::slot_over(row, handoff.tools.clone());
            let mut node_b = Rig::with(
                INSTANCE,
                handoff.port,
                None,
                None,
                Some(handoff.tools),
                Footing {
                    tls: Some(Arc::new(tls)),
                    ledger: Ledger::Store(core),
                    ..Footing::own()
                },
                &|app| super::door_boundary::dispatched(app, row, &slot),
            )
            .await;
            assert!(
                Arc::ptr_eq(node_b.app.governance.as_ref().unwrap(), &node_b.gov),
                "the HTTP App retains this independent node's native governance owner"
            );
            let admission = node_b
                .app
                .planes
                .admission_for(&super::tool_door::endpoint())
                .expect("the actual HTTP door retains its configured plane admission");
            assert_eq!(
                Some(admission.audience.as_str()),
                node_b.audience.as_deref(),
                "HTTP authentication checks the audience bound by this real door"
            );
            node_b.key = Arc::new(handoff.key);
            node_b.token = handoff.token;
            assert!(
                node_b
                    .gov
                    .verify_token(
                        &node_b.bound_token(),
                        busbar_kernel::store::now(),
                        node_b.audience.as_deref()
                    )
                    .is_some(),
                "the independent node admits the exact original signed caller"
            );
            let second = redeem(&node_b, &handoff.state).await;
            assert!(
                proceeded(&second),
                "an in-memory store per node keeps nothing the other reads: {second:?}"
            );
            println!("{DONE}");
            return;
        }
        let server = TlsToolServer::new().await;
        let node_a = node(&server, Ledger::Memory, None).await;
        let state = ask(&node_a).await;
        let first = redeem(&node_a, &state).await;
        assert!(
            proceeded(&first),
            "node A's redemption dispatches: {first:?}"
        );
        let handoff = Handoff {
            port: server.port,
            ca: server.ca_der.clone(),
            tools: tools(&server),
            key: (*node_a.key).clone(),
            token: node_a.token.clone(),
            state,
        };
        let bytes = zeroize::Zeroizing::new(serde_json::to_vec(&handoff).unwrap());
        let exact = std::thread::current().name().unwrap().to_string();
        tokio::task::spawn_blocking(move || {
            use std::io::Write as _;
            let mut child = std::process::Command::new(std::env::current_exe().unwrap())
                .args(["--exact", &exact, "--nocapture"])
                .env(CHILD, "1")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .spawn()
                .expect("start a second independent native Memory node");
            child.stdin.take().unwrap().write_all(&bytes).unwrap();
            let output = child.wait_with_output().unwrap();
            assert!(
                output.status.success(),
                "the independent native node failed: {}",
                output.status
            );
            assert!(
                String::from_utf8_lossy(&output.stdout).contains(DONE),
                "node B completed its original redemption assertion"
            );
        })
        .await
        .unwrap();
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod upstream_ask_relay {
    use std::sync::Arc;

    use super::tool_door::{send, tool_digest, tool_listing, Rig, TlsToolServer, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    const INSTANCE: &str = "door-ask-relay";

    const ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"draft":{"method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":4096}}},"requestState":"s"}}"#;

    async fn asking_server() -> TlsToolServer {
        TlsToolServer::answering(Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                ASK.to_string()
            }
        }))
        .await
    }

    fn tools(server: &TlsToolServer, granted: bool) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  \
             pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             grants: {{ sampling: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\" }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    async fn call(rig: &Rig, body: &str) -> (u16, serde_json::Value) {
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), body).await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    fn retry(state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = serde_json::json!({ "draft": { "role": "assistant", "content": { "type": "text", "text": "the caller's own draft" } } });
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_granted_ask_reaches_the_caller_verbatim_and_its_retry_goes_back_to_the_member() {
        let _one = PUBLISHING.lock().await;
        let mut server = asking_server().await;
        let rig = server.rig(INSTANCE, tools(&server, true), &|app| app).await;
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 200, "{body}");
        let upstream: serde_json::Value = serde_json::from_str(ASK).expect("the ask");
        assert_eq!(
            body["result"]["inputRequests"], upstream["result"]["inputRequests"],
            "the upstream's requests reach the caller byte for byte: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's state")
            .to_string();
        assert_ne!(
            state, "s",
            "the upstream's own state is nested in busbar's sealed one"
        );
        let verify = server
            .heard
            .try_recv()
            .expect("verify-on-call fetched the tool list");
        assert!(verify.contains("\"tools/list\""), "{verify}");
        let first = server
            .heard
            .try_recv()
            .expect("the call reached the server");
        assert!(!first.contains("inputResponses"), "{first}");
        assert!(
            server.heard.try_recv().is_err(),
            "busbar answered nothing upstream on the caller's behalf"
        );

        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 200, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered by the caller",
            "{body}"
        );
        let mut sent = None;
        while let Ok(request) = server.heard.try_recv() {
            if request.contains("inputResponses") {
                sent = Some(request);
            }
        }

        let sent = sent.expect("the retry reached the member");
        let body = sent
            .split_once("\r\n\r\n")
            .map_or(sent.as_str(), |(_, b)| b);
        let sent: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(sent["params"]["requestState"], "s", "{sent}");
        assert_eq!(
            sent["params"]["inputResponses"]["draft"]["content"]["text"], "the caller's own draft",
            "{sent}"
        );

        let (status, body) = call(&rig, &retry(&state)).await;
        assert_eq!(status, 400, "a spent state is refused: {body}");

        let (status, body) = call(&rig, &retry("forged")).await;
        assert_eq!(status, 400, "a forged state is refused: {body}");
        assert_eq!(body["error"]["data"]["reason"], "state_malformed", "{body}");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_is_refused_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let server = asking_server().await;
        let rig = server
            .rig(INSTANCE, tools(&server, false), &|app| app)
            .await;
        let (status, body) = call(&rig, CALL).await;
        assert_eq!(status, 403, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_ungranted", "{body}");
        assert!(body.get("result").is_none(), "{body}");
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
#[path = "door_listen.rs"]
mod door_listen;

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod task_continuation {
    use busbar_kernel::governance::NewKeySpec;

    use super::tool_door::{
        protocol_version, send_as, tool_digest, tool_listing, Footing, Ledger, Rig, Rows,
        TlsToolServer, CALL,
    };
    use crate::root::serve::planes_tests::PUBLISHING;

    const TASKS: &str = "io.modelcontextprotocol/tasks";

    const ANSWER: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"content":[{"type":"text","text":"from the server"}]}}"#;

    fn tools(server: &TlsToolServer, support: &str) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: {support} }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    fn declared() -> serde_json::Value {
        serde_json::json!({ "extensions": { TASKS: {} } })
    }

    fn task_call() -> String {
        let mut call: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] = declared();
        call.to_string()
    }

    fn verb(method: &str, task_id: &str) -> String {
        serde_json::json!({
            "jsonrpc": "2.0",
            "id": 41,
            "method": method,
            "params": {
                "taskId": task_id,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": protocol_version(),
                    "io.modelcontextprotocol/clientCapabilities": declared(),
                },
            },
        })
        .to_string()
    }

    async fn ask(rig: &Rig, token: &str, method: &str, task_id: &str) -> (u16, serde_json::Value) {
        let (status, body) = send_as(
            &rig.router,
            Some(token),
            &verb(method, task_id),
            method,
            Some(task_id),
        )
        .await;
        (
            status.as_u16(),
            serde_json::from_slice(&body).expect("JSON-RPC"),
        )
    }

    const HANG_GUARD: std::time::Duration = std::time::Duration::from_secs(120);

    async fn until(rig: &Rig, task_id: &str, status: &str) -> serde_json::Value {
        let deadline = tokio::time::Instant::now() + HANG_GUARD;
        while tokio::time::Instant::now() < deadline {
            let (_, body) = ask(rig, &rig.bound_token(), "tasks/get", task_id).await;
            if body["result"]["status"] == status {
                return body;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        panic!("task {task_id} never reached `{status}`");
    }

    async fn gated_server(release: tokio::sync::watch::Receiver<bool>) -> TlsToolServer {
        TlsToolServer::gated(release, ANSWER).await
    }

    async fn next_call(heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>) -> String {
        let wait = async {
            loop {
                let request = heard.recv().await.expect("the server hears");
                if request.contains("\"tools/call\"") {
                    return request;
                }
            }
        };
        tokio::time::timeout(HANG_GUARD, wait)
            .await
            .expect("the upstream call ran")
    }

    async fn create(rig: &Rig) -> (serde_json::Value, String) {
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a taskId")
            .to_string();
        (body, task_id)
    }

    fn observed_count(rig: &Rig) -> usize {
        rig.work_observations
            .lock()
            .expect("the host observations")
            .len()
    }

    fn assert_task_ttl(
        rig: &Rig,
        body: &serde_json::Value,
        task_id: &str,
        since: usize,
    ) -> busbar_contract::abi::mechanism::inspection::WorkObservation {
        let result = &body["result"];
        assert_eq!(result["taskId"], task_id, "the exact observed work");
        let stamp = result["createdAt"]
            .as_str()
            .expect("the real task creation timestamp");
        assert_eq!(
            stamp.len(),
            24,
            "the task's UTC millisecond timestamp: {stamp}"
        );
        let number = |range: std::ops::Range<usize>| {
            stamp[range].parse::<u64>().expect("timestamp component")
        };
        let target = (
            number(0..4) as i64,
            number(5..7) as u32,
            number(8..10) as u32,
        );
        let (mut lo, mut hi) = (0i64, 3_000_000i64);
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            if busbar_contract::civil::civil_from_days(mid) < target {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        assert_eq!(busbar_contract::civil::civil_from_days(lo), target);
        let seconds = u64::try_from(lo)
            .unwrap()
            .checked_mul(86_400)
            .unwrap()
            .checked_add(number(11..13).checked_mul(3600).unwrap())
            .unwrap()
            .checked_add(number(14..16).checked_mul(60).unwrap())
            .unwrap()
            .checked_add(number(17..19))
            .unwrap();
        let millis = number(20..23);
        let rendered = busbar_contract::civil::rfc3339_from_secs(seconds);
        assert_eq!(
            format!("{}.{millis:03}Z", rendered.trim_end_matches('Z')),
            stamp
        );
        let created_ms = seconds
            .checked_mul(1000)
            .unwrap()
            .checked_add(millis)
            .unwrap();
        let ttl = result["ttlMs"].as_u64().expect("an integer TTL");
        let observations = rig.work_observations.lock().expect("the host observations");
        let candidates: Vec<_> = observations[since..]
            .iter()
            .filter(|seen| seen.reference == task_id.as_bytes() && seen.instance == rig.instance)
            .collect();
        assert!(
            !candidates.is_empty(),
            "the response inspected its own work {task_id}"
        );
        let seen = candidates
            .into_iter()
            .find(|seen| {
                let o = seen.observation;
                o.settled_ms
                    .unwrap_or(o.observed_ms)
                    .checked_add(o.retain_ms)
                    .and_then(|horizon| horizon.checked_sub(created_ms))
                    == Some(ttl)
            })
            .expect("the exact wire TTL is the real host horizon minus task creation");
        assert!(
            seen.observation.opened_ms >= created_ms,
            "work opens after task creation"
        );
        assert_eq!(
            seen.observation.retain_ms, 300_000,
            "the host's actual retention policy"
        );
        seen.observation
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_call_answers_a_task_and_its_upstream_call_runs_without_a_poll() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-runs";
        let (release, gate) = tokio::sync::watch::channel(false);
        let mut server = gated_server(gate).await;
        let rig = server
            .rig(instance, tools(&server, "optional"), &|app| app)
            .await;

        let observed_before = observed_count(&rig);
        let (body, task_id) = create(&rig).await;
        let result = &body["result"];
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(result["resultType"], "task", "{body}");
        assert_eq!(result["status"], "working", "{body}");
        let observation = assert_task_ttl(&rig, &body, &task_id, observed_before);
        assert!(
            observation.settled_ms.is_none(),
            "a live task has no established expiry"
        );
        assert_eq!(result["pollIntervalMs"], 250, "{body}");
        assert_eq!(result["content"], serde_json::json!([]), "{body}");
        assert_eq!(
            task_id.len(),
            32,
            "the work handle's 128-bit reference: {task_id}"
        );
        for absent in ["result", "error", "inputRequests", "requestState"] {
            assert!(
                result.get(absent).is_none(),
                "`{absent}` is tasks/get's: {body}"
            );
        }

        let call = next_call(&mut server.heard).await;
        assert!(call.starts_with("POST /rpc "), "{call}");

        let (status, working) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{working}");
        assert_eq!(working["result"]["status"], "working", "{working}");
        assert_eq!(working["result"]["resultType"], "complete", "{working}");
        assert!(working["result"].get("result").is_none(), "{working}");

        release.send_replace(true);
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(done["id"], 41, "{done}");
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
        assert!(done["result"].get("error").is_none(), "{done}");

        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("every unit ended");
        assert_eq!(
            rig.admitted().await,
            2,
            "the creating unit and its continuation"
        );

        let records = rig
            .book
            .durability
            .lock()
            .expect("unpoisoned")
            .audit_records
            .clone();
        let calls: Vec<_> = records
            .iter()
            .filter(|r| {
                r.usage.lines.iter().any(|l| {
                    l.class.as_str() == super::tool_door::surface("class_tool_calls")
                        && l.quantity > 0
                })
            })
            .collect();
        assert_eq!(
            calls.len(),
            1,
            "the tool call is reported once: {records:?}"
        );
        assert_eq!(
            calls[0].subject,
            busbar_kernel_audit::Subject::PrincipalId(rig.key.id.clone()),
            "on the caller's key"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_cancelled_task_stays_cancelled_and_carries_no_result() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-cancel";
        let (release, gate) = tokio::sync::watch::channel(false);
        let mut server = gated_server(gate).await;
        let rig = server
            .rig(instance, tools(&server, "optional"), &|app| app)
            .await;
        let (_, task_id) = create(&rig).await;
        let _call = next_call(&mut server.heard).await;
        let (status, ack) = ask(&rig, &rig.bound_token(), "tasks/cancel", &task_id).await;
        assert_eq!(status, 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "an empty ack: {ack}"
        );
        let (_, got) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");

        release.send_replace(true);
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("the continuation ended");
        let (_, got) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(got["result"]["status"], "cancelled", "{got}");
        assert!(got["result"].get("result").is_none(), "{got}");

        let (status, again) = ask(&rig, &rig.bound_token(), "tasks/cancel", &task_id).await;
        assert_eq!(
            (status, again["result"].clone()),
            (200, ack["result"].clone())
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_required_task_tool_refuses_a_caller_that_declared_no_tasks() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-required";
        let (_release, gate) = tokio::sync::watch::channel(false);
        let server = gated_server(gate).await;
        let rig = server
            .rig(instance, tools(&server, "required"), &|app| app)
            .await;
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            CALL,
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        assert_eq!(
            body["error"]["data"]["requiredCapabilities"],
            declared(),
            "{body}"
        );

        let mut undeclared: serde_json::Value =
            serde_json::from_str(&verb("tasks/get", "x")).expect("a verb");
        undeclared["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &undeclared.to_string(),
            "tasks/get",
            Some("x"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 400, "{body}");
        assert_eq!(body["error"]["code"], -32021, "{body}");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn another_callers_task_answers_exactly_as_an_unknown_one() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-foreign";
        let (release, gate) = tokio::sync::watch::channel(true);
        let server = gated_server(gate).await;
        let rig = server
            .rig(instance, tools(&server, "optional"), &|app| app)
            .await;
        let (_, task_id) = create(&rig).await;
        until(&rig, &task_id, "completed").await;
        drop(release);
        let (_, other) = rig
            .gov
            .mint_signed_async(
                NewKeySpec {
                    name: "another".to_string(),
                    ..Default::default()
                },
                4_000_000_000,
                1_700_000_000,
            )
            .await
            .expect("mint");
        let other = other.expose(&busbar_kernel::seal::lend()).to_string();
        let other = rig.bound_token_for(&other);
        let foreign = ask(&rig, &other, "tasks/get", &task_id).await;
        let unknown = ask(
            &rig,
            &other,
            "tasks/get",
            "00000000000000000000000000000000",
        )
        .await;
        assert_eq!(foreign.0, 400, "{:?}", foreign.1);
        assert_eq!(foreign.1["error"]["code"], -32602, "{:?}", foreign.1);
        assert_eq!(
            foreign.1["error"]["message"],
            "No task with that `taskId` exists for this caller."
        );
        assert_eq!(
            foreign, unknown,
            "a foreign task is indistinguishable from an unknown one"
        );
        let cancel = ask(&rig, &other, "tasks/cancel", &task_id).await;
        assert_eq!(cancel.1["error"], unknown.1["error"]);

        let (_, mine) = ask(&rig, &rig.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(mine["result"]["status"], "completed", "{mine}");
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_task_parks_on_its_own_ask_until_tasks_update_delivers_the_answer() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-ask";
        let (_release, gate) = tokio::sync::watch::channel(true);
        let mut server = gated_server(gate).await;
        let port = server.port;
        let pin = &server.pin;
        let section: serde_yaml::Value = serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             tools_allow:\n    read_file:\n      schema_hash: \"{}\"\n      task_support: optional\n      \
             task_ask_caller:\n        - confirm: {{ method: elicitation/create, params: {{ message: \"Go?\" }} }}\n",
            tool_digest()
        ))
        .expect("a section");
        let rig = server.rig(instance, section, &|app| app).await;
        let mut call: serde_json::Value = serde_json::from_str(&task_call()).expect("the call");
        call["params"]["_meta"]["io.modelcontextprotocol/clientCapabilities"]["elicitation"] =
            serde_json::json!({});
        let (status, body) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call.to_string(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        let body: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{body}");
        let task_id = body["result"]["taskId"]
            .as_str()
            .expect("a task")
            .to_string();
        let parked = until(&rig, &task_id, "input_required").await;
        assert_eq!(
            parked["result"]["inputRequests"]["confirm"]["method"], "elicitation/create",
            "{parked}"
        );

        while let Ok(request) = server.heard.try_recv() {
            assert!(!request.contains("\"tools/call\""), "{request}");
        }
        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "confirm": { "action": "accept" } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        let ack: serde_json::Value = serde_json::from_slice(&ack).expect("JSON-RPC");
        assert_eq!(status.as_u16(), 200, "{ack}");
        assert_eq!(
            ack["result"],
            serde_json::json!({ "resultType": "complete" }),
            "{ack}"
        );

        let call = next_call(&mut server.heard).await;
        assert!(call.contains("\"confirm\""), "{call}");
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "from the server",
            "{done}"
        );
        server.close().await;
    }

    const UPSTREAM_ASK: &str = r#"{"jsonrpc":"2.0","id":0,"result":{"resultType":"input_required","inputRequests":{"ok":{"method":"elicitation/create","params":{"message":"Publish it?","requestedSchema":{"type":"object","properties":{}}}}},"requestState":"theirs"}}"#;

    async fn asking_member() -> TlsToolServer {
        TlsToolServer::answering(std::sync::Arc::new(|request: &str| {
            if request.contains("\"tools/list\"") {
                serde_json::json!({"jsonrpc": "2.0", "id": 1, "result": {"tools": tool_listing()}})
                    .to_string()
            } else if request.contains("\"inputResponses\"") {
                r#"{"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"answered by the caller"}]}}"#
                    .to_string()
            } else {
                UPSTREAM_ASK.to_string()
            }
        }))
        .await
    }

    fn asking_tools(server: &TlsToolServer, granted: bool) -> serde_yaml::Value {
        let port = server.port;
        let pin = &server.pin;
        serde_yaml::from_str(&format!(
            "fs:\n  url: \"https://127.0.0.1:{port}/rpc\"\n  pin: {{ mechanism: cert_spki, key: \"{pin}\" }}\n  \
             grants: {{ elicitation: {granted} }}\n  \
             tools_allow:\n    read_file: {{ schema_hash: \"{}\", task_support: optional }}\n",
            tool_digest()
        ))
        .expect("a section")
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_members_ask_inside_a_task_reaches_the_caller_and_its_answer_reaches_the_member() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay";
        let mut server = asking_member().await;
        let rig = server
            .rig(instance, asking_tools(&server, true), &|app| app)
            .await;
        let (_, task_id) = create(&rig).await;
        let parked = until(&rig, &task_id, "input_required").await;
        let sent: serde_json::Value = serde_json::from_str(UPSTREAM_ASK).expect("the ask");
        assert_eq!(
            parked["result"]["inputRequests"], sent["result"]["inputRequests"],
            "the member's requests reach the caller verbatim: {parked}"
        );
        assert!(parked["result"].get("requestState").is_none(), "{parked}");
        let first = next_call(&mut server.heard).await;
        assert!(!first.contains("inputResponses"), "{first}");

        let mut update: serde_json::Value =
            serde_json::from_str(&verb("tasks/update", &task_id)).expect("a verb");
        update["params"]["inputResponses"] =
            serde_json::json!({ "ok": { "action": "accept", "content": {} } });
        let (status, ack) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &update.to_string(),
            "tasks/update",
            Some(&task_id),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&ack));

        let retry = next_call(&mut server.heard).await;
        let body = retry
            .split_once("\r\n\r\n")
            .map_or(retry.as_str(), |(_, b)| b);
        let retry: serde_json::Value = serde_json::from_str(body).expect("JSON");
        assert_eq!(retry["params"]["requestState"], "theirs", "{retry}");
        assert_eq!(
            retry["params"]["inputResponses"]["ok"]["action"], "accept",
            "{retry}"
        );
        assert!(
            retry["params"]["arguments"].get("ok").is_none(),
            "the member's answers never become arguments: {retry}"
        );
        let done = until(&rig, &task_id, "completed").await;
        assert_eq!(
            done["result"]["result"]["content"][0]["text"], "answered by the caller",
            "{done}"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_ask_inside_a_task_is_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-relay-ungranted";
        let server = asking_member().await;
        let rig = server
            .rig(instance, asking_tools(&server, false), &|app| app)
            .await;
        let (_, task_id) = create(&rig).await;
        let failed = until(&rig, &task_id, "failed").await;
        assert!(
            failed["result"]["error"]["message"]
                .as_str()
                .is_some_and(|m| m.contains("grants.elicitation")),
            "{failed}"
        );
        assert!(failed["result"].get("inputRequests").is_none(), "{failed}");
        server.close().await;
    }

    async fn node(
        instance: &'static str,
        server: &TlsToolServer,
        rows: &std::sync::Arc<Rows>,
        max_live: usize,
        book: Option<&Rig>,
    ) -> Rig {
        server
            .rig_with_footing(
                instance,
                tools(server, "optional"),
                Footing {
                    ledger: Ledger::Rows(std::sync::Arc::clone(rows), max_live),
                    book,
                    ..Footing::own()
                },
                &|app| app,
            )
            .await
    }

    async fn ended(rig: &Rig) {
        let ended = async {
            while !rig.all_ended() {
                tokio::time::sleep(std::time::Duration::from_millis(20)).await;
            }
        };
        tokio::time::timeout(std::time::Duration::from_secs(10), ended)
            .await
            .expect("every unit ended");
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_live_task_created_on_one_node_is_answered_by_another() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-fleet";
        let (_release, gate) = tokio::sync::watch::channel(false);
        let mut server = gated_server(gate).await;
        let rows = Rows::open().await;
        let a = node(instance, &server, &rows, 4096, None).await;
        let b = node(instance, &server, &rows, 4096, Some(&a)).await;
        let (_, task_id) = create(&a).await;
        let _call = next_call(&mut server.heard).await;
        let observed_here = observed_count(&a);
        let (status, here) = ask(&a, &a.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{here}");
        assert_eq!(here["result"]["status"], "working", "{here}");
        let here_observation = assert_task_ttl(&a, &here, &task_id, observed_here);
        let observed_there = observed_count(&b);
        let (status, there) = ask(&b, &b.bound_token(), "tasks/get", &task_id).await;
        assert_eq!(status, 200, "{there}");
        let there_observation = assert_task_ttl(&b, &there, &task_id, observed_there);
        assert!(here_observation.settled_ms.is_none() && there_observation.settled_ms.is_none());
        assert_eq!(
            there["result"]["ttlMs"]
                .as_u64()
                .unwrap()
                .checked_sub(here["result"]["ttlMs"].as_u64().unwrap()),
            there_observation
                .observed_ms
                .checked_sub(here_observation.observed_ms),
            "live TTL grows by exactly the host-observed age between nodes"
        );
        let (mut here_fields, mut there_fields) = (here.clone(), there.clone());
        here_fields["result"]
            .as_object_mut()
            .unwrap()
            .remove("ttlMs");
        there_fields["result"]
            .as_object_mut()
            .unwrap()
            .remove("ttlMs");
        assert_eq!(
            there_fields, here_fields,
            "every other field comes from the same host task rows"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_live_handles_a_gone_process_left_are_settled_and_a_new_task_is_admitted() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-restart";
        let (_release, gate) = tokio::sync::watch::channel(false);
        let server = gated_server(gate).await;
        let rows = Rows::open().await;
        let gone = node(instance, &server, &rows, 2, None).await;
        let (_, first) = create(&gone).await;
        let (_, second) = create(&gone).await;
        let (status, refused) = send_as(
            &gone.router,
            Some(&gone.bound_token()),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            503,
            "at the bound of live work: {}",
            String::from_utf8_lossy(&refused)
        );

        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        let next = node(instance, &server, &rows, 2, Some(&gone)).await;
        drop(gone);
        next.wall
            .fetch_add(3_600_000, std::sync::atomic::Ordering::SeqCst);
        let (status, body) = send_as(
            &next.router,
            Some(&next.bound_token()),
            &task_call(),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            200,
            "admitted: {}",
            String::from_utf8_lossy(&body)
        );
        for id in [&first, &second] {
            let (_, got) = ask(&next, &next.bound_token(), "tasks/get", id).await;
            assert_eq!(got["result"]["status"], "cancelled", "{got}");
        }
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_settle_the_store_refuses_is_made_again_until_it_lands() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-task-settle-retry";
        let (_release, gate) = tokio::sync::watch::channel(true);
        let server = gated_server(gate).await;
        let rows = Rows::open().await;
        rows.1.store(2, std::sync::atomic::Ordering::SeqCst);
        let rig = node(instance, &server, &rows, 4096, None).await;
        let (_, task_id) = create(&rig).await;
        ended(&rig).await;
        let reference =
            busbar_kernel::host_work::parse_reference(task_id.as_bytes()).expect("a reference");
        let rows = busbar_kernel::persistence::scoped::ScopedStore::host_private(
            rig.store.clone(),
            instance,
            [busbar_kernel::host_work::WORK_SCHEMA.as_str().to_string()],
        )
        .unwrap();
        let state = || async {
            rows.get(busbar_kernel::host_work::WORK_SCHEMA.as_str(), &reference)
                .await
                .expect("the actual native Store reads the task")
                .and_then(|row| row.expose(&busbar_kernel::seal::lend()).get(1).copied())
        };
        assert_eq!(
            state().await,
            Some(busbar_contract::abi::host::service::WORK_LIVE),
            "the store refused the continuation's settle"
        );
        for _ in 0..2 {
            create(&rig).await;
            ended(&rig).await;
        }
        let mut settled = false;
        for _ in 0..250 {
            if state().await == Some(busbar_contract::abi::host::service::WORK_SETTLED) {
                settled = true;
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        }
        assert!(settled, "the owed settle landed");
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod hook_parity {
    use super::tool_door::{send_as, surface, Rig, TlsToolServer};
    use crate::root::serve::planes_tests::PUBLISHING;

    pub(crate) fn gate(
        prompt: &str,
        settings: serde_json::Value,
    ) -> busbar_kernel::config::HookCfg {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")
            .expect("the hook sidecar binds a real listener");
        listener.set_nonblocking(true).unwrap();
        let endpoint = format!("http://{}/hook", listener.local_addr().unwrap());
        let listener = tokio::net::TcpListener::from_std(listener).unwrap();
        let router = axum::Router::new().route(
            "/hook",
            axum::routing::post(move |axum::Json(body): axum::Json<serde_json::Value>| {
                let settings = settings.clone();
                async move {
                    let rejected = settings
                        .get("reject_if_contains")
                        .and_then(serde_json::Value::as_str)
                        .is_some_and(|needle| {
                            body["request"]["messages"].to_string().contains(needle)
                        });
                    let reply = if rejected {
                        serde_json::json!({"reject":{
                            "status":settings.get("reject_status")
                                .and_then(serde_json::Value::as_u64).unwrap_or(403),
                            "message":"blocked by test gate"
                        }})
                    } else if body["op"] == "transform" {
                        settings
                            .get("raw_transform_reply")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({}))
                    } else {
                        settings
                            .get("raw_decide_reply")
                            .cloned()
                            .unwrap_or_else(|| serde_json::json!({}))
                    };
                    let status = settings
                        .get("http_status")
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|status| u16::try_from(status).ok())
                        .and_then(|status| axum::http::StatusCode::from_u16(status).ok())
                        .unwrap_or(axum::http::StatusCode::OK);
                    (status, axum::Json(reply))
                }
            }),
        );
        tokio::spawn(async move {
            axum::serve(listener, router)
                .await
                .expect("the actual hook sidecar serves");
        });
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_WEBREQUEST_CDYLIB")
                .expect("BUSBAR_TEST_WEBREQUEST_CDYLIB names the actual built webrequest product"),
        );
        let statement = crate::root::loader::dispatch::rendering_of_library(&path)
            .expect("the actual hook statement reads")
            .expect("the actual hook states itself");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual hook statement is valid")
            .name;
        serde_json::from_value(serde_json::json!({
            "kind": "gate",
            "module": module,
            "timeout_ms": 10_000,
            "on_error": "weighted",
            "prompt": prompt,
            "user": "ro",
            "priority": 0,
            "settings": {"url":endpoint},
            "global": false,
            "default": false,
            "signals": [],
            "groups": [],
            "phase": [],
        }))
        .expect("a hook document")
    }

    pub(crate) fn hook_env() -> busbar_kernel::hooks::HookEnv {
        let _ = super::tool_door::line_door();
        let path = std::path::PathBuf::from(
            std::env::var_os("BUSBAR_TEST_WEBREQUEST_CDYLIB")
                .expect("BUSBAR_TEST_WEBREQUEST_CDYLIB names the actual built webrequest product"),
        );
        let statement = crate::root::loader::dispatch::rendering_of_library(&path)
            .expect("the actual hook statement reads")
            .expect("the actual hook states itself");
        let module = busbar_contract::abi::mechanism::rendering::read(&statement)
            .expect("the actual hook statement is valid")
            .name;
        let mut manifest = crate::root::test_plugins::manifest(
            "hook",
            &module,
            crate::root::loader::sign::FIRST_PARTY_PUBLISHER,
        );
        manifest.statement = Some(hex::encode(statement));
        manifest.needs.prompt = busbar_contract::plugin_rows::NeedLevel::Rw;
        manifest.needs.user = busbar_contract::plugin_rows::NeedLevel::Ro;
        let release = crate::root::test_plugins::key(0x5a);
        let directory = crate::root::test_plugins::scratch(&format!(
            "door-hooks-{}",
            busbar_kernel::door::op_id().counter(),
        ));
        let library = std::fs::read(path).expect("the actual hook library reads");
        let archive = crate::root::test_plugins::signed(&release, manifest, &library);
        std::fs::write(directory.join("hook.tar.gz"), archive)
            .expect("stage the actual hook archive");
        let registry = crate::root::loader::scan_and_validate(
            &directory,
            &crate::root::test_plugins::release_policy(&release),
        )
        .expect("the actual root loader admits the signed hook");
        crate::root::linked::register_stores(&crate::LINKED);
        busbar_kernel::hooks::HookEnv::new(
            std::sync::Arc::new(registry),
            std::sync::Arc::new(busbar_kernel::config::secret::SecretResolver::builtins_only()),
        )
        .expect("the actual root constructs the hook environment")
    }

    pub(crate) async fn rig(
        instance: &'static str,
        server: &TlsToolServer,
        hooks: Vec<(&'static str, busbar_kernel::config::HookCfg)>,
    ) -> Rig {
        let env = hook_env();
        server
            .rig(instance, server.section(), &move |mut app| {
                if hooks.is_empty() {
                    return app;
                }
                app.hook_env = env.clone();
                for (name, cfg) in &hooks {
                    app.hook_registry.insert((*name).to_string(), cfg.clone());
                }
                app.requested_signals = busbar_kernel::hooks::requested_signals(&app.hook_registry);
                app.any_content_hook = busbar_kernel::hooks::any_content_hook(&app.hook_registry);
                let attached = hooks
                    .iter()
                    .map(|(name, _)| (*name).to_string())
                    .collect::<Vec<_>>();
                app.plane_gates.insert(
                    surface("plane_key"),
                    app.resolve_container_gates(std::iter::once(("fs", &[][..])), &attached),
                );
                app.plane_rewrites.insert(
                    surface("plane_key"),
                    app.resolve_container_rewrites(std::iter::once(("fs", &[][..])), &attached),
                );
                app
            })
            .await
    }

    pub(crate) fn call(arguments: serde_json::Value) -> String {
        serde_json::json!({
            "jsonrpc": "2.0", "id": 30, "method": "tools/call",
            "params": {
                "name": "fs_read_file", "arguments": arguments,
                "_meta": {
                    "io.modelcontextprotocol/protocolVersion": surface("protocol_version"),
                    "io.modelcontextprotocol/clientCapabilities": {},
                },
            },
        })
        .to_string()
    }

    pub(crate) fn calls_heard(
        heard: &mut tokio::sync::mpsc::UnboundedReceiver<String>,
    ) -> Vec<String> {
        std::iter::from_fn(|| heard.try_recv().ok())
            .filter(|r| r.contains("\"tools/call\""))
            .collect()
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn tools_hooks_reject_all_rejects_a_tools_call() {
        const EXACT: &str = concat!(
            module_path!(),
            "::tools_hooks_reject_all_rejects_a_tools_call"
        );
        let Some(case) =
            crate::root::door_steps::tests::isolated_fixture_cases(EXACT, &["control", "gated"])
        else {
            return;
        };
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-reject-all";
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));

        let mut server = TlsToolServer::new().await;
        if case == "control" {
            let control = rig(instance, &server, Vec::new()).await;
            let (status, answer) = send_as(
                &control.router,
                Some(&control.bound_token()),
                &body,
                "tools/call",
                Some("fs_read_file"),
            )
            .await;
            assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
            assert_eq!(
                calls_heard(&mut server.heard).len(),
                1,
                "the control reached the server"
            );
            drop(control);
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }

        if case == "gated" {
            let gated = rig(
            instance,
            &server,
            vec![(
                "reject-all",
                gate(
                    "ro",
                    serde_json::json!({
                        "raw_decide_reply": {"reject": {"status": 403, "message": "no tool calls today"}}
                    }),
                ),
            )],
        ).await;
            let (status, answer) = send_as(
                &gated.router,
                Some(&gated.bound_token()),
                &body,
                "tools/call",
                Some("fs_read_file"),
            )
            .await;
            assert_eq!(status.as_u16(), 403, "{}", String::from_utf8_lossy(&answer));
            let answer: serde_json::Value = serde_json::from_slice(&answer).expect("JSON-RPC");
            assert_eq!(
                answer["error"]["message"], "no tool calls today",
                "{answer}"
            );
            assert!(
                calls_heard(&mut server.heard).is_empty(),
                "a gate that rejects after the call went out stopped nothing"
            );
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn the_calls_content_reaches_the_gate() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-content";
        let mut server = TlsToolServer::new().await;
        let rig = rig(
            instance,
            &server,
            vec![(
                "screen",
                gate(
                    "ro",
                    serde_json::json!({ "reject_if_contains": "/etc/shadow" }),
                ),
            )],
        )
        .await;
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(
            status.as_u16(),
            403,
            "the gate's verdict was driven by the arguments: {}",
            String::from_utf8_lossy(&answer)
        );
        assert_eq!(
            calls_heard(&mut server.heard).len(),
            1,
            "only the clean call went out"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_hook_edits_the_tool_call_arguments_before_they_go_upstream() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rewrite";
        let mut server = TlsToolServer::new().await;
        let rig = rig(
            instance,
            &server,
            vec![(
                "rewrite",
                gate(
                    "rw",
                    serde_json::json!({ "raw_transform_reply": {
                        "rewrite": { "messages": [
                            { "role": "user", "content": { "path": "/srv/rewritten-by-hook" } }
                        ] }
                    } }),
                ),
            )],
        )
        .await;
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
        let wire = calls_heard(&mut server.heard);
        assert_eq!(wire.len(), 1, "one call went out");
        assert!(
            wire[0].contains("/srv/rewritten-by-hook") && !wire[0].contains("/etc/hosts"),
            "the server received the arguments the hook rewrote them to: {}",
            wire[0]
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_rewrite_gate_can_reject_on_the_arguments_it_screens() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-rw-screen";
        let mut server = TlsToolServer::new().await;
        let rig = rig(
            instance,
            &server,
            vec![(
                "screen",
                // Screens only: clean arguments are let through untouched (the double's default
                // answer is a chat rewrite a tool call cannot take, which is refused, never
                // relayed un-rewritten).
                gate(
                    "rw",
                    serde_json::json!({
                        "reject_if_contains": "/etc/shadow",
                        "reject_status": 451,
                        "raw_transform_reply": {},
                    }),
                ),
            )],
        )
        .await;
        let (status, _) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/hosts" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 200, "clean arguments are served");
        let (status, answer) = send_as(
            &rig.router,
            Some(&rig.bound_token()),
            &call(serde_json::json!({ "path": "/etc/shadow" })),
            "tools/call",
            Some("fs_read_file"),
        )
        .await;
        assert_eq!(status.as_u16(), 451, "{}", String::from_utf8_lossy(&answer));
        assert_eq!(
            calls_heard(&mut server.heard).len(),
            1,
            "the rejected call never went out"
        );
        server.close().await;
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn rewrite_failure_outcomes_preserve_the_body_or_refuse_before_the_tool_hop() {
        const EXACT: &str = concat!(
            module_path!(),
            "::rewrite_failure_outcomes_preserve_the_body_or_refuse_before_the_tool_hop"
        );
        let Some(case) = crate::root::door_steps::tests::isolated_fixture_cases(
            EXACT,
            &["optional", "required"],
        ) else {
            return;
        };
        let _one = PUBLISHING.lock().await;
        let instance = "door-hook-failure-dispositions";
        let body = call(serde_json::json!({ "path": "/etc/hosts" }));
        let mut server = TlsToolServer::new().await;
        if case == "optional" {
            let weighted = rig(
                instance,
                &server,
                vec![(
                    "optional-outcome",
                    // A real target error makes the actual webrequest operation fail;
                    // its optional disposition must preserve the original request.
                    gate("rw", serde_json::json!({ "http_status": 503 })),
                )],
            )
            .await;
            let (status, answer) = send_as(
                &weighted.router,
                Some(&weighted.bound_token()),
                &body,
                "tools/call",
                Some("fs_read_file"),
            )
            .await;
            assert_eq!(status.as_u16(), 200, "{}", String::from_utf8_lossy(&answer));
            let wire = calls_heard(&mut server.heard);
            assert!(
                wire.len() == 1 && wire[0].contains("/etc/hosts"),
                "served with the caller's original arguments: {wire:?}"
            );
            drop(weighted);
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }

        if case == "required" {
            let mut required = gate("rw", serde_json::json!({ "http_status": 503 }));
            required.on_error = serde_json::from_value(serde_json::json!("reject"))
                .expect("an on_error disposition");
            let required = rig(instance, &server, vec![("required-outcome", required)]).await;
            let (status, body) = send_as(
                &required.router,
                Some(&required.bound_token()),
                &body,
                "tools/call",
                Some("fs_read_file"),
            )
            .await;
            assert_eq!(
                status.as_u16(),
                busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_STATUS,
                "the required-hook failure outcome refuses the call: {}",
                String::from_utf8_lossy(&body)
            );
            let answer: serde_json::Value = serde_json::from_slice(&body).expect("JSON-RPC");
            assert_eq!(
                answer["error"]["message"],
                busbar_kernel::hooks::REQUIRED_HOOK_UNAVAILABLE_MESSAGE,
                "the content-free refusal reaches the caller: {answer}",
            );
            assert!(
                calls_heard(&mut server.heard).is_empty(),
                "nothing was dispatched"
            );
            crate::root::door_steps::tests::isolated_fixture_done(EXACT, &case);
        }
        server.close().await;
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
pub(crate) mod program_member {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    pub(crate) fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        format!(
            "inits=0; lists=0; calls=0; pongs=0\n\
             L='{listing}'\n\
             while IFS= read -r l; do\n\
               id=$(printf '%s' \"$l\" | sed -n 's/.*\"id\":\\([0-9]\\{{10,\\}}\\).*/\\1/p')\n\
               case \"$l\" in\n\
                 *'\"method\":\"initialize\"'*) inits=$((inits+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"protocolVersion\":\"2025-06-18\",\"capabilities\":{{\"tools\":{{}}}},\"serverInfo\":{{\"name\":\"s\",\"version\":\"1\"}}}}}}\\n' \"$id\" ;;\n\
                 *'\"method\":\"tools/list\"'*) lists=$((lists+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"method\":\"notifications/message\",\"params\":{{\"level\":\"info\",\"data\":\"listing\"}}}}\\n'; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"tools\":%s}}}}\\n' \"$id\" \"$L\" ;;\n\
                 *'\"method\":\"tools/call\"'*) calls=$((calls+1)); \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":\"srv-%s\",\"method\":\"ping\"}}\\n' \"$calls\"; \
                   printf '{{\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{{\"content\":[{{\"type\":\"text\",\"text\":\"from the server pid=%s inits=%s lists=%s calls=%s pongs=%s\"}}]}}}}\\n' \"$id\" \"$$\" \"$inits\" \"$lists\" \"$calls\" \"$pongs\" ;;\n\
                 *'\"result\":{{}}'*) pongs=$((pongs+1)) ;;\n\
               esac\n\
             done\n"
        )
    }

    fn section() -> serde_yaml::Value {
        section_running(script())
    }

    pub(crate) fn section_running(script: String) -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "cwd".into(),
            std::env::current_dir()
                .expect("an absolute fixture cwd")
                .to_str()
                .expect("a UTF-8 fixture cwd")
                .into(),
        );
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script.into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: local_program, key: \"/bin/sh\" }").unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    fn text(body: &[u8]) -> String {
        let body: serde_json::Value = serde_json::from_slice(body).expect("a JSON-RPC answer");
        assert_eq!(body["id"], 30, "answered under the caller's own id: {body}");
        body["result"]["content"][0]["text"]
            .as_str()
            .unwrap_or_else(|| panic!("a tool result: {body}"))
            .to_string()
    }

    fn fact<'t>(text: &'t str, key: &str) -> &'t str {
        text.split(' ')
            .find_map(|w| w.strip_prefix(key)?.strip_prefix('='))
            .unwrap_or_else(|| panic!("{key} in {text:?}"))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_registration_serves_the_call_and_a_second_call_reuses_its_child() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-member";
        let rig = rig_tools(instance, 0, section(), &|app| app).await;

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let first = text(&body);
        assert!(first.starts_with("from the server "), "{first}");
        assert_eq!(
            fact(&first, "inits"),
            "1",
            "greeted before the call: {first}"
        );
        assert_eq!(
            fact(&first, "lists"),
            "1",
            "verify-on-call on the child: {first}"
        );
        assert_eq!(fact(&first, "calls"), "1");

        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let second = text(&body);
        assert_eq!(
            fact(&second, "pid"),
            fact(&first, "pid"),
            "the second call reached the same child"
        );
        assert_eq!(fact(&second, "inits"), "1", "greeted once: {second}");
        assert_eq!(fact(&second, "calls"), "2");
        assert_eq!(
            fact(&second, "pongs"),
            "1",
            "the child's own request was answered once: {second}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_registration_is_served_on_its_own_rig_whatever_the_process_opened_first() {
        let _one = PUBLISHING.lock().await;
        let _first = crate::root::doors::dispatcher();
        let rig = rig_tools("door-program-member-own", 0, section(), &|app| app).await;
        let (status, body) = send(&rig.router, Some(&rig.bound_token()), CALL).await;
        assert_eq!(status, StatusCode::OK, "{}", String::from_utf8_lossy(&body));
        let text = text(&body);
        assert!(text.starts_with("from the server "), "{text}");
        assert_eq!(fact(&text, "calls"), "1", "{text}");
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod program_member_supervised {
    use super::program_member::section_running;
    use super::tool_door::{rig_tools, send, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    fn section(spawns: &std::path::Path) -> serde_yaml::Value {
        section_running(format!("echo spawned >> '{}'; exit 1", spawns.display()))
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_program_that_keeps_ending_is_spawned_five_times_then_refused() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-supervised";
        let spawns =
            std::env::temp_dir().join(format!("busbar-{instance}-{}-spawns", std::process::id()));
        let _ = std::fs::remove_file(&spawns);
        let rig = rig_tools(instance, 0, section(&spawns), &|app| app).await;

        for _ in 0..24 {
            let _ = send(&rig.router, Some(&rig.bound_token()), CALL).await;
            tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        }
        let spawned = std::fs::read_to_string(&spawns)
            .unwrap_or_default()
            .lines()
            .count();
        let _ = std::fs::remove_file(&spawns);
        assert_eq!(
            spawned, 5,
            "five ends inside a minute stop the restarts: spawned {spawned} times"
        );
    }
}

#[cfg(all(linked_axis_plane_door, linked_section_pools))]
mod program_member_ask {
    use axum::http::StatusCode;

    use super::tool_door::{rig_tools, send, tool_digest, tool_listing, CALL};
    use crate::root::serve::planes_tests::PUBLISHING;

    fn script() -> String {
        let listing = tool_listing().to_string().replace('\'', "'\\''");
        r#"calls=0; pending=""
L='__LISTING__'
while IFS= read -r l; do
  id=$(printf '%s' "$l" | sed -n 's/.*"id":\([0-9]\{10,\}\).*/\1/p')
  case "$l" in
    *'"method":"initialize"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"protocolVersion":"2025-06-18","capabilities":{"tools":{}},"serverInfo":{"name":"s","version":"1"}}}\n' "$id" ;;
    *'"method":"tools/list"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"tools":%s}}\n' "$id" "$L" ;;
    *'"method":"tools/call"'*) calls=$((calls+1)); pending=$id; printf '{"jsonrpc":"2.0","id":"srv-ask-%s","method":"sampling/createMessage","params":{"messages":[{"role":"user","content":{"type":"text","text":"Draft it."}}],"maxTokens":64}}\n' "$calls" ;;
    *'"srv-ask-'*) got=$(printf '%s' "$l" | sed -n 's/.*"text":"\([^"]*\)".*/\1/p'); [ -n "$got" ] || got=$(printf '%s' "$l" | sed -n 's/.*"reason":"\([^"]*\)".*/\1/p'); printf '{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"answered with %s"}]}}\n' "$pending" "$got" ;;
  esac
done
"#
        .replace("__LISTING__", &listing)
    }

    fn section(granted: bool) -> serde_yaml::Value {
        let mut fs = serde_yaml::Mapping::new();
        fs.insert("transport".into(), "stdio".into());
        fs.insert("command".into(), "/bin/sh".into());
        fs.insert(
            "cwd".into(),
            std::env::current_dir()
                .expect("an absolute fixture cwd")
                .to_str()
                .expect("a UTF-8 fixture cwd")
                .into(),
        );
        fs.insert(
            "args".into(),
            serde_yaml::Value::Sequence(vec!["-c".into(), script().into()]),
        );
        fs.insert(
            "pin".into(),
            serde_yaml::from_str("{ mechanism: local_program, key: \"/bin/sh\" }").unwrap(),
        );
        fs.insert(
            "grants".into(),
            serde_yaml::from_str(&format!("{{ sampling: {granted} }}")).unwrap(),
        );
        fs.insert(
            "tools_allow".into(),
            serde_yaml::from_str(&format!(
                "{{ read_file: {{ schema_hash: \"{}\" }} }}",
                tool_digest()
            ))
            .unwrap(),
        );
        let mut tools = serde_yaml::Mapping::new();
        tools.insert("fs".into(), serde_yaml::Value::Mapping(fs));
        serde_yaml::Value::Mapping(tools)
    }

    async fn call(
        router: &axum::Router,
        token: &str,
        body: &str,
    ) -> (StatusCode, serde_json::Value) {
        let (status, body) = send(router, Some(token), body).await;
        (
            status,
            serde_json::from_slice(&body).expect("a JSON-RPC answer"),
        )
    }

    fn retry(answers: serde_json::Value, state: &str) -> String {
        let mut body: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        body["params"]["inputResponses"] = answers;
        body["params"]["requestState"] = state.into();
        body.to_string()
    }

    fn draft() -> serde_json::Value {
        serde_json::json!({ "role": "assistant", "content": { "type": "text", "text": "the callers own draft" }, "model": "m" })
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_childs_ask_reaches_the_caller_verbatim_and_its_answer_reaches_the_child() {
        use base64::engine::general_purpose::URL_SAFE_NO_PAD;
        use base64::Engine as _;
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask";
        let rig = rig_tools(instance, 0, section(true), &|app| app).await;

        let (status, body) = call(&rig.router, &rig.bound_token(), CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(body["id"], 30, "{body}");
        assert_eq!(body["result"]["resultType"], "input_required", "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["srv-ask-1"],
            serde_json::json!({"method": "sampling/createMessage", "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "Draft it."}}], "maxTokens": 64}}),
            "the child's request, verbatim: {body}"
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();

        let answered = retry(serde_json::json!({ "srv-ask-1": draft() }), &state);
        let (status, body) = call(&rig.router, &rig.bound_token(), &answered).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );

        let (status, body) = call(&rig.router, &rig.bound_token(), &answered).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "a spent state: {body}");
        let (status, body) = call(
            &rig.router,
            &rig.bound_token(),
            &retry(serde_json::json!({ "srv-ask-1": draft() }), "forged"),
        )
        .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "malformed state: {body}");
        assert_eq!(body["error"]["code"], -32602, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "state_malformed", "{body}");

        // Keep the actual issued payload and canonical encoding; change only its seal.
        let (payload, signature) = state.split_once('.').expect("the issued payload and seal");
        let mut signature_bytes = URL_SAFE_NO_PAD
            .decode(signature)
            .expect("canonical issued seal");
        assert_eq!(signature_bytes.len(), 64, "the issued Ed25519 signature");
        assert_eq!(URL_SAFE_NO_PAD.encode(&signature_bytes), signature);
        signature_bytes[0] ^= 1;
        let tampered = format!("{payload}.{}", URL_SAFE_NO_PAD.encode(&signature_bytes));
        assert_ne!(tampered, state, "the issued seal was actually changed");
        let (status, body) = call(
            &rig.router,
            &rig.bound_token(),
            &retry(serde_json::json!({ "srv-ask-1": draft() }), &tampered),
        )
        .await;
        assert_eq!(
            status,
            StatusCode::BAD_REQUEST,
            "a tampered issued seal: {body}"
        );
        assert_eq!(body["error"]["code"], -32602, "{body}");
        assert_eq!(
            body["error"]["data"]["reason"], "state_bad_signature",
            "{body}"
        );

        let mut unsolicited: serde_json::Value = serde_json::from_str(CALL).expect("the call");
        unsolicited["params"]["inputResponses"] = serde_json::json!({ "srv-ask-1": draft() });
        assert!(unsolicited["params"].get("requestState").is_none());
        let (status, body) = call(&rig.router, &rig.bound_token(), &unsolicited.to_string()).await;
        // Initial inputResponses is ordinary upstream input when no local ask is
        // configured. It cannot resume the spent exchange or answer a new child
        // request: the child must issue its next ask and receive a sealed retry.
        assert_eq!(
            status,
            StatusCode::OK,
            "ordinary initial input starts a new exchange: {body}"
        );
        assert_eq!(body["result"]["resultType"], "input_required", "{body}");
        assert!(body["result"].get("content").is_none(), "{body}");
        assert_eq!(
            body["result"]["inputRequests"]["srv-ask-2"],
            serde_json::json!({"method": "sampling/createMessage", "params": {"messages": [{"role": "user", "content": {"type": "text", "text": "Draft it."}}], "maxTokens": 64}}),
            "the new child request is still required, verbatim: {body}"
        );
        assert_ne!(
            body["result"]["requestState"].as_str(),
            Some(state.as_str())
        );
        let state = body["result"]["requestState"]
            .as_str()
            .expect("busbar's sealed state")
            .to_string();
        assert!(
            body["result"]["inputRequests"].get("srv-ask-2").is_some(),
            "{body}"
        );
        let (status, body) = call(
            &rig.router,
            &rig.bound_token(),
            &retry(serde_json::json!({}), &state),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"]["data"]["reason"], "ask_unanswered", "{body}");
        let (status, body) = call(
            &rig.router,
            &rig.bound_token(),
            &retry(serde_json::json!({ "srv-ask-2": draft() }), &state),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with the callers own draft",
            "{body}"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_ungranted_childs_ask_is_refused_on_its_input_and_never_relayed() {
        let _one = PUBLISHING.lock().await;
        let instance = "door-program-ask-ungranted";
        let rig = rig_tools(instance, 0, section(false), &|app| app).await;
        let (status, body) = call(&rig.router, &rig.bound_token(), CALL).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        assert!(body["result"].get("inputRequests").is_none(), "{body}");
        assert_eq!(
            body["result"]["content"][0]["text"], "answered with ask_ungranted",
            "the child was refused on its input, by the operator's grant: {body}"
        );
    }
}
