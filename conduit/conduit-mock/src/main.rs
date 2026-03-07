/// High-performance mock upstream server for stress testing Conduit proxy.
/// Uses axum + tokio for async I/O — handles tens of thousands of concurrent connections.
use axum::{
    extract::Path,
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;
use rand::Rng;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Parser)]
#[command(name = "conduit-mock", about = "Mock upstream for stress testing")]
struct Args {
    /// HTTP listen port
    #[arg(long, default_value = "18080")]
    http_port: u16,

    /// HTTPS listen port
    #[arg(long, default_value = "18443")]
    https_port: u16,
}

// Pre-generated random bytes for /bytes/:n responses (avoids alloc per request)
struct ByteCache {
    data_1mb: Vec<u8>,
}

impl ByteCache {
    fn new() -> Self {
        let mut rng = rand::rng();
        let mut data = vec![0u8; 1024 * 1024];
        rng.fill(&mut data[..]);
        Self { data_1mb: data }
    }

    fn get(&self, n: usize) -> &[u8] {
        let n = n.min(self.data_1mb.len());
        &self.data_1mb[..n]
    }
}

async fn handle_get(headers: HeaderMap) -> impl IntoResponse {
    let body = serde_json::json!({
        "url": "/get",
        "headers": headers.iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect::<std::collections::HashMap<_, _>>(),
    });
    axum::Json(body)
}

async fn handle_headers(headers: HeaderMap) -> impl IntoResponse {
    let body = serde_json::json!({
        "headers": headers.iter()
            .map(|(k, v)| (k.as_str().to_string(), v.to_str().unwrap_or("").to_string()))
            .collect::<std::collections::HashMap<_, _>>(),
    });
    axum::Json(body)
}

async fn handle_uuid() -> impl IntoResponse {
    let id = uuid_v4();
    axum::Json(serde_json::json!({ "uuid": id }))
}

async fn handle_ip() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "origin": "127.0.0.1" }))
}

async fn handle_status(Path(code): Path<u16>) -> Response {
    let status = StatusCode::from_u16(code).unwrap_or(StatusCode::OK);
    (status, "").into_response()
}

async fn handle_bytes(
    Path(n): Path<usize>,
    axum::Extension(cache): axum::Extension<Arc<ByteCache>>,
) -> Response {
    let data = cache.get(n);
    (
        StatusCode::OK,
        [("content-type", "application/octet-stream")],
        data.to_vec(),
    )
        .into_response()
}

async fn handle_health() -> &'static str {
    "ok"
}

async fn handle_small() -> impl IntoResponse {
    axum::Json(serde_json::json!({ "status": "ok" }))
}

fn uuid_v4() -> String {
    let mut rng = rand::rng();
    let bytes: [u8; 16] = rng.random();
    format!(
        "{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]),
        u16::from_be_bytes([bytes[4], bytes[5]]),
        u16::from_be_bytes([bytes[6], bytes[7]]) & 0x0FFF,
        (u16::from_be_bytes([bytes[8], bytes[9]]) & 0x3FFF) | 0x8000,
        u64::from_be_bytes([0, 0, bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]])
    )
}

fn build_router(cache: Arc<ByteCache>) -> Router {
    Router::new()
        .route("/get", get(handle_get))
        .route("/headers", get(handle_headers))
        .route("/uuid", get(handle_uuid))
        .route("/ip", get(handle_ip))
        .route("/small", get(handle_small))
        .route("/health", get(handle_health))
        .route("/status/{code}", get(handle_status))
        .route("/bytes/{n}", get(handle_bytes))
        .route("/user-agent", get(handle_ip))
        .layer(axum::Extension(cache))
}

fn generate_self_signed_cert() -> (Vec<u8>, Vec<u8>) {
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    let key_pair = rcgen::KeyPair::generate().unwrap();
    let cert = params.self_signed(&key_pair).unwrap();
    (cert.pem().into_bytes(), key_pair.serialize_pem().into_bytes())
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let cache = Arc::new(ByteCache::new());

    let http_router = build_router(cache.clone());
    let https_router = build_router(cache);

    // Start HTTP server
    let http_listener = TcpListener::bind(format!("0.0.0.0:{}", args.http_port))
        .await
        .expect("Failed to bind HTTP port");
    println!("Mock HTTP upstream listening on :{}", args.http_port);

    let http_handle = tokio::spawn(async move {
        axum::serve(http_listener, http_router).await.unwrap();
    });

    // Start HTTPS server
    let (cert_pem, key_pem) = generate_self_signed_cert();
    let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
        .collect::<Result<Vec<_>, _>>()
        .expect("Failed to parse cert");
    let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
        .expect("Failed to parse key")
        .expect("No private key found");

    let tls_config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .expect("Failed to build TLS config");
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls_config));

    let https_listener = TcpListener::bind(format!("0.0.0.0:{}", args.https_port))
        .await
        .expect("Failed to bind HTTPS port");
    println!("Mock HTTPS upstream listening on :{}", args.https_port);

    let https_handle = tokio::spawn(async move {
        loop {
            let (stream, _addr) = match https_listener.accept().await {
                Ok(s) => s,
                Err(_) => continue,
            };
            let acceptor = tls_acceptor.clone();
            let router = https_router.clone();
            tokio::spawn(async move {
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let service = hyper_util::service::TowerToHyperService::new(router);
                if let Err(_e) = hyper_util::server::conn::auto::Builder::new(
                    hyper_util::rt::TokioExecutor::new(),
                )
                .serve_connection(io, service)
                .await
                {}
            });
        }
    });

    tokio::select! {
        _ = http_handle => {},
        _ = https_handle => {},
        _ = tokio::signal::ctrl_c() => {
            println!("\nShutting down mock server");
        },
    }
}
