use conduit_common::types::LogEntry;
use conduit_common::util::escape_sd_value;
use std::net::SocketAddr;
use tokio::net::UdpSocket;
use tokio::sync::Mutex;

/// RFC 5424 syslog sender (UDP or TCP).
pub struct SyslogSink {
    transport: Mutex<SyslogTransport>,
}

enum SyslogTransport {
    Udp {
        socket: UdpSocket,
        target: SocketAddr,
    },
    Tcp {
        stream: tokio::net::TcpStream,
    },
}

impl SyslogSink {
    /// Create a new syslog sink from a target URI like `udp://host:514` or `tcp://host:514`.
    pub async fn new(target: &str) -> anyhow::Result<Self> {
        if let Some(addr_str) = target.strip_prefix("udp://") {
            let target_addr: SocketAddr = addr_str.parse()?;
            let socket = UdpSocket::bind("0.0.0.0:0").await?;
            Ok(Self {
                transport: Mutex::new(SyslogTransport::Udp {
                    socket,
                    target: target_addr,
                }),
            })
        } else if let Some(addr_str) = target.strip_prefix("tcp://") {
            let stream = tokio::net::TcpStream::connect(addr_str).await?;
            Ok(Self {
                transport: Mutex::new(SyslogTransport::Tcp { stream }),
            })
        } else {
            anyhow::bail!("Invalid syslog target: {target}. Use udp://host:port or tcp://host:port")
        }
    }

    /// Send a log entry as an RFC 5424 syslog message.
    pub async fn send(&self, entry: &LogEntry) -> anyhow::Result<()> {
        let msg = format_rfc5424(entry);
        let mut transport = self.transport.lock().await;

        match &mut *transport {
            SyslogTransport::Udp { socket, target } => {
                socket.send_to(msg.as_bytes(), *target).await?;
            }
            SyslogTransport::Tcp { stream } => {
                use tokio::io::AsyncWriteExt;
                // TCP syslog uses newline-delimited messages
                let framed = format!("{}\n", msg);
                stream.write_all(framed.as_bytes()).await?;
            }
        }

        Ok(())
    }
}

/// Format a log entry as RFC 5424.
/// <priority>VERSION TIMESTAMP HOSTNAME APP-NAME PROCID MSGID STRUCTURED-DATA MSG
fn format_rfc5424(entry: &LogEntry) -> String {
    let priority = 14; // facility=user(1), severity=informational(6): 1*8+6=14
    let timestamp = entry.timestamp.format("%Y-%m-%dT%H:%M:%S%.3fZ");
    let username = entry.username.as_deref().unwrap_or("-");

    // Escape structured-data values per RFC 5424 Section 6.3.3
    let action = escape_sd_value(&format!("{:?}", entry.action).to_lowercase());
    let category = escape_sd_value(entry.category.as_deref().unwrap_or("-"));
    let user = escape_sd_value(username);
    let method = escape_sd_value(&entry.method);
    let url = escape_sd_value(&entry.full_url);

    let node_id = escape_sd_value(entry.node_id.as_deref().unwrap_or("-"));
    let node_name = escape_sd_value(entry.node_name.as_deref().unwrap_or("-"));
    let block_reason = escape_sd_value(
        &entry.block_reason.as_ref()
            .map(|r| r.to_string())
            .unwrap_or_else(|| "-".to_string()),
    );

    format!(
        "<{}>1 {} cleargate cleargate-proxy - - [meta action=\"{}\" category=\"{}\" user=\"{}\" node_id=\"{}\" node_name=\"{}\" block_reason=\"{}\"] {} {} {} {}",
        priority,
        timestamp,
        action,
        category,
        user,
        node_id,
        node_name,
        block_reason,
        method,
        url,
        entry.status_code,
        entry.duration_ms,
    )
}
