# Egress Lockdown & Port Filtering

This guide describes how to achieve a **fully locked egress environment** using Conduit in conjunction with host-level firewall rules.

---

## 1. Threat Model & Architecture

A forward proxy like Conduit listens on a local port (default `:8888`). By default:
* **Cooperative applications** (browsers, `curl`, Python `requests`, agent CLIs, package managers) respect environment variables like `http_proxy` / `https_proxy` or system proxy settings, sending their traffic through Conduit.
* **Malware or hostile binaries** can bypass the proxy entirely by creating raw TCP sockets directly to external IP addresses and arbitrary ports (e.g. `domain.com:1234`), completely evading proxy-based inspection.

To achieve total egress lockdown, a **two-tier defense** is required:

```
+-------------------------------------------------------------------------+
|                              Host / Machine                             |
|                                                                         |
|  +--------------------+    Direct socket (port 1234)                    |
|  | Untrusted / Malware| -------------------------------\                |
|  +--------------------+                                |                |
|           |                                            |                |
|           | http_proxy:8888                            |                |
|           v                                            v                |
|  +--------------------+                     +--------------------+      |
|  |   Conduit Proxy    |                     | Host Egress Fire-  |      |
|  | - Port Filtering   |                     | wall (nftables /   |      |
|  | - Threat Heuristics|                     | iptables)          |      |
|  | - YARA Package Scan|                     |                    |      |
|  | - SSRF Guardrails  |                     | DEFAULT DROP       |      |
|  +--------------------+                     +--------------------+      |
|           |                                            |                |
|           | Approved ports only                        X BLOCKED        |
|           v                                                             |
+-----------|-------------------------------------------------------------+
            v
         Internet
```

1. **Host-Level Egress Firewall (Layer 3/4)**: Drops all outbound traffic by default, permitting only approved direct services (DNS, NTP, WireGuard) and allowing outbound web traffic only from the user running Conduit.
2. **Conduit Egress Filtering (Layer 7)**: Inspects all proxied traffic, restricting `CONNECT` tunnels and plain HTTP to authorized destination ports, running real-time threat heuristics, package scanning, DLP, and SSRF loopback protections.

---

## 2. Common Egress Ports Inventory

Before locking down egress, understand the ports commonly required by developers and system services:

| Port | Protocol | Purpose / Common Services | Egress Handling |
| :--- | :--- | :--- | :--- |
| **`443`** | TCP | Secure Web (HTTPS), REST APIs, LLM endpoints (Anthropic, OpenAI, Gemini), GitHub, package registries (npm, PyPI, crates.io). | Routed through Conduit |
| **`80`** | TCP | Plain HTTP (package mirrors, initial redirects, ACME cert challenges). | Routed through Conduit |
| **`8443` / `8080`** | TCP | Alternative HTTPS / HTTP management APIs. | Routed through Conduit |
| **`6443`** | TCP | **Kubernetes API Server** (`kubectl` against self-hosted, k3s, kubeadm). Note: Managed cloud clusters like EKS/GKE typically use standard `443`. | Routed through Conduit or direct |
| **`22`** | TCP | SSH and Git-over-SSH. | Direct (or via `corkscrew`/`connect-proxy`) |
| **`53`** | UDP / TCP | System DNS resolution (`systemd-resolved`, `bind`). | Direct to upstream resolver |
| **`123`** | UDP | Network Time Protocol (`systemd-timesyncd`, `chrony`). | Direct to NTP pool |
| **`41641`** | UDP | Tailscale WireGuard peer-to-peer mesh. | Direct UDP |

---

## 3. Configuring Conduit Port Restrictions

Conduit includes native egress port enforcement in `conduit.toml`:

```toml
# --- Outbound Egress Port Restrictions ---
[egress]
# Allowed destination ports for CONNECT tunneling (HTTPS, WebSocket, Kubernetes API).
# Requests attempting to tunnel to unlisted ports (e.g. 1234) are immediately rejected with 403 Forbidden.
allowed_connect_ports = [443, 8443, 6443]

# Allowed destination ports for plain HTTP proxying.
allowed_http_ports = [80, 8080]
```

### Allowlist Interaction

If a destination is explicitly allowed in `[allowlist]`, it bypasses general egress port restrictions:
* **Ephemeral Agent Callbacks**: Ports `>= 1024` on `localhost` or `127.0.0.1` (e.g. OAuth redirect ports `45678` used by Claude Code or IDE tools) are permitted when `allow_loopback = true`.
* **Explicit Host:Port Overrides**: An entry like `"internal-tool.corp:9000"` in `allowlist.hosts` will permit port `9000` for that specific host without opening it globally.

---

## 4. Host-Level Egress Firewall (Default-Deny)

To prevent malware from bypassing Conduit via raw sockets, configure the host firewall to drop unauthorized outbound traffic.

### Option A: `nftables` Configuration (Recommended)

Save to `/etc/nftables.conf`:

```nft
#!/usr/sbin/nft -f

flush ruleset

table inet filter {
    chain input {
        type filter hook input priority filter; policy drop;

        # Allow loopback
        iif "lo" accept

        # Allow established and related connections
        ct state established,related accept

        # Drop invalid
        ct state invalid drop

        # Allow incoming SSH (adjust port as needed)
        tcp dport 22 accept

        # Allow local subnet to proxy port 8888 (if serving LAN)
        # ip saddr 192.168.1.0/24 tcp dport 8888 accept
    }

    chain output {
        type filter hook output priority filter; policy drop;

        # 1. Always allow loopback traffic
        oif "lo" accept

        # 2. Allow established and related traffic
        ct state established,related accept

        # 3. Allow system DNS (UDP/TCP 53)
        udp dport 53 accept
        tcp dport 53 accept

        # 4. Allow NTP time sync (UDP 123)
        udp dport 123 accept

        # 5. Allow Tailscale WireGuard (UDP 41641) if applicable
        udp dport 41641 accept

        # 6. Allow direct outbound SSH (TCP 22)
        tcp dport 22 accept

        # 7. Allow direct kubectl to API servers (TCP 6443)
        tcp dport 6443 accept

        # 8. Web traffic (ports 80 & 443):
        # ONLY permit the dedicated conduit user or service to make direct outbound HTTP/HTTPS connections.
        # All other processes must use 127.0.0.1:8888.
        skuid "conduit" tcp dport { 80, 443 } accept

        # If running as systemd user service, you can match systemd cgroup or UID:
        # meta cgroup "user.slice/.../conduit-proxy.service" tcp dport { 80, 443 } accept

        # 9. All other outbound attempts will be rejected and logged
        log prefix "[EGRESS BLOCKED]: " flags all counter reject
    }
}
```

Reload with:
```bash
sudo nft -f /etc/nftables.conf
```

---

### Option B: `iptables` Ruleset

If using traditional `iptables`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# 1. Flush existing output rules
iptables -F OUTPUT

# 2. Allow loopback
iptables -A OUTPUT -o lo -j ACCEPT

# 3. Allow established connections
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# 4. Allow DNS, NTP, SSH, and kubectl
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
iptables -A OUTPUT -p udp --dport 123 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 6443 -j ACCEPT

# 5. Allow only Conduit (UID 1000 or specific service user) to connect out on 80/443
# Replace 'conduit' with the proxy system user
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m owner --uid-owner conduit -j ACCEPT

# 6. Reject everything else
iptables -A OUTPUT -m limit --limit 5/min -j LOG --log-prefix "[EGRESS BLOCKED]: "
iptables -A OUTPUT -j REJECT --reject-with icmp-port-unreachable
```

---

## 5. Verification & Testing

Verify that your lockdown policy is effective:

### 1. Test Permitted Web Traffic via Conduit
```bash
curl -i -s -x http://127.0.0.1:8888 https://api.anthropic.com/
# Output: HTTP/1.1 200 OK
```

### 2. Test Disallowed Outbound Port via Conduit
Attempting to connect to an unauthorized port like 1234 through Conduit:
```bash
curl -i -s -x http://127.0.0.1:8888 https://example.com:1234/
# Output: HTTP/1.1 403 Forbidden
# Conduit log: "CONNECT rejected: port not permitted by egress policy"
```

### 3. Test Direct Outbound Socket Bypass (Simulating Malware)
Attempting to bypass Conduit and connect directly to an external port:
```bash
curl --noproxy "*" -m 3 https://example.com:1234/
# Output: curl: (28) Failed to connect to example.com port 1234: Connection timed out / rejected
# Kernel log: [EGRESS BLOCKED]: IN= OUT=enp7s0 SRC=... DST=... DPT=1234 ...
```

### 4. Verify Local Agent Callbacks Still Work
Verify that local OAuth redirect listeners (e.g. port 45678) succeed:
```bash
python3 -m http.server 45678 --bind 127.0.0.1 &
PID=$!
curl -s -x http://127.0.0.1:8888 http://localhost:45678/
kill $PID
# Output: 404 / 200 (connection permitted through proxy)
```

---

## 6. Desktop Notifications, Noise Reduction & Alert Muting

When an outbound connection or port is blocked, Conduit alerts local desktop users via native freedesktop notifications (`notify-send`).

### Intelligent Stacking & Noise Reduction
To prevent notification storms when an application repeatedly retries a blocked connection (e.g. dozens of times a second):
1. **Replacement Stacking (`-r <id>`)**: Subsequent blocks for the same `host:port` update the existing toast in-place (`Conduit: Outbound Blocked (x5)`) rather than spamming new popups.
2. **Rate Limiting**: Updates are throttled to at most once every 2 seconds.
3. **Local Origin Scoping**: Only requests originating from the local machine trigger notifications; external LAN clients proxying through the gateway do not generate desktop alerts.

### Muting Noisy Domains (Telemetry / Beacons)
Certain applications (such as telemetry beacons like Datadog `browser-intake-us5-datadoghq.com`) retry aggressively in the background when blocked. You can silence notifications for these domains while keeping traffic blocked:

#### 1. Via 1-Click Omarchy Panel
In the Omarchy bar menu (`io.github.the2dl.conduit`), under **Recent Blocked Traffic**:
* Click **`[Mute]`** next to any blocked host to immediately silence all desktop notifications for that domain while continuing to block its traffic.
* Click **`[Allow]`** if you wish to unblock the host and permit traffic through.

#### 2. Via `conduit.toml` Configuration
Add domains or wildcard patterns to `[notifications]`:
```toml
[notifications]
enabled = true
min_interval_secs = 2
muted_domains = [
    "browser-intake-us5-datadoghq.com",
    "*.datadoghq.com",
    "*.telemetry.corp",
]
```

#### 3. Via REST API
Dynamically mute or unmute domains at runtime without restarting Conduit:
```bash
# Mute a domain
curl -X POST http://127.0.0.1:8443/api/v1/notifications/mute \
  -H "Content-Type: application/json" \
  -d '{"domain": "browser-intake-us5-datadoghq.com"}'

# List currently muted domains
curl http://127.0.0.1:8443/api/v1/notifications/mutes

# Unmute a domain
curl -X DELETE http://127.0.0.1:8443/api/v1/notifications/mute \
  -H "Content-Type: application/json" \
  -d '{"domain": "browser-intake-us5-datadoghq.com"}'
```

