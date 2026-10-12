#!/usr/bin/env python3
"""Exercise assessment capture against isolated Conduit/Valkey processes."""
import base64
import contextlib
import http.client
import http.server
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Origin(http.server.BaseHTTPRequestHandler):
    held_started = threading.Event()
    held_release = threading.Event()
    def do_GET(self):
        self.respond()

    def do_POST(self):
        self.respond()

    def respond(self):
        body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
        if urlsplit(self.path).path == "/held":
            self.held_started.set()
            assert self.held_release.wait(timeout=5)
        payload = json.dumps({"method": self.command, "path": self.path,
                              "headers": dict(self.headers), "body": body.decode()}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):
        pass


def wait_for(predicate, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = predicate()
            if result:
                return result
        except (OSError, urllib.error.URLError, subprocess.CalledProcessError):
            pass
        time.sleep(0.1)
    raise AssertionError("timed out waiting for isolated service")


def main():
    datastore = shutil.which("valkey-server") or shutil.which("redis-server")
    cli = shutil.which("valkey-cli") or shutil.which("redis-cli")
    assert datastore and cli, "Valkey/Redis server and CLI required"
    assert (ROOT / "target/debug/conduit-api").exists(), "build conduit-api first"
    assert (ROOT / "target/debug/conduit-proxy").exists(), "build conduit-proxy first"
    db_port, api_port, proxy_port = port(), port(), port()
    origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
    origin_url = f"http://127.0.0.1:{origin.server_port}"
    threading.Thread(target=origin.serve_forever, daemon=True).start()
    processes = []
    tls_origin = None
    try:
        with tempfile.TemporaryDirectory(prefix="conduit-assessment-test-") as scratch:
            scratch = Path(scratch)
            subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                            "-subj", "/CN=assessment.example.com", "-keyout", str(scratch / "origin.key"),
                            "-out", str(scratch / "origin.pem")], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            tls_origin = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Origin)
            tls_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls_context.load_cert_chain(scratch / "origin.pem", scratch / "origin.key")
            tls_origin.socket = tls_context.wrap_socket(tls_origin.socket, server_side=True)
            threading.Thread(target=tls_origin.serve_forever, daemon=True).start()
            config = scratch / "conduit.toml"
            config.write_text(f'''listen_addr = "127.0.0.1:{proxy_port}"
api_addr = "127.0.0.1:{api_port}"
dragonfly_url = "redis://127.0.0.1:{db_port}"
workers = 1
ca_cert_path = "{scratch}/ca.pem"
ca_key_path = "{scratch}/ca-key.pem"
[allowlist]
hosts = ["127.0.0.1"]
[load_balancing]
enabled = true
[[load_balancing.upstreams]]
name = "isolated-tls-origin"
domains = ["assessment.example.com"]
backends = [{{addr = "127.0.0.1:{tls_origin.server_port}"}}]
''')
            env = os.environ.copy()
            env.update(CONDUIT_CONFIG=str(config), CONDUIT_ASSESSMENT_KEY=base64.b64encode(secrets.token_bytes(32)).decode(), CONDUIT_ASSESSMENT_API_KEY="integration-key")
            opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

            def api(path, method="GET", payload=None, authenticated=True, expected=200):
                headers = {"Content-Type": "application/json"}
                if authenticated:
                    headers["Authorization"] = "Bearer integration-key"
                request = urllib.request.Request(f"http://127.0.0.1:{api_port}/api/v1{path}",
                    data=None if payload is None else json.dumps(payload).encode(), headers=headers, method=method)
                try:
                    response = opener.open(request, timeout=5)
                except urllib.error.HTTPError as error:
                    response = error
                assert response.status == expected, (response.status, response.read())
                raw = response.read()
                return json.loads(raw) if raw else {}

            def redis(*args):
                return subprocess.check_output([cli, "-p", str(db_port), "--raw", *args], text=True, stderr=subprocess.DEVNULL).strip()

            with contextlib.ExitStack() as stack:
                def start(command, name):
                    log = stack.enter_context((scratch / f"{name}.log").open("w"))
                    process = subprocess.Popen(command, cwd=scratch, env=env, stdout=log, stderr=log)
                    processes.append(process)

                start([datastore, "--bind", "127.0.0.1", "--port", str(db_port), "--save", "", "--appendonly", "no"], "valkey")
                wait_for(lambda: redis("PING") == "PONG")
                start([str(ROOT / "target/debug/conduit-api")], "api")
                start([str(ROOT / "target/debug/conduit-proxy")], "proxy")
                wait_for(lambda: api("/health")["valkey"])
                wait_for(lambda: socket.create_connection(("127.0.0.1", proxy_port), timeout=1).close() or True)

                def create(**kwargs):
                    return api("/assessments", "POST", {"origins": [origin_url], **kwargs})["session"]

                def send(path, session=None, token=None, body=None):
                    headers = {"Authorization": "Bearer target-secret", "Cookie": "session=target-cookie"}
                    if session:
                        headers["X-Conduit-Assessment"] = session["id"]
                        headers["X-Conduit-Capture-Token"] = token or session["token"]
                    connection = http.client.HTTPConnection("127.0.0.1", proxy_port, timeout=5)
                    connection.request("POST" if body is not None else "GET", origin_url + path, body=body, headers=headers)
                    response = connection.getresponse()
                    data = response.read()
                    assert response.status == 200, data
                    connection.close()
                    result = json.loads(data)
                    assert "X-Conduit-Assessment" not in result["headers"]
                    assert "X-Conduit-Capture-Token" not in result["headers"]
                    return result

                api("/assessments", "POST", {"origins": [origin_url]}, authenticated=False, expected=401)
                api("/stats", authenticated=False)
                session = create()
                run = session["id"]
                path = f"/assessments/{run}"
                assert "token" not in api(path)
                api("/assessments", "POST", {"origins": []}, expected=400)
                api("/assessments", "POST", {"origins": [origin_url], "ttl_seconds": 86401}, expected=400)
                send("/ordinary")
                send("/invalid-token", session, token="bad")
                assert api(path + "/flows")["total"] == 0
                result = send("/captured?probe=1", session, body="original-body-secret")
                assert result["headers"]["Authorization"] == "Bearer target-secret"
                listing = wait_for(lambda: api(path + "/flows")["entries"])
                flow_id = listing[0]["id"]
                flow = api(path + "/flows/" + flow_id)
                assert base64.b64decode(flow["request"]["body_base64"]) == b"original-body-secret"
                encrypted = redis("GET", f"conduit:assessment:{run}:flow:{flow_id}")
                assert "target-secret" not in encrypted and "original-body-secret" not in encrypted
                assert "target-secret".encode() not in base64.b64decode(encrypted)
                assert redis("TTL", f"conduit:assessment:{run}:flow:{flow_id}").isdigit()
                assert api(path + "/flows?search=/captured")["total"] == 1
                replay = api(path + f"/flows/{flow_id}/replay", "POST", {
                    "method": "POST", "url": origin_url + "/mutated", "body_base64": base64.b64encode(b"replacement").decode(),
                    "set_headers": [["Authorization", "Bearer other"]], "remove_headers": ["Cookie"]})
                assert replay["status"] == 200 and replay["flow_id"]
                echoed = json.loads(base64.b64decode(replay["response"]["body_base64"]))
                assert urlsplit(echoed["path"]).path == "/mutated" and echoed["body"] == "replacement", echoed
                assert echoed["headers"].get("authorization") == "Bearer other"
                assert "cookie" not in echoed["headers"] and "Cookie" not in echoed["headers"]
                api(path + f"/flows/{flow_id}/replay", "POST", {"url": "http://example.com/out-of-scope"}, expected=400)
                other = create()
                api(f"/assessments/{other['id']}/flows/{flow_id}", expected=404)
                scoped_out = api("/assessments", "POST", {"origins": ["http://example.com"]})["session"]
                send("/outside", scoped_out)
                assert api(f"/assessments/{scoped_out['id']}/flows")["total"] == 0
                capped = create(max_body_bytes=3, max_flows=1)
                send("/bounded", capped, body="abcdef")
                capped_path = f"/assessments/{capped['id']}"
                capped_id = wait_for(lambda: api(capped_path + "/flows")["entries"])[0]["id"]
                bounded = api(capped_path + "/flows/" + capped_id)
                assert bounded["request"]["truncated"] and bounded["response"]["truncated"]
                assert base64.b64decode(bounded["request"]["body_base64"]) == b"abc"
                api(capped_path + f"/flows/{capped_id}/replay", "POST", {}, expected=400)
                send("/beyond-cap", capped)
                time.sleep(0.2)
                assert api(capped_path + "/flows")["total"] == 1
                expiring = create(ttl_seconds=1)
                send("/expiring", expiring)
                expiring_path = f"/assessments/{expiring['id']}"
                wait_for(lambda: redis("EXISTS", f"conduit:assessment:{expiring['id']}:session") == "0", timeout=3)
                api(expiring_path, expected=404)
                assert redis("KEYS", f"conduit:assessment:{expiring['id']}:*") == ""
                held = create()
                held_errors = []
                def held_request():
                    try:
                        send("/held", held)
                    except Exception as error:
                        held_errors.append(error)
                held_thread = threading.Thread(target=held_request)
                held_thread.start()
                assert Origin.held_started.wait(timeout=5)
                api(f"/assessments/{held['id']}", "DELETE")
                Origin.held_release.set()
                held_thread.join(timeout=5)
                assert not held_thread.is_alive() and not held_errors, held_errors
                time.sleep(0.1)
                assert redis("KEYS", f"conduit:assessment:{held['id']}:*") == ""
                wait_for(lambda: api(path + "/flows")["total"] >= 2)
                deleted = api(path, "DELETE")
                assert deleted["deleted"] >= 2
                assert redis("KEYS", f"conduit:assessment:{run}:*") == ""
                # Real CONNECT + TLS interception + inner HTTP capture, all local.
                tls_session = api("/assessments", "POST", {"origins": ["https://assessment.example.com"]})["session"]
                ca_pem = opener.open(f"http://127.0.0.1:{api_port}/api/v1/ca/cert", timeout=5).read()
                trusted = ssl.create_default_context(cadata=ca_pem.decode())
                connection = http.client.HTTPSConnection("127.0.0.1", proxy_port, timeout=10, context=trusted)
                connection.set_tunnel("assessment.example.com", 443)
                connection.request("POST", "/tls-captured", body="tls-secret", headers={
                    "X-Conduit-Assessment": tls_session["id"], "X-Conduit-Capture-Token": tls_session["token"],
                    "Authorization": "Bearer tls-target"})
                response = connection.getresponse()
                data = response.read()
                assert response.status == 200, data
                echoed = json.loads(data)
                assert "X-Conduit-Capture-Token" not in echoed["headers"]
                connection.close()
                tls_path = f"/assessments/{tls_session['id']}"
                tls_id = wait_for(lambda: api(tls_path + "/flows")["entries"])[0]["id"]
                tls_flow = api(tls_path + "/flows/" + tls_id)
                assert tls_flow["url"] == "https://assessment.example.com/tls-captured"
                assert base64.b64decode(tls_flow["request"]["body_base64"]) == b"tls-secret"
                tls_replay = api(tls_path + f"/flows/{tls_id}/replay", "POST", {})
                assert tls_replay["status"] == 200 and tls_replay["flow_id"]
                send("/deleted", session)
                assert redis("KEYS", f"conduit:assessment:{run}:*") == ""
                print("PASS: authentication, capture opt-in, header stripping, encrypted storage, search, replay mutation, origin/session isolation, truncation, flow cap, expiry, deletion, HTTPS interception and replay")
    finally:
        Origin.held_release.set()
        for process in reversed(processes):
            process.terminate()
        for process in reversed(processes):
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
        origin.shutdown()
        origin.server_close()
        if tls_origin:
            tls_origin.shutdown()
            tls_origin.server_close()


if __name__ == "__main__":
    main()
