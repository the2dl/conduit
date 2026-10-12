#!/usr/bin/env bash
# shellcheck source-path=SCRIPTDIR
# Deploy already-built assessment binaries and keys under the rollback watchdog.
set -euo pipefail
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
SOURCE_ROOT=$(dirname "$SCRIPT_DIR")
# Compile every embedded Python block before configuring keys or restarting.
python3 - "${BASH_SOURCE[0]}" <<'CHECK_PY'
import pathlib, re, sys
source = pathlib.Path(sys.argv[1]).read_text()
blocks = re.findall(r"<<'PY'\n(.*?)\nPY(?:\n|$)", source, re.S)
if len(blocks) != 3:
    raise RuntimeError('activation script Python block layout changed; update preflight')
for number, block in enumerate(blocks, 1):
    compile(block, sys.argv[1] + ':python-block-' + str(number), 'exec')
CHECK_PY
if [ "${1:-}" = --check ]; then echo "Activation Python preflight passed."; exit 0; fi
CLIENT_USER=${1:?usage: sudo bash scripts/activate-assessment.sh CLIENT_USER [--verify-request-metadata]}
VERIFY_REQUEST_METADATA=${2:-}
if [ -n "$VERIFY_REQUEST_METADATA" ] && [ "$VERIFY_REQUEST_METADATA" != --verify-request-metadata ]; then
  echo "Unknown activation option: $VERIFY_REQUEST_METADATA" >&2; exit 1
fi
[ "$EUID" -eq 0 ] || { echo "Activation requires root." >&2; exit 1; }
for binary in conduit-api conduit-proxy; do
  [ -x "$SOURCE_ROOT/target/release/$binary" ] || { echo "Build $binary in release mode first." >&2; exit 1; }
done
CLIENT_DIR=$(python3 - "$CLIENT_USER" <<'PY'
import pwd, sys
print(pwd.getpwnam(sys.argv[1]).pw_dir + '/.config/conduit')
PY
)
STATE=$(bash "$SCRIPT_DIR/rollback-deploy.sh" checkpoint system "$SOURCE_ROOT" "${CONDUIT_DEPLOY_CHECK_URL:-https://example.com/}")
[ -n "$STATE" ] || { echo "Activation expects an existing system installation." >&2; exit 1; }
# Include all new key/drop-in files in the existing rollback transaction.
# shellcheck source=rollback-deploy.sh
source "$SCRIPT_DIR/rollback-deploy.sh"
snapshot_file "$STATE" /etc/conduit/assessment-encryption.env 20
snapshot_file "$STATE" /etc/conduit/assessment-api.env 21
snapshot_file "$STATE" /etc/systemd/system/conduit-api.service.d/assessment.conf 22
snapshot_file "$STATE" /etc/systemd/system/conduit-proxy.service.d/assessment.conf 23
snapshot_file "$STATE" "$CLIENT_DIR/assessment-client.env" 24
snapshot_file "$STATE" /usr/local/bin/conduit-ctl 25
ACTIVATION_STATE=$STATE
activation_exit() {
  local result=$?
  trap - EXIT
  if [ "$result" -ne 0 ] && [ -n "$ACTIVATION_STATE" ]; then
    bash "$SCRIPT_DIR/rollback-deploy.sh" rollback "$ACTIVATION_STATE" || true
  fi
  exit "$result"
}
trap activation_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
bash "$SCRIPT_DIR/rollback-deploy.sh" arm "$ACTIVATION_STATE" "$$"

python3 - "$CLIENT_USER" <<'PY'
import base64, os, pathlib, pwd, secrets
account = pwd.getpwnam(__import__('sys').argv[1])
def existing_or_generate(path, name, value):
    path = pathlib.Path(path)
    if path.is_symlink():
        raise RuntimeError('refusing symlink key file')
    if path.exists():
        lines = dict(line.split('=', 1) for line in path.read_text().splitlines() if '=' in line)
        result = lines.get(name, '')
        if not result:
            raise RuntimeError('existing key file is invalid')
    else:
        result = value
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'w') as handle:
            handle.write(name + '=' + result + '\n')
    path.chmod(0o600)
    os.chown(path, 0, 0)
    return result
encryption = existing_or_generate('/etc/conduit/assessment-encryption.env', 'CONDUIT_ASSESSMENT_KEY', base64.b64encode(secrets.token_bytes(32)).decode())
if len(base64.b64decode(encryption, validate=True)) != 32:
    raise RuntimeError('encryption key must decode to 32 bytes')
api_key = existing_or_generate('/etc/conduit/assessment-api.env', 'CONDUIT_ASSESSMENT_API_KEY', secrets.token_hex(32))
if any(c not in 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/=_-' for c in api_key):
    raise RuntimeError('API key contains unsupported environment characters')
client = pathlib.Path(account.pw_dir) / '.config/conduit'
client.mkdir(mode=0o700, parents=True, exist_ok=True)
if client.is_symlink():
    raise RuntimeError('refusing symlink client directory')
os.chown(client, account.pw_uid, account.pw_gid)
target = client / 'assessment-client.env'
if target.is_symlink():
    raise RuntimeError('refusing symlink client key file')
fd = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as handle:
    handle.write('CONDUIT_ASSESSMENT_API_KEY=' + api_key + '\nCONDUIT_API_URL=http://127.0.0.1:8443\nCONDUIT_PROXY=http://127.0.0.1:8888\n')
target.chmod(0o600)
os.chown(target, account.pw_uid, account.pw_gid)
for service in ('conduit-api', 'conduit-proxy'):
    directory = pathlib.Path('/etc/systemd/system') / (service + '.service.d')
    directory.mkdir(mode=0o755, exist_ok=True)
    content = '[Service]\nEnvironmentFile=/etc/conduit/assessment-encryption.env\n'
    if service == 'conduit-api':
        content += 'EnvironmentFile=/etc/conduit/assessment-api.env\n'
    (directory / 'assessment.conf').write_text(content)
    (directory / 'assessment.conf').chmod(0o644)
print('Keys configured; existing keys preserved. No secrets printed.')
PY

for binary in conduit-api conduit-proxy; do
  STAGE=$(mktemp "/usr/local/bin/.${binary}.XXXXXX")
  install -m 755 "$SOURCE_ROOT/target/release/$binary" "$STAGE"
  mv -fT "$STAGE" "/usr/local/bin/$binary"
done
install -m 755 "$SCRIPT_DIR/conduit-ctl.sh" /usr/local/bin/conduit-ctl
systemctl daemon-reload
systemctl restart conduit-api.service conduit-proxy.service

python3 - "$VERIFY_REQUEST_METADATA" <<'PY'
import base64, http.client, http.server, json, pathlib, socket, subprocess, sys, threading, time, urllib.error, urllib.request
values = dict(line.split('=', 1) for line in pathlib.Path('/etc/conduit/assessment-api.env').read_text().splitlines() if '=' in line)
key = values['CONDUIT_ASSESSMENT_API_KEY']
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
def api(path, method='GET', payload=None, auth=True, expected=200):
    headers = {'Content-Type': 'application/json'}
    if auth: headers['Authorization'] = 'Bearer ' + key
    request = urllib.request.Request('http://127.0.0.1:8443/api/v1' + path, method=method, headers=headers,
                                    data=None if payload is None else json.dumps(payload).encode())
    try: response = opener.open(request, timeout=5)
    except urllib.error.HTTPError as error: response = error
    if response.status != expected:
        raise RuntimeError('unexpected API status: ' + str(response.status))
    raw = response.read()
    return json.loads(raw) if raw else {}
for attempt in range(90):
    try:
        if api('/health', auth=False)['status'] == 'healthy':
            with socket.create_connection(('127.0.0.1', 8888), timeout=1):
                break
    except (OSError, urllib.error.URLError): pass
    time.sleep(1)
else: raise RuntimeError('API/proxy listeners did not become ready')
api('/stats', auth=False)
api('/assessments', 'POST', {'origins': ['http://127.0.0.1:3000']}, auth=False, expected=401)
class Origin(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', '0')))
        if self.headers.get('X-Conduit-Capture-Token') or self.headers.get('X-Conduit-Assessment'):
            self.send_error(500); return
        self.send_response(200)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)
    def log_message(self, *_): pass
origin = http.server.ThreadingHTTPServer(('127.0.0.1', 0), Origin)
threading.Thread(target=origin.serve_forever, daemon=True).start()
run = None
try:
    url = 'http://127.0.0.1:' + str(origin.server_port) + '/assessment-smoke'
    session = api('/assessments', 'POST', {'origins': [url], 'ttl_seconds': 300})['session']
    run = session['id']
    connection = http.client.HTTPConnection('127.0.0.1', 8888, timeout=10)
    connection.request('POST', url, body='conduit-live-smoke', headers={
        'X-Conduit-Assessment': run, 'X-Conduit-Capture-Token': session['token']})
    response = connection.getresponse()
    if response.status != 200 or response.read() != b'conduit-live-smoke':
        raise RuntimeError('live proxied smoke request failed')
    connection.close()
    for attempt in range(30):
        entries = api('/assessments/' + run + '/flows')['entries']
        if entries: break
        time.sleep(0.1)
    else: raise RuntimeError('live flow was not captured')
    flow_path = '/assessments/' + run + '/flows/' + entries[0]['id']
    flow = api(flow_path)
    if base64.b64decode(flow['request']['body_base64']) != b'conduit-live-smoke':
        raise RuntimeError('captured body mismatch')
    replay = api(flow_path + '/replay', 'POST', {'body_base64': base64.b64encode(b'conduit-replay-smoke').decode()})
    if replay['status'] != 200 or base64.b64decode(replay['response']['body_base64']) != b'conduit-replay-smoke':
        raise RuntimeError('live replay failed')
    if sys.argv[1] == '--verify-request-metadata':
        marker_url = 'http://127.0.0.1:' + str(origin.server_port) + '/referer-ua-smoke'
        referer, user_agent = 'https://example.com/conduit-deploy-parent', 'conduit-deploy-metadata-smoke/1.0'
        connection = http.client.HTTPConnection('127.0.0.1', 8888, timeout=10)
        # Untagged traffic verifies normal logs, independently of assessment capture.
        connection.request('POST', marker_url, body='normal-log-smoke', headers={
            'Referer': referer, 'User-Agent': user_agent})
        response = connection.getresponse()
        if response.status != 200 or response.read() != b'normal-log-smoke':
            raise RuntimeError('normal metadata smoke request failed')
        connection.close()
        for attempt in range(30):
            journal = subprocess.check_output(['journalctl', '-u', 'conduit-proxy', '--since', '2 minutes ago',
                '--no-pager', '-o', 'cat', '-n', '2000'], text=True)
            matched = False
            for line in journal.splitlines():
                try: record = json.loads(line)
                except ValueError: continue
                if record.get('full_url') == marker_url:
                    if record.get('referer') != referer or record.get('user_agent') != user_agent:
                        raise RuntimeError('normal log is missing expected referer/user_agent')
                    matched = True
                    break
            if matched: break
            time.sleep(0.1)
        else: raise RuntimeError('normal request metadata log did not arrive')
        print('PASS: untagged normal JSON log contains referer and user_agent.')
    print('PASS: dashboard API, assessment auth, live capture, header stripping, and mutated replay.')
finally:
    if run: api('/assessments/' + run, 'DELETE')
    origin.shutdown(); origin.server_close()
PY

bash "$SCRIPT_DIR/rollback-deploy.sh" verify-commit "$ACTIVATION_STATE"
echo "Assessment capture is live. Rollback checkpoint: $ACTIVATION_STATE"
ACTIVATION_STATE=""
echo "Client API key file: $CLIENT_DIR/assessment-client.env"
