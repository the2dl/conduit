#!/usr/bin/env bash
# Source this file to route your current shell / subshell traffic through Conduit:
#   source /home/dan/conduit/scripts/env.sh

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export http_proxy="http://127.0.0.1:8888"
export https_proxy="http://127.0.0.1:8888"
export HTTP_PROXY="http://127.0.0.1:8888"
export HTTPS_PROXY="http://127.0.0.1:8888"
export ALL_PROXY="http://127.0.0.1:8888"
export no_proxy="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
export NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"

# CA Bundle for curl, python requests/urllib, Node.js, git, and OpenSSL.
# Prefer combined bundle or system trust bundle (which includes Conduit CA + public internet roots).
# This allows bypassed/allowlisted domains (e.g. *.googleapis.com, *.google.com) to verify
# alongside Conduit-intercepted traffic.
CA_BUNDLE="/etc/conduit/ca/ca-bundle.pem"
if [ ! -f "$CA_BUNDLE" ]; then
    for f in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt /etc/ssl/ca-bundle.pem /etc/ssl/cert.pem; do
        if [ -f "$f" ]; then
            CA_BUNDLE="$f"
            break
        fi
    done
fi
[ ! -f "$CA_BUNDLE" ] && CA_BUNDLE="${DIR}/ca/ca.pem"

export CURL_CA_BUNDLE="$CA_BUNDLE"
export SSL_CERT_FILE="$CA_BUNDLE"
export REQUESTS_CA_BUNDLE="$CA_BUNDLE"
export NODE_EXTRA_CA_CERTS="${DIR}/ca/ca.pem"
export GIT_SSL_CAINFO="$CA_BUNDLE"
export CODEX_CA_CERTIFICATE="$CA_BUNDLE"
export AWS_CA_BUNDLE="$CA_BUNDLE"

# Node.js built-in fetch (undici) proxy support (Node 20.18+, 22.1+, 24+)
if command -v node >/dev/null 2>&1 && node --use-env-proxy -e 'process.exit(0)' 2>/dev/null; then
    case " ${NODE_OPTIONS:-} " in
        *" --use-env-proxy "*) ;;
        *) export NODE_OPTIONS="${NODE_OPTIONS:+$NODE_OPTIONS }--use-env-proxy" ;;
    esac
fi

if [[ $- == *i* ]]; then
    echo "Conduit proxy environment enabled (127.0.0.1:8888)."
fi
