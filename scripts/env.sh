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

# CA Bundle for curl, python requests/urllib, Node.js, git, and OpenSSL
export CURL_CA_BUNDLE="${DIR}/ca/ca.pem"
export SSL_CERT_FILE="${DIR}/ca/ca.pem"
export REQUESTS_CA_BUNDLE="${DIR}/ca/ca.pem"
export NODE_EXTRA_CA_CERTS="${DIR}/ca/ca.pem"
export GIT_SSL_CAINFO="${DIR}/ca/ca.pem"
export CODEX_CA_CERTIFICATE="${DIR}/ca/ca.pem"
export AWS_CA_BUNDLE="${DIR}/ca/ca.pem"

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
