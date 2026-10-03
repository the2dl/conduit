#!/usr/bin/env bash
# Source this file to route your current shell / subshell traffic through Conduit:
#   source /home/dan/conduit/scripts/env.sh

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

export http_proxy="http://192.168.44.72:8888"
export https_proxy="http://192.168.44.72:8888"
export HTTP_PROXY="http://192.168.44.72:8888"
export HTTPS_PROXY="http://192.168.44.72:8888"
export ALL_PROXY="http://192.168.44.72:8888"
export no_proxy="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"
export NO_PROXY="localhost,127.0.0.1,::1,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,169.254.0.0/16,.local,.internal,.svc,.cluster.local"

# CA Bundle for curl, python requests/urllib, Node.js, git, and OpenSSL
export CURL_CA_BUNDLE="${DIR}/ca/ca.pem"
export SSL_CERT_FILE="${DIR}/ca/ca.pem"
export REQUESTS_CA_BUNDLE="${DIR}/ca/ca.pem"
export NODE_EXTRA_CA_CERTS="${DIR}/ca/ca.pem"
export GIT_SSL_CAINFO="${DIR}/ca/ca.pem"

if [[ $- == *i* ]]; then
    echo "Conduit proxy environment enabled (192.168.44.72:8888)."
fi
