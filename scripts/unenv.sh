#!/usr/bin/env bash
# Source this file to disable Conduit proxying in your current shell:
#   source /home/dan/conduit/scripts/unenv.sh

unset http_proxy https_proxy HTTP_PROXY HTTPS_PROXY ALL_PROXY no_proxy NO_PROXY
unset CURL_CA_BUNDLE SSL_CERT_FILE REQUESTS_CA_BUNDLE NODE_EXTRA_CA_CERTS GIT_SSL_CAINFO CODEX_CA_CERTIFICATE AWS_CA_BUNDLE

if [[ $- == *i* ]]; then
    echo "Conduit proxy environment disabled."
fi
