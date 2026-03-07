#!/usr/bin/env node
//
// Minimal mock upstream server for stress testing.
// Avoids hitting real external services and removes network variability.
//
// Usage:
//   node mock-upstream.js [--http-port 18080] [--https-port 18443]
//
// The server responds to common httpbin-style routes with minimal latency.

const http = require("http");
const https = require("https");
const crypto = require("crypto");
const { argv } = require("process");

const HTTP_PORT = parseInt(getArg("--http-port") || "18080");
const HTTPS_PORT = parseInt(getArg("--https-port") || "18443");

function getArg(name) {
  const idx = argv.indexOf(name);
  return idx !== -1 && idx + 1 < argv.length ? argv[idx + 1] : null;
}

// Self-signed cert for HTTPS
const { privateKey, publicKey } = crypto.generateKeyPairSync("rsa", {
  modulusLength: 2048,
});

// Generate a self-signed certificate using node's built-in crypto
// For simplicity, we'll use a pre-generated cert approach
const selfSignedCert = generateSelfSignedCert();

function generateSelfSignedCert() {
  // Use openssl-like approach with node crypto
  // Fall back to inline test cert if needed
  try {
    const { execSync } = require("child_process");
    const tmpKey = "/tmp/mock-upstream-key.pem";
    const tmpCert = "/tmp/mock-upstream-cert.pem";
    execSync(
      `openssl req -x509 -newkey rsa:2048 -keyout ${tmpKey} -out ${tmpCert} -days 1 -nodes -subj '/CN=localhost' 2>/dev/null`
    );
    const fs = require("fs");
    return {
      key: fs.readFileSync(tmpKey),
      cert: fs.readFileSync(tmpCert),
    };
  } catch {
    console.error(
      "Warning: Could not generate self-signed cert, HTTPS mock disabled"
    );
    return null;
  }
}

// Pre-generate random byte buffers for /bytes/:n responses
const BYTE_CACHE = {};
function getBytes(n) {
  n = Math.min(n, 10 * 1024 * 1024); // cap at 10MB
  if (!BYTE_CACHE[n]) {
    BYTE_CACHE[n] = crypto.randomBytes(n);
  }
  return BYTE_CACHE[n];
}

function handler(req, res) {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname;

  // Route matching
  if (path === "/get" || path === "/headers" || path === "/small") {
    const body = JSON.stringify({
      url: req.url,
      headers: req.headers,
      method: req.method,
      origin: req.socket.remoteAddress,
    });
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": body.length,
    });
    res.end(body);
    return;
  }

  if (path === "/ip" || path === "/user-agent" || path === "/uuid") {
    const body = JSON.stringify({
      origin: req.socket.remoteAddress,
      "user-agent": req.headers["user-agent"],
      uuid: crypto.randomUUID(),
    });
    res.writeHead(200, {
      "Content-Type": "application/json",
      "Content-Length": body.length,
    });
    res.end(body);
    return;
  }

  const bytesMatch = path.match(/^\/bytes\/(\d+)$/);
  if (bytesMatch) {
    const n = parseInt(bytesMatch[1]);
    const data = getBytes(n);
    res.writeHead(200, {
      "Content-Type": "application/octet-stream",
      "Content-Length": data.length,
    });
    res.end(data);
    return;
  }

  const statusMatch = path.match(/^\/status\/(\d+)$/);
  if (statusMatch) {
    const code = parseInt(statusMatch[1]);
    res.writeHead(code, { "Content-Length": "0" });
    res.end();
    return;
  }

  if (path === "/health") {
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
    return;
  }

  // Default: 200 with small body
  const body = "ok";
  res.writeHead(200, {
    "Content-Type": "text/plain",
    "Content-Length": body.length,
  });
  res.end(body);
}

// Start HTTP server
const httpServer = http.createServer(handler);
httpServer.maxConnections = 0; // unlimited
httpServer.keepAliveTimeout = 120000;
httpServer.headersTimeout = 120000;
httpServer.listen(HTTP_PORT, () => {
  console.log(`Mock HTTP upstream listening on :${HTTP_PORT}`);
});

// Start HTTPS server if cert available
if (selfSignedCert) {
  const httpsServer = https.createServer(selfSignedCert, handler);
  httpsServer.maxConnections = 0;
  httpsServer.keepAliveTimeout = 120000;
  httpsServer.headersTimeout = 120000;
  httpsServer.listen(HTTPS_PORT, () => {
    console.log(`Mock HTTPS upstream listening on :${HTTPS_PORT}`);
  });
}

// Handle graceful shutdown
process.on("SIGINT", () => process.exit(0));
process.on("SIGTERM", () => process.exit(0));
