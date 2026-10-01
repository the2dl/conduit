// Pure utility and parsing helpers for Conduit Quickshell plugin.
.pragma library

function parseStats(jsonString) {
  try {
    var data = JSON.parse(jsonString);
    return {
      totalRequests: Number(data.total_requests || 0),
      blockedRequests: Number(data.blocked_requests || 0),
      activeConnections: Number(data.active_connections || 0),
      tlsIntercepted: Number(data.tls_intercepted || 0),
      cacheHits: Number(data.cache_hits || 0),
      cacheMisses: Number(data.cache_misses || 0),
      threatBlocks: Number(data.threat_blocks || 0),
      threatTier0Evals: Number(data.threat_tier0_evals || 0),
      threatTier1Escalations: Number(data.threat_tier1_escalations || 0),
      threatTier2Escalations: Number(data.threat_tier2_escalations || 0),
      threatTier3Escalations: Number(data.threat_tier3_escalations || 0)
    };
  } catch (e) {
    return null;
  }
}

function parsePrometheus(text) {
  var metrics = {
    activeConnections: 0,
    requestsTotal: 0,
    requestsAllowed: 0,
    requestsBlocked: 0,
    cacheHits: 0,
    cacheMisses: 0,
    threatTier0Evals: 0
  };
  if (!text) return metrics;

  var lines = text.split("\n");
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i].trim();
    if (line === "" || line[0] === "#") continue;

    if (line.indexOf("conduit_active_connections ") === 0) {
      metrics.activeConnections = parseFloat(line.split(" ")[1]) || 0;
    } else if (line.indexOf("conduit_requests_total") === 0) {
      var parts = line.split(" ");
      var val = parseFloat(parts[parts.length - 1]) || 0;
      metrics.requestsTotal += val;
      if (line.indexOf('action="allow"') !== -1) metrics.requestsAllowed += val;
      if (line.indexOf('action="block"') !== -1) metrics.requestsBlocked += val;
    } else if (line.indexOf("conduit_cache_hits_total ") === 0) {
      metrics.cacheHits = parseFloat(line.split(" ")[1]) || 0;
    } else if (line.indexOf("conduit_cache_misses_total ") === 0) {
      metrics.cacheMisses = parseFloat(line.split(" ")[1]) || 0;
    } else if (line.indexOf("conduit_threat_evaluations_total") === 0) {
      var tParts = line.split(" ");
      metrics.threatTier0Evals += parseFloat(tParts[tParts.length - 1]) || 0;
    }
  }
  return metrics;
}

function formatRate(rate) {
  if (!isFinite(rate) || rate < 0) return "0.0 req/s";
  if (rate >= 100) return Math.round(rate) + " req/s";
  if (rate >= 10) return rate.toFixed(1) + " req/s";
  return rate.toFixed(1) + " req/s";
}

function formatRatio(part, total) {
  if (!isFinite(part) || !isFinite(total) || total <= 0) return "0.0%";
  var pct = (part / total) * 100.0;
  return pct.toFixed(1) + "%";
}

function formatNumber(n) {
  if (!isFinite(n) || n < 0) return "0";
  return Math.round(n).toLocaleString();
}
