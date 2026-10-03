import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root

  moduleName: "io.github.the2dl.conduit"
  ipcTarget: "io.github.the2dl.conduit"
  manageIpc: false

  // Theme roles & palette tokens
  readonly property color foreground: bar ? bar.barForeground : Color.foreground
  readonly property color accent: Color.accent
  readonly property color urgent: bar ? bar.urgent : Color.urgent
  readonly property color muted: Qt.darker(foreground, 1.35)
  readonly property color dim: Qt.darker(foreground, 1.6)
  readonly property color cardFill: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.04)
  readonly property color cardBorder: Qt.rgba(foreground.r, foreground.g, foreground.b, 0.10)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property bool rounded: Style.cornerRadius > 0

  // Status & Telemetry
  property bool running: false
  property bool preventionMode: false
  property bool tlsIntercept: true
  property double requestsPerSec: 0.0
  property double peakRequestsPerSec: 0.0
  property int activeConnections: 0
  property int totalRequests: 0
  property int blockedRequests: 0
  property int tlsIntercepted: 0
  property int threatEvals: 0
  property int threatEscalations: 0
  property int threatsBlocked: 0
  property int cacheHits: 0
  property int cacheMisses: 0
  property bool dragonflyConnected: true
  property var recentBlocked: []
  property var mutedDomains: []

  property double _lastTotalRequests: 0
  property double _lastSampleTime: 0
  property string _copyFeedback: ""

  // Config & Settings
  readonly property bool iconOnly: Boolean(setting("iconOnly", true))
  readonly property bool showThroughput: Boolean(setting("showThroughputInBar", false))
  readonly property int pollIntervalSec: Math.max(1, Number(setting("pollIntervalSec", 2)))
  readonly property string pollScriptPath: Quickshell.env("HOME") + "/.config/omarchy/plugins/io.github.the2dl.conduit/poll.sh"

  readonly property string heroGlyph: "󰇩"

  implicitWidth: iconOnly ? iconButton.implicitWidth : button.implicitWidth
  implicitHeight: iconOnly ? iconButton.implicitHeight : button.implicitHeight

  function setting(name, fallback) {
    var val = root.settings ? root.settings[name] : undefined
    return val === undefined || val === null ? fallback : val
  }

  function barLabel() {
    if (!root.running) return root.heroGlyph + " Inactive"
    if (!root.showThroughput) return root.heroGlyph + " Proxy"
    if (root.requestsPerSec <= 0) return root.heroGlyph + " 0 req/s"
    return root.heroGlyph + " " + Model.formatRate(root.requestsPerSec)
  }

  function tooltipText() {
    if (!root.running) return "Conduit Gateway: Inactive (Stopped)\nClick to open panel"
    return "Conduit Gateway: " + (root.preventionMode ? "Prevention Mode" : "Monitoring Mode") +
           "\nThroughput: " + Model.formatRate(root.requestsPerSec) +
           "\nActive Sockets: " + root.activeConnections +
           "\nTLS Intercepted: " + root.tlsIntercepted + " / " + root.totalRequests +
           "\nThreat Evals: " + root.threatEvals
  }

  function barPressed(buttonCode) {
    if (buttonCode === Qt.RightButton) {
      root.toggleProxyService()
    } else if (buttonCode === Qt.MiddleButton) {
      root.openPortal()
    } else {
      root.toggle()
    }
  }

  function openPortal() {
    Quickshell.execDetached(["omarchy-launch-browser", "http://127.0.0.1:8443"])
  }

  function copyCaCertPath() {
    var caPath = Quickshell.env("HOME") + "/conduit/ca/ca.pem"
    Quickshell.execDetached(["bash", "-c", "printf %s " + Util.shellQuote(caPath) + " | wl-copy"])
    root._copyFeedback = "CA Path Copied!"
    copyFeedbackTimer.restart()
  }

  function restartGateway() {
    serviceRestartProc.running = true
  }

  function allowTarget(host, port) {
    if (!host) return
    var cleanHost = host.trim()
    var ruleName = "Allow " + cleanHost
    var ruleId = "allow-" + cleanHost.replace(/[^a-zA-Z0-9]/g, "-")
    var payload = {
      "id": ruleId,
      "priority": 1,
      "name": ruleName,
      "enabled": true,
      "domains": [cleanHost],
      "categories": [],
      "users": [],
      "groups": [],
      "action": "allow"
    }
    createPolicyProc.command = [
      "curl", "-s", "--noproxy", "*", "--max-time", "2", "-X", "POST",
      "http://127.0.0.1:8443/api/v1/policies",
      "-H", "Content-Type: application/json",
      "-d", JSON.stringify(payload)
    ]
    createPolicyProc.running = true
    root._copyFeedback = "Allowed " + cleanHost + "!"
    copyFeedbackTimer.restart()
  }

  function isTargetMuted(host) {
    if (!host || !root.mutedDomains || root.mutedDomains.length === 0) return false
    var h = host.toLowerCase().trim()
    for (var i = 0; i < root.mutedDomains.length; i++) {
      var pat = String(root.mutedDomains[i]).toLowerCase().trim()
      if (pat.startsWith("*.")) {
        var suffix = pat.slice(2)
        if (h === suffix || h.endsWith("." + suffix)) return true
      } else if (pat.startsWith(".")) {
        var suffix = pat.slice(1)
        if (h === suffix || h.endsWith("." + suffix)) return true
      } else if (h === pat) {
        return true
      }
    }
    return false
  }

  function muteTarget(host) {
    if (!host) return
    var cleanHost = host.trim()
    muteDomainProc.command = [
      "curl", "-s", "--noproxy", "*", "--max-time", "2", "-X", "POST",
      "http://127.0.0.1:8443/api/v1/notifications/mute",
      "-H", "Content-Type: application/json",
      "-d", JSON.stringify({ "domain": cleanHost })
    ]
    muteDomainProc.running = true
    root._copyFeedback = "Muted " + cleanHost + "!"
    copyFeedbackTimer.restart()
  }

  function unmuteTarget(host) {
    if (!host) return
    var cleanHost = host.trim()
    muteDomainProc.command = [
      "curl", "-s", "--noproxy", "*", "--max-time", "2", "-X", "DELETE",
      "http://127.0.0.1:8443/api/v1/notifications/mute",
      "-H", "Content-Type: application/json",
      "-d", JSON.stringify({ "domain": cleanHost })
    ]
    muteDomainProc.running = true
    root._copyFeedback = "Unmuted " + cleanHost + "!"
    copyFeedbackTimer.restart()
  }

  function toggleProxyService() {
    var action = root.running ? "stop" : "start"
    serviceToggleProc.command = ["systemctl", "--user", action, "conduit.target"]
    serviceToggleProc.running = true
    root.running = !root.running // Optimistic toggle
  }

  function togglePreventionMode() {
    var nextVal = !root.preventionMode
    root.preventionMode = nextVal // Optimistic toggle
    putConfigProc.command = [
      "curl", "-s", "--noproxy", "*", "--max-time", "2", "-X", "PUT",
      "http://127.0.0.1:8443/api/v1/config",
      "-H", "Content-Type: application/json",
      "-d", JSON.stringify({ "prevention_mode": String(nextVal) })
    ]
    putConfigProc.running = true
  }

  function toggleTlsIntercept() {
    var nextVal = !root.tlsIntercept
    root.tlsIntercept = nextVal // Optimistic toggle
    putConfigProc.command = [
      "curl", "-s", "--noproxy", "*", "--max-time", "2", "-X", "PUT",
      "http://127.0.0.1:8443/api/v1/config",
      "-H", "Content-Type: application/json",
      "-d", JSON.stringify({ "tls_intercept": String(nextVal) })
    ]
    putConfigProc.running = true
  }

  function refresh() {
    if (!pollProc.running) {
      pollProc.running = true
    }
  }

  onOpenedChanged: {
    if (opened) {
      root.refresh()
      Qt.callLater(function() { keyCatcher.forceActiveFocus() })
    }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): string { root.open(); return "ok" }
    function close(): string { root.close(); return "ok" }
    function show(): string { root.open(); return "ok" }
    function hide(): string { root.close(); return "ok" }
    function toggle(): string { root.toggle(); return "ok" }
    function refresh(): string { root.refresh(); return "ok" }
    function portal(): string { root.openPortal(); return "ok" }
  }

  Timer {
    id: pollTimer
    interval: root.opened ? 1500 : (root.pollIntervalSec * 1000)
    repeat: true
    running: true
    triggeredOnStart: true
    onTriggered: root.refresh()
  }

  Timer {
    id: copyFeedbackTimer
    interval: 2500
    repeat: false
    onTriggered: root._copyFeedback = ""
  }

  // --- Background Process Runners ---

  Process {
    id: pollProc
    command: ["bash", root.pollScriptPath]
    stdout: StdioCollector {
      waitForEnd: true
      onStreamFinished: {
        try {
          var payload = JSON.parse(text)
          root.running = (payload.health && payload.health.status === "healthy")
          root.dragonflyConnected = Boolean(payload.health && (payload.health.valkey || payload.health.dragonfly))

          if (payload.config) {
            if (payload.config.tls_intercept !== undefined) {
              root.tlsIntercept = (payload.config.tls_intercept === "true" || payload.config.tls_intercept === true)
            }
            if (payload.config.prevention_mode !== undefined) {
              root.preventionMode = (payload.config.prevention_mode === "true" || payload.config.prevention_mode === true)
            }
          }

          if (payload.stats) {
            var s = payload.stats
            var now = Date.now()
            if (root._lastSampleTime > 0 && now > root._lastSampleTime) {
              var dt = (now - root._lastSampleTime) / 1000.0
              var dReq = (s.total_requests || 0) - root._lastTotalRequests
              if (dReq >= 0 && dt > 0) {
                var rps = dReq / dt
                root.requestsPerSec = rps
                if (rps > root.peakRequestsPerSec) root.peakRequestsPerSec = rps
              }
            }
            root._lastTotalRequests = s.total_requests || 0
            root._lastSampleTime = now

            root.totalRequests = s.total_requests || 0
            root.blockedRequests = s.blocked_requests || 0
            root.activeConnections = s.active_connections || 0
            root.tlsIntercepted = s.tls_intercepted || 0
            root.threatsBlocked = s.threat_blocks || 0
            root.threatEvals = s.threat_tier0_evals || 0
            root.threatEscalations = (s.threat_tier1_escalations || 0) + (s.threat_tier2_escalations || 0) + (s.threat_tier3_escalations || 0)
            if (payload.cache) {
              root.cacheHits = Number(payload.cache.hits || 0)
              root.cacheMisses = Number(payload.cache.misses || 0)
            } else {
              root.cacheHits = s.cache_hits || 0
              root.cacheMisses = s.cache_misses || 0
            }
          }

          if (payload.blocked && payload.blocked.entries) {
            var seen = {}
            var deduped = []
            for (var bi = 0; bi < payload.blocked.entries.length; bi++) {
              var be = payload.blocked.entries[bi]
              var k = (be.host || "") + ":" + (be.port || "")
              if (!seen[k]) {
                seen[k] = true
                deduped.push(be)
              }
              if (deduped.length >= 4) break
            }
            root.recentBlocked = deduped
          } else {
            root.recentBlocked = []
          }

          if (payload.mutes) {
            root.mutedDomains = payload.mutes
          } else {
            root.mutedDomains = []
          }
        } catch (e) {
          root.running = false
        }
      }
    }
    onExited: function(exitCode) {
      if (exitCode !== 0) root.running = false
    }
  }

  Process {
    id: muteDomainProc
    running: false
    command: []
    onExited: function() { root.refresh() }
  }

  Process {
    id: createPolicyProc
    running: false
    command: []
    onExited: function() { root.refresh() }
  }

  Process {
    id: putConfigProc
    running: false
    command: []
    onExited: function() { root.refresh() }
  }

  Process {
    id: serviceToggleProc
    running: false
    command: []
    onExited: function() { root.refresh() }
  }

  Process {
    id: serviceRestartProc
    running: false
    command: ["systemctl", "--user", "restart", "conduit.target"]
    onExited: function() { root.refresh() }
  }

  // --- Bar Representation ---

  WidgetButton {
    id: button
    anchors.fill: parent
    visible: !root.iconOnly
    bar: root.bar
    text: root.barLabel()
    fontSize: Style.font.caption
    horizontalMargin: 6
    active: root.running
    activeColor: root.threatsBlocked > 0 ? root.urgent : root.accent
    tooltipText: root.tooltipText()
    onPressed: function(buttonCode) { root.barPressed(buttonCode) }
  }

  BarIconButton {
    id: iconButton
    anchors.fill: parent
    visible: root.iconOnly
    bar: root.bar
    active: root.running
    activeColor: root.threatsBlocked > 0 ? root.urgent : root.accent
    tooltipText: root.tooltipText()
    onPressed: function(buttonCode) { root.barPressed(buttonCode) }

    iconComponent: Component {
      Item {
        anchors.fill: parent
        Image {
          anchors.centerIn: parent
          width: Math.round(parent.width * 0.92)
          height: Math.round(parent.height * 0.92)
          source: "./assets/svg/conduit-app-icon.svg"
          fillMode: Image.PreserveAspectFit
          smooth: true
          mipmap: true
          opacity: root.running ? 1.0 : 0.35
        }
      }
    }
  }

  // --- Flyout Popup Panel ---

  KeyboardPanel {
    id: panel
    anchorItem: root.iconOnly ? iconButton : button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: keyCatcher
    contentWidth: panel.fittedContentWidth(Style.space(380))
    contentHeight: panel.fittedContentHeight(panelColumn.implicitHeight, Style.space(640))

    PanelKeyCatcher {
      id: keyCatcher
      anchors.fill: parent
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }
      onTextKey: function(text) {
        if (text === "r" || text === "R") root.refresh()
        else if (text === "p" || text === "P" || text === "d" || text === "D") root.openPortal()
        else if (text === "t" || text === "T") root.toggleProxyService()
      }

      ScrollView {
        id: scrollArea
        anchors.fill: parent
        clip: true
        ScrollBar.horizontal.policy: ScrollBar.AlwaysOff
        ScrollBar.vertical.policy: panelColumn.implicitHeight > height ? ScrollBar.AsNeeded : ScrollBar.AlwaysOff

        Column {
          id: panelColumn
          width: scrollArea.availableWidth
          spacing: Style.space(10)

          // ---------- Hero: Gateway Identity & Status ----------
          PanelHero {
            width: parent.width
            title: "Conduit Gateway"
            meta: root.running
                  ? (root.preventionMode ? "ACTIVE · PREVENTION MODE" : "ACTIVE · MONITORING MODE")
                  : "INACTIVE · GATEWAY STOPPED"
            detail: root.running ? Model.formatRate(root.requestsPerSec) : "OFF"
            foreground: root.foreground
            fontFamily: root.fontFamily

            iconComponent: Component {
              Image {
                width: Style.space(36)
                height: Style.space(36)
                source: "./assets/svg/conduit-app-icon.svg"
                fillMode: Image.PreserveAspectFit
                smooth: true
                mipmap: true
                opacity: root.running ? 1.0 : 0.4
              }
            }

            trailingControl: Component {
              Row {
                spacing: Style.space(6)

                PanelActionButton {
                  iconText: "󰑐"
                  tooltipText: "Refresh (R)"
                  foreground: root.foreground
                  hoverColor: root.accent
                  fontFamily: root.fontFamily
                  onClicked: root.refresh()
                }

                PanelActionButton {
                  iconText: "󰖟"
                  tooltipText: "Open Portal (P/D)"
                  foreground: root.foreground
                  hoverColor: root.accent
                  fontFamily: root.fontFamily
                  onClicked: root.openPortal()
                }
              }
            }
          }

          // ---------- Section: Recent Blocks (prominent at top) ----------
          PanelSeparator {
            foreground: root.foreground
            visible: root.recentBlocked && root.recentBlocked.length > 0
          }

          PanelSectionHeader {
            text: "RECENT BLOCKED TRAFFIC"
            foreground: root.foreground
            fontFamily: root.fontFamily
            visible: root.recentBlocked && root.recentBlocked.length > 0
          }

          Column {
            width: parent.width
            spacing: Style.space(6)
            visible: root.recentBlocked && root.recentBlocked.length > 0

            Repeater {
              model: root.recentBlocked
              delegate: BorderSurface {
                required property var modelData
                width: parent.width
                implicitHeight: Math.max(Style.space(42), itemLayout.implicitHeight + Style.space(10))
                radius: Style.cornerRadius
                color: root.cardFill
                borderSpec: Border.controlSpec("normal", root.cardBorder, root.urgent)

                RowLayout {
                  id: itemLayout
                  anchors.left: parent.left
                  anchors.right: parent.right
                  anchors.verticalCenter: parent.verticalCenter
                  anchors.leftMargin: Style.space(10)
                  anchors.rightMargin: Style.space(10)
                  spacing: Style.space(8)

                  Text {
                    text: "󰅙"
                    color: root.urgent
                    font.family: root.fontFamily
                    font.pixelSize: Style.font.body
                    Layout.alignment: Qt.AlignVCenter
                  }

                  ColumnLayout {
                    Layout.fillWidth: true
                    Layout.alignment: Qt.AlignVCenter
                    spacing: Style.space(2)

                    Text {
                      Layout.fillWidth: true
                      text: (modelData.host || "Unknown") + (modelData.port ? (":" + modelData.port) : "")
                      color: root.foreground
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.bodySmall
                      font.bold: true
                      elide: Text.ElideRight
                    }

                    Text {
                      Layout.fillWidth: true
                      text: (modelData.rule_name || modelData.block_reason || "Blocked") + (modelData.category ? (" · " + modelData.category) : "")
                      color: root.muted
                      font.family: root.fontFamily
                      font.pixelSize: Style.font.caption
                      elide: Text.ElideRight
                    }
                  }

                  Row {
                    Layout.alignment: Qt.AlignVCenter
                    spacing: Style.space(4)

                    Button {
                      property bool isMuted: root.isTargetMuted(modelData.host)
                      text: isMuted ? "Muted" : "Mute"
                      iconText: isMuted ? "󰂛" : "󰂚"
                      bordered: true
                      foreground: isMuted ? root.accent : root.muted
                      accent: root.accent
                      fontFamily: root.fontFamily
                      fontSize: Style.font.caption
                      iconSize: Style.font.caption
                      horizontalPadding: Style.space(6)
                      verticalPadding: Style.space(4)
                      onClicked: {
                        if (isMuted) {
                          root.unmuteTarget(modelData.host)
                        } else {
                          root.muteTarget(modelData.host)
                        }
                      }
                    }

                    Button {
                      text: "Allow"
                      iconText: "󰄬"
                      bordered: true
                      foreground: root.foreground
                      accent: root.accent
                      fontFamily: root.fontFamily
                      fontSize: Style.font.caption
                      iconSize: Style.font.caption
                      horizontalPadding: Style.space(8)
                      verticalPadding: Style.space(4)
                      onClicked: root.allowTarget(modelData.host, modelData.port)
                    }
                  }
                }
              }
            }
          }

          PanelSeparator { foreground: root.foreground }

          // ---------- Section: Controls & Toggles ----------
          PanelSectionHeader {
            text: "GATEWAY CONTROLS"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          Toggle {
            width: parent.width
            label: "Proxy Gateway"
            description: root.running
                         ? "Pingora 0.9.0 PQ TLS proxy active on :8888"
                         : "Service stopped (click to start)"
            checked: root.running
            foreground: root.foreground
            accent: root.accent
            fontFamily: root.fontFamily
            onClicked: root.toggleProxyService()
          }

          Toggle {
            width: parent.width
            label: "Prevention Mode"
            description: root.preventionMode
                         ? "Enforcing: blocks malware, high-risk domains & leaks"
                         : "Audit: observes and logs threats without blocking"
            checked: root.preventionMode
            foreground: root.foreground
            accent: root.accent
            fontFamily: root.fontFamily
            onClicked: root.togglePreventionMode()
          }

          Toggle {
            width: parent.width
            label: "TLS Inspection (MITM)"
            description: root.tlsIntercept
                         ? "Decrypts & inspects HTTPS with local Root CA"
                         : "Passthrough TCP tunneling without TLS decryption"
            checked: root.tlsIntercept
            foreground: root.foreground
            accent: root.accent
            fontFamily: root.fontFamily
            onClicked: root.toggleTlsIntercept()
          }

          PanelSeparator { foreground: root.foreground }

          // ---------- Section: Throughput & Telemetry ----------
          PanelSectionHeader {
            text: "THROUGHPUT & TELEMETRY"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          // Telemetry Grid
          Grid {
            width: parent.width
            columns: 2
            spacing: Style.space(8)

            MetricCard {
              cardWidth: (parent.width - Style.space(8)) / 2
              glyph: "󰓅"
              title: "THROUGHPUT"
              value: Model.formatRate(root.requestsPerSec)
              subValue: "Peak " + Model.formatRate(root.peakRequestsPerSec)
              accentColor: root.accent
            }

            MetricCard {
              cardWidth: (parent.width - Style.space(8)) / 2
              glyph: "󱢓"
              title: "ACTIVE SOCKETS"
              value: root.activeConnections + " conns"
              subValue: "Pingora pool"
              accentColor: root.accent
            }

            MetricCard {
              cardWidth: (parent.width - Style.space(8)) / 2
              glyph: "󰌾"
              title: "TLS INTERCEPTED"
              value: Model.formatRatio(root.tlsIntercepted, root.totalRequests)
              subValue: Model.formatNumber(root.tlsIntercepted) + " / " + Model.formatNumber(root.totalRequests)
              accentColor: root.accent
            }

            MetricCard {
              cardWidth: (parent.width - Style.space(8)) / 2
              glyph: "󰒃"
              title: "THREAT EVALS"
              value: Model.formatNumber(root.threatEvals)
              subValue: root.threatEscalations + " esc · " + root.threatsBlocked + " blocked"
              accentColor: root.threatsBlocked > 0 ? root.urgent : root.foreground
            }
          }

          // Cache & Engine efficiency bar
          BorderSurface {
            width: parent.width
            implicitHeight: cacheRow.implicitHeight + Style.space(16)
            radius: Style.cornerRadius
            color: root.cardFill
            borderSpec: Border.controlSpec("normal", root.cardBorder, root.accent)

            Row {
              id: cacheRow
              anchors.centerIn: parent
              spacing: Style.space(12)

              Text {
                text: "󰆼 HTTP Cache: " + Model.formatNumber(root.cacheHits) + " hits / " + Model.formatNumber(root.cacheMisses) + " misses"
                color: root.muted
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Text {
                text: "·"
                color: root.dim
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }

              Text {
                text: "Datastore: " + (root.dragonflyConnected ? "Connected" : "Disconnected")
                color: root.dragonflyConnected ? root.muted : root.urgent
                font.family: root.fontFamily
                font.pixelSize: Style.font.caption
              }
            }
          }

          PanelSeparator { foreground: root.foreground }

          // ---------- Section: Quick Actions ----------
          PanelSectionHeader {
            text: "QUICK ACTIONS"
            foreground: root.foreground
            fontFamily: root.fontFamily
          }

          Row {
            width: parent.width
            spacing: Style.space(8)

            Button {
              width: (parent.width - Style.space(16)) / 3
              text: "Dashboard"
              iconText: "󰖟"
              bordered: true
              foreground: root.foreground
              accent: root.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              iconSize: Style.font.icon
              onClicked: root.openPortal()
            }

            Button {
              width: (parent.width - Style.space(16)) / 3
              text: "Restart"
              iconText: "󰑐"
              bordered: true
              foreground: root.foreground
              accent: root.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              iconSize: Style.font.icon
              onClicked: root.restartGateway()
            }

            Button {
              width: (parent.width - Style.space(16)) / 3
              text: root._copyFeedback !== "" ? root._copyFeedback : "CA Cert"
              iconText: "󰄬"
              bordered: true
              foreground: root.foreground
              accent: root.accent
              fontFamily: root.fontFamily
              fontSize: Style.font.bodySmall
              iconSize: Style.font.icon
              onClicked: root.copyCaCertPath()
            }
          }
        }
      }
    }
  }

  // Component for styled metric summary cards
  component MetricCard: BorderSurface {
    id: card
    property real cardWidth: 100
    property string glyph: ""
    property string title: ""
    property string value: ""
    property string subValue: ""
    property color accentColor: root.foreground

    width: cardWidth
    implicitHeight: cardContent.implicitHeight + Style.space(16)
    radius: Style.cornerRadius
    color: root.cardFill
    borderSpec: Border.controlSpec("normal", root.cardBorder, root.accent)

    Column {
      id: cardContent
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.leftMargin: Style.space(12)
      anchors.rightMargin: Style.space(12)
      anchors.verticalCenter: parent.verticalCenter
      spacing: Style.space(3)

      Row {
        spacing: Style.space(6)
        Text {
          text: card.glyph
          color: card.accentColor
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
        }
        Text {
          text: card.title
          color: root.dim
          font.family: root.fontFamily
          font.pixelSize: Style.font.caption
          font.bold: true
          font.letterSpacing: 1.1
        }
      }

      Text {
        text: card.value
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.title
        font.bold: true
      }

      Text {
        text: card.subValue
        color: root.muted
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
        elide: Text.ElideRight
        width: parent.width
      }
    }
  }
}
