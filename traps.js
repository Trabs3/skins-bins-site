/**
 * skins-bins.xyz — Detection Traps v1
 * 
 * Trap 1: Timing trap — delayed fetch at 3s, 7s, 15s after load
 *         Real browsers stay on page; bots usually leave within 1-2s
 * 
 * Trap 2: Navigation trap — hidden links that only DOM parsers find
 *         Real users never click display:none links
 * 
 * Trap 3: WebSocket probe — open WS connection to test if bot supports it
 *         Most headless bots either don't support WS or close immediately
 */
(function() {
  "use strict";

  const WORKER = "https://skins.companybbig.workers.dev";
  const SITE_ID = "skins-bins";
  const TEST_RUN_ID = "skins_bins_test_jun";
  const PAGE_LOAD_TS = Date.now();

  function send(data) {
    const json = JSON.stringify(data);
    if (navigator.sendBeacon) {
      try {
        const blob = new Blob([json], { type: "application/json" });
        if (navigator.sendBeacon(WORKER, blob)) return;
      } catch(e) {}
    }
    fetch(WORKER, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: json,
      keepalive: true
    }).catch(function(){});
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TRAP 1: TIMING TRAP
  // Fire delayed requests at 3s, 7s, 15s. If bot leaves before — we won't
  // see these hits. The timing of each hit tells us how long the bot stays.
  // ═══════════════════════════════════════════════════════════════════════════
  
  function timingTrap() {
    const delays = [3000, 7000, 15000];
    
    delays.forEach(function(delay) {
      setTimeout(function() {
        // Only fire if page is still visible (real users might tab away)
        const isVisible = document.visibilityState === "visible";
        
        send({
          log_type: "timing_trap",
          site_id: SITE_ID,
          test_run_id: TEST_RUN_ID,
          ts: new Date().toISOString(),
          delay_ms: delay,
          actual_delay_ms: Date.now() - PAGE_LOAD_TS,
          page_visible: isVisible,
          page_url: window.location.href,
          path: window.location.pathname,
          user_agent: navigator.userAgent,
          // Check if any interaction happened by this point
          had_interaction: !!(
            window.__sb_had_mouse || 
            window.__sb_had_scroll || 
            window.__sb_had_click
          ),
        });
        
        // Also fire a pixel for redundancy (in case sendBeacon fails)
        var img = new Image();
        img.src = WORKER + "/pixel?site_id=" + SITE_ID + 
          "&trap=timing&delay=" + delay + 
          "&actual=" + (Date.now() - PAGE_LOAD_TS) +
          "&visible=" + isVisible +
          "&cb=" + Date.now();
      }, delay);
    });
    
    // Track basic interactions for timing trap context
    document.addEventListener("mousemove", function() { window.__sb_had_mouse = true; }, { once: true, passive: true });
    document.addEventListener("scroll", function() { window.__sb_had_scroll = true; }, { once: true, passive: true });
    document.addEventListener("click", function() { window.__sb_had_click = true; }, { once: true, passive: true });
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TRAP 2: NAVIGATION TRAP (HONEYPOT LINKS)
  // Hidden links that are invisible to real users but visible to DOM parsers.
  // If a bot follows these links — it's parsing the DOM, not rendering visually.
  // Multiple layers of hiding to test different bot sophistication levels.
  // ═══════════════════════════════════════════════════════════════════════════
  
  function navigationTrap() {
    // Create multiple hidden links with different hiding techniques
    const traps = [
      // 1. display:none — simplest, most bots skip this
      { id: "ht-display", style: "display:none", href: "/trap/display-none", text: "Special Offers" },
      // 2. visibility:hidden + zero size — slightly harder to detect
      { id: "ht-visibility", style: "visibility:hidden;width:0;height:0;overflow:hidden;position:absolute", href: "/trap/visibility-hidden", text: "Admin Panel" },
      // 3. Off-screen positioning — classic honeypot
      { id: "ht-offscreen", style: "position:absolute;left:-9999px;top:-9999px", href: "/trap/offscreen", text: "Login" },
      // 4. Same color as background (transparent) — visual honeypot
      { id: "ht-transparent", style: "color:transparent;font-size:0;line-height:0;position:absolute;top:0;left:0", href: "/trap/transparent", text: "Dashboard" },
      // 5. aria-hidden — accessibility-aware bots might skip, dumb ones won't
      { id: "ht-aria", style: "position:absolute;clip:rect(0,0,0,0);white-space:nowrap;border:0;padding:0;margin:-1px;overflow:hidden;width:1px;height:1px", href: "/trap/aria-hidden", text: "API Keys" },
    ];

    const container = document.createElement("div");
    container.setAttribute("aria-hidden", "true");
    container.setAttribute("data-noindex", "true");
    container.style.cssText = "position:absolute;top:0;left:0;pointer-events:none;";
    
    traps.forEach(function(trap) {
      const a = document.createElement("a");
      a.href = trap.href;
      a.id = trap.id;
      a.style.cssText = trap.style;
      a.textContent = trap.text;
      a.tabIndex = -1;
      a.setAttribute("aria-hidden", "true");
      container.appendChild(a);
    });
    
    document.body.appendChild(container);
    
    // Also inject a hidden link in the HTML that looks like a real nav item
    // This tests if the bot parses raw HTML vs rendered DOM
    const footer = document.querySelector("footer");
    if (footer) {
      const hiddenNav = document.createElement("a");
      hiddenNav.href = "/trap/footer-hidden";
      hiddenNav.style.cssText = "display:none";
      hiddenNav.textContent = "Site Map";
      footer.appendChild(hiddenNav);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // TRAP 3: WEBSOCKET PROBE
  // Open a WebSocket connection. Real browsers maintain it; bots often:
  // - Don't support WebSocket at all
  // - Close it immediately
  // - Never send the upgrade handshake
  // We log: connection success, time-to-open, messages received, close reason
  // ═══════════════════════════════════════════════════════════════════════════
  
  function websocketProbe() {
    // Use a simple echo WebSocket service or our own worker
    // We'll connect to our worker's WS endpoint
    const wsUrl = "wss://skins.companybbig.workers.dev/ws?site_id=" + SITE_ID + 
      "&test_run_id=" + TEST_RUN_ID + "&ts=" + Date.now();
    
    const wsData = {
      supported: "WebSocket" in window,
      attempted: false,
      connected: false,
      connect_time_ms: null,
      messages_received: 0,
      messages_sent: 0,
      close_code: null,
      close_reason: null,
      close_time_ms: null,
      error: null,
      protocol: null,
    };

    if (!wsData.supported) {
      send({
        log_type: "websocket_probe",
        site_id: SITE_ID,
        test_run_id: TEST_RUN_ID,
        ts: new Date().toISOString(),
        time_on_page_ms: Date.now() - PAGE_LOAD_TS,
        page_url: window.location.href,
        user_agent: navigator.userAgent,
        ws: wsData,
      });
      return;
    }

    wsData.attempted = true;
    const startTime = Date.now();

    try {
      const ws = new WebSocket(wsUrl);
      
      ws.onopen = function() {
        wsData.connected = true;
        wsData.connect_time_ms = Date.now() - startTime;
        wsData.protocol = ws.protocol || null;
        
        // Send a ping message
        ws.send(JSON.stringify({
          type: "ping",
          site_id: SITE_ID,
          ua: navigator.userAgent,
          ts: Date.now(),
        }));
        wsData.messages_sent++;
      };

      ws.onmessage = function(event) {
        wsData.messages_received++;
        // After receiving response, close gracefully
        if (wsData.messages_received >= 1) {
          setTimeout(function() {
            ws.close(1000, "probe_complete");
          }, 500);
        }
      };

      ws.onerror = function(event) {
        wsData.error = "ws_error";
      };

      ws.onclose = function(event) {
        wsData.close_code = event.code;
        wsData.close_reason = event.reason || null;
        wsData.close_time_ms = Date.now() - startTime;
        
        send({
          log_type: "websocket_probe",
          site_id: SITE_ID,
          test_run_id: TEST_RUN_ID,
          ts: new Date().toISOString(),
          time_on_page_ms: Date.now() - PAGE_LOAD_TS,
          page_url: window.location.href,
          user_agent: navigator.userAgent,
          ws: wsData,
        });
      };

      // Timeout — if WS doesn't connect in 5s, log and close
      setTimeout(function() {
        if (!wsData.connected) {
          wsData.error = "timeout_5s";
          try { ws.close(); } catch(e) {}
          send({
            log_type: "websocket_probe",
            site_id: SITE_ID,
            test_run_id: TEST_RUN_ID,
            ts: new Date().toISOString(),
            time_on_page_ms: Date.now() - PAGE_LOAD_TS,
            page_url: window.location.href,
            user_agent: navigator.userAgent,
            ws: wsData,
          });
        }
      }, 5000);

    } catch(e) {
      wsData.error = "exception: " + String(e.message || e);
      send({
        log_type: "websocket_probe",
        site_id: SITE_ID,
        test_run_id: TEST_RUN_ID,
        ts: new Date().toISOString(),
        time_on_page_ms: Date.now() - PAGE_LOAD_TS,
        page_url: window.location.href,
        user_agent: navigator.userAgent,
        ws: wsData,
      });
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // INIT — run all traps after DOM is ready
  // ═══════════════════════════════════════════════════════════════════════════
  
  function initTraps() {
    timingTrap();
    navigationTrap();
    // Delay WS probe slightly to not interfere with page load
    setTimeout(websocketProbe, 1500);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initTraps);
  } else {
    initTraps();
  }

})();
