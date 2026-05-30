/**
 * skins-bins.xyz — Maximum Surveillance Tracker v2
 * Goal: reverse-engineer SimilarWeb vendor traffic emulation
 * Layers: fingerprint, behavior, resource timing, network info,
 *         battery, localStorage memory, error honeypot, WebRTC leak,
 *         fetch/XHR interception, MutationObserver, performance observer
 */
(function () {
  "use strict";

  const WORKER = "https://skins.companybbig.workers.dev";
  const SITE_ID = "skins-bins";
  const TEST_RUN_ID = "skins_bins_test_jun";
  const SESSION_ID = Math.random().toString(36).slice(2) + Date.now().toString(36);
  const PAGE_LOAD_TS = Date.now();
  const LS_KEY = "_sb_visits";

  // ── INTERCEPT ALL OUTBOUND FETCH / XHR ────────────────────────────────────
  // Capture every external request the bot makes (e.g. SimilarWeb SDK pinging home)
  const outboundRequests = [];

  const _origFetch = window.fetch;
  window.fetch = function (input, init) {
    const url = (typeof input === "string" ? input : input.url) || "";
    if (!url.includes(WORKER)) {
      outboundRequests.push({ type: "fetch", url: url, ts: Date.now() - PAGE_LOAD_TS });
    }
    return _origFetch.apply(this, arguments);
  };

  const _origOpen = XMLHttpRequest.prototype.open;
  XMLHttpRequest.prototype.open = function (method, url) {
    if (url && !String(url).includes(WORKER)) {
      outboundRequests.push({ type: "xhr", method: method, url: String(url), ts: Date.now() - PAGE_LOAD_TS });
    }
    return _origOpen.apply(this, arguments);
  };

  // ── ERROR HONEYPOT ─────────────────────────────────────────────────────────
  // Different headless environments produce different error stacks
  const errors = [];
  window.onerror = function (msg, src, line, col, err) {
    errors.push({
      message: String(msg).slice(0, 200),
      source: String(src).slice(0, 100),
      line: line, col: col,
      stack: err ? String(err.stack).slice(0, 500) : null,
      ts: Date.now() - PAGE_LOAD_TS,
    });
    return false; // don't suppress
  };
  window.addEventListener("unhandledrejection", function (e) {
    errors.push({
      message: "unhandledrejection: " + String(e.reason).slice(0, 200),
      ts: Date.now() - PAGE_LOAD_TS,
    });
  });

  // ── LOCALSTORAGE MEMORY ────────────────────────────────────────────────────
  // Track repeat visits — if bot comes daily, we'll see visit history
  function getVisitMemory() {
    try {
      const raw = localStorage.getItem(LS_KEY);
      const history = raw ? JSON.parse(raw) : [];
      const visit = { ts: new Date().toISOString(), session: SESSION_ID };
      history.push(visit);
      if (history.length > 50) history.splice(0, history.length - 50);
      localStorage.setItem(LS_KEY, JSON.stringify(history));
      return {
        visit_count: history.length,
        first_visit: history[0]?.ts || null,
        previous_sessions: history.slice(-5).map(v => v.ts),
        is_returning: history.length > 1,
      };
    } catch (e) {
      return { error: "localstorage_blocked" };
    }
  }

  // ── BROWSER / ENVIRONMENT FINGERPRINT ─────────────────────────────────────
  function getBrowserFingerprint() {
    const nav = navigator;
    const scr = screen;
    const win = window;

    // Canvas fingerprint
    let canvasHash = null;
    try {
      const c = document.createElement("canvas");
      const ctx = c.getContext("2d");
      ctx.textBaseline = "top";
      ctx.font = "14px 'Arial'";
      ctx.fillStyle = "#f60";
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = "#069";
      ctx.fillText("SimilarWeb\ud83d\udd0d", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("SimilarWeb\ud83d\udd0d", 4, 17);
      canvasHash = c.toDataURL().slice(-50);
    } catch (e) { canvasHash = "canvas_blocked"; }

    // WebGL
    let webglVendor = null, webglRenderer = null, webglVersion = null;
    try {
      const gl = document.createElement("canvas").getContext("webgl") ||
                 document.createElement("canvas").getContext("experimental-webgl");
      if (gl) {
        const ext = gl.getExtension("WEBGL_debug_renderer_info");
        if (ext) {
          webglVendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
          webglRenderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
        }
        webglVersion = gl.getParameter(gl.VERSION);
      }
    } catch (e) {}

    // WebGL2
    let webgl2 = false;
    try { webgl2 = !!document.createElement("canvas").getContext("webgl2"); } catch(e) {}

    // Audio fingerprint
    let audioHash = null;
    try {
      const AudioCtx = win.AudioContext || win.webkitAudioContext;
      if (AudioCtx) {
        const ctx = new AudioCtx();
        const osc = ctx.createOscillator();
        const analyser = ctx.createAnalyser();
        const gain = ctx.createGain();
        gain.gain.value = 0;
        osc.connect(analyser);
        analyser.connect(gain);
        gain.connect(ctx.destination);
        osc.start(0);
        const buf = new Float32Array(analyser.frequencyBinCount);
        analyser.getFloatFrequencyData(buf);
        audioHash = buf.slice(0, 10).join(",");
        ctx.close();
      }
    } catch (e) { audioHash = "audio_blocked"; }

    // Fonts
    const testFonts = ["Arial","Helvetica","Times New Roman","Courier New","Georgia",
      "Verdana","Comic Sans MS","Impact","Trebuchet MS","Palatino Linotype",
      "Lucida Console","Tahoma","Segoe UI","Roboto","Open Sans","Lato","Montserrat"];
    const availableFonts = [];
    try {
      const span = document.createElement("span");
      span.style.cssText = "position:absolute;left:-9999px;font-size:72px;visibility:hidden;";
      span.innerHTML = "mmmmmmmmmmlli";
      document.body.appendChild(span);
      const baseW = {};
      ["monospace","serif","sans-serif"].forEach(f => { span.style.fontFamily = f; baseW[f] = span.offsetWidth; });
      testFonts.forEach(font => {
        let detected = false;
        ["monospace","serif","sans-serif"].forEach(base => {
          span.style.fontFamily = `'${font}',${base}`;
          if (span.offsetWidth !== baseW[base]) detected = true;
        });
        if (detected) availableFonts.push(font);
      });
      document.body.removeChild(span);
    } catch (e) {}

    // Plugins
    const plugins = [];
    try { for (let i = 0; i < nav.plugins.length; i++) plugins.push(nav.plugins[i].name); } catch(e) {}

    // Mime types
    const mimeTypes = [];
    try { for (let i = 0; i < nav.mimeTypes.length; i++) mimeTypes.push(nav.mimeTypes[i].type); } catch(e) {}

    // Connection
    const conn = nav.connection || nav.mozConnection || nav.webkitConnection;
    const connectionInfo = conn ? {
      effectiveType: conn.effectiveType,
      type: conn.type,
      downlink: conn.downlink,
      downlinkMax: conn.downlinkMax,
      rtt: conn.rtt,
      saveData: conn.saveData,
    } : null;

    // Timezone
    let timezone = null, tzLocale = null;
    try {
      const dtf = Intl.DateTimeFormat();
      timezone = dtf.resolvedOptions().timeZone;
      tzLocale = dtf.resolvedOptions().locale;
    } catch(e) {}

    // Headless signals
    const headlessSignals = {
      webdriver: !!nav.webdriver,
      no_plugins: nav.plugins.length === 0,
      no_mime_types: nav.mimeTypes.length === 0,
      phantom: !!win._phantom || !!win.callPhantom,
      selenium: !!(win.document.__selenium_unwrapped || win.document.__webdriver_evaluate || win.document.__driver_evaluate),
      nightmare: !!win.__nightmare,
      chrome_headless: nav.userAgent.includes("HeadlessChrome"),
      no_languages: !nav.languages || nav.languages.length === 0,
      single_language: nav.languages && nav.languages.length === 1,
      outer_width_zero: win.outerWidth === 0,
      missing_chrome: !win.chrome,
      missing_chrome_runtime: !(win.chrome && win.chrome.runtime),
      // Broken notification permission (headless Chrome returns denied without prompt)
      // filled async
      permissions_anomaly: false,
      // cdc_ properties left by ChromeDriver
      cdc_present: Object.keys(win).some(k => k.startsWith("cdc_")),
      // $cdc_ in document
      cdc_doc: !!(win.document && Object.keys(win.document).some(k => k.startsWith("$cdc_"))),
      // Electron
      is_electron: !!(win.process && win.process.versions && win.process.versions.electron),
      // Node.js in browser context
      has_node_process: typeof process !== "undefined" && !!process.versions,
    };

    if (navigator.permissions) {
      navigator.permissions.query({ name: "notifications" }).then(p => {
        headlessSignals.permissions_anomaly = p.state === "denied" && nav.userAgent.includes("Chrome");
      }).catch(() => {});
    }

    // CSS media queries
    const media = {};
    if (win.matchMedia) {
      media.prefers_dark = win.matchMedia("(prefers-color-scheme: dark)").matches;
      media.prefers_light = win.matchMedia("(prefers-color-scheme: light)").matches;
      media.prefers_reduced_motion = win.matchMedia("(prefers-reduced-motion: reduce)").matches;
      media.hover_none = win.matchMedia("(hover: none)").matches;
      media.pointer_coarse = win.matchMedia("(pointer: coarse)").matches;
      media.pointer_fine = win.matchMedia("(pointer: fine)").matches;
      media.any_hover = win.matchMedia("(any-hover: hover)").matches;
      media.forced_colors = win.matchMedia("(forced-colors: active)").matches;
      media.print = win.matchMedia("print").matches;
    }

    return {
      user_agent: nav.userAgent,
      app_version: nav.appVersion,
      platform: nav.platform,
      vendor: nav.vendor,
      product: nav.product,
      product_sub: nav.productSub,
      language: nav.language,
      languages: nav.languages ? Array.from(nav.languages) : [],
      cookie_enabled: nav.cookieEnabled,
      java_enabled: nav.javaEnabled ? nav.javaEnabled() : false,
      online: nav.onLine,
      hardware_concurrency: nav.hardwareConcurrency || null,
      device_memory: nav.deviceMemory || null,
      max_touch_points: nav.maxTouchPoints || 0,
      has_touch: "ontouchstart" in win || (nav.maxTouchPoints || 0) > 0,
      do_not_track: nav.doNotTrack || win.doNotTrack || nav.msDoNotTrack,
      // Screen
      screen_width: scr.width,
      screen_height: scr.height,
      screen_avail_width: scr.availWidth,
      screen_avail_height: scr.availHeight,
      screen_color_depth: scr.colorDepth,
      screen_pixel_depth: scr.pixelDepth,
      device_pixel_ratio: win.devicePixelRatio || null,
      // Viewport
      viewport_width: win.innerWidth,
      viewport_height: win.innerHeight,
      outer_width: win.outerWidth,
      outer_height: win.outerHeight,
      // Fingerprints
      canvas_hash: canvasHash,
      webgl_vendor: webglVendor,
      webgl_renderer: webglRenderer,
      webgl_version: webglVersion,
      webgl2_supported: webgl2,
      audio_hash: audioHash,
      // Fonts & plugins
      available_fonts: availableFonts,
      fonts_count: availableFonts.length,
      plugins: plugins,
      plugins_count: plugins.length,
      mime_types: mimeTypes,
      mime_types_count: mimeTypes.length,
      // Network
      connection: connectionInfo,
      // Timezone
      timezone: timezone,
      timezone_offset: new Date().getTimezoneOffset(),
      timezone_locale: tzLocale,
      // Storage
      has_localstorage: (function(){ try { localStorage.setItem("_t","1"); localStorage.removeItem("_t"); return true; } catch(e){ return false; } })(),
      has_sessionstorage: (function(){ try { sessionStorage.setItem("_t","1"); sessionStorage.removeItem("_t"); return true; } catch(e){ return false; } })(),
      has_indexeddb: !!win.indexedDB,
      has_serviceworker: "serviceWorker" in nav,
      has_webrtc: !!(win.RTCPeerConnection || win.mozRTCPeerConnection || win.webkitRTCPeerConnection),
      has_webassembly: typeof WebAssembly === "object",
      has_shared_array_buffer: typeof SharedArrayBuffer !== "undefined",
      has_atomics: typeof Atomics !== "undefined",
      has_bigint: typeof BigInt !== "undefined",
      // APIs presence (bots often missing these)
      has_payment_request: typeof PaymentRequest !== "undefined",
      has_credential_management: !!(nav.credentials),
      has_geolocation: !!nav.geolocation,
      has_bluetooth: !!(nav.bluetooth),
      has_usb: !!(nav.usb),
      has_serial: !!(nav.serial),
      has_hid: !!(nav.hid),
      has_presentation: !!(nav.presentation),
      has_wakeLock: !!(nav.wakeLock),
      // Media
      media_queries: media,
      // Headless
      headless_signals: headlessSignals,
      // Window properties count (headless has fewer)
      window_keys_count: Object.keys(win).length,
      document_keys_count: Object.keys(win.document).length,
    };
  }

  // ── RESOURCE TIMING ───────────────────────────────────────────────────────
  // What resources did the browser actually load? Bots often skip fonts/images
  function getResourceTiming() {
    try {
      const entries = performance.getEntriesByType("resource");
      return entries.map(e => ({
        name: e.name.replace(window.location.origin, ""),
        type: e.initiatorType,
        duration: Math.round(e.duration),
        size: e.transferSize || 0,
        cached: e.transferSize === 0 && e.decodedBodySize > 0,
      }));
    } catch(e) { return null; }
  }

  // ── PERFORMANCE TIMING ────────────────────────────────────────────────────
  function getPerformanceTiming() {
    try {
      const perf = performance.timing || {};
      const nav = performance.getEntriesByType("navigation")[0] || {};
      return {
        dns: (perf.domainLookupEnd - perf.domainLookupStart) || null,
        tcp: (perf.connectEnd - perf.connectStart) || null,
        ssl: (perf.connectEnd - perf.secureConnectionStart) || null,
        ttfb: (perf.responseStart - perf.navigationStart) || null,
        response: (perf.responseEnd - perf.responseStart) || null,
        dom_interactive: (perf.domInteractive - perf.navigationStart) || null,
        dom_content_loaded: (perf.domContentLoadedEventEnd - perf.navigationStart) || null,
        dom_complete: (perf.domComplete - perf.navigationStart) || null,
        load_event: (perf.loadEventEnd - perf.navigationStart) || null,
        nav_type: nav.type || (performance.navigation ? performance.navigation.type : null),
        redirect_count: nav.redirectCount || (performance.navigation ? performance.navigation.redirectCount : null),
        // Paint timings
        fp: null,
        fcp: null,
      };
    } catch(e) { return null; }
  }

  // ── PAINT TIMING ──────────────────────────────────────────────────────────
  function getPaintTiming() {
    try {
      const paints = {};
      performance.getEntriesByType("paint").forEach(e => { paints[e.name] = Math.round(e.startTime); });
      return paints;
    } catch(e) { return null; }
  }

  // ── BEHAVIORAL SIGNALS ────────────────────────────────────────────────────
  let firstInteraction = null;
  let mouseMovements = 0, mouseX = [], mouseY = [];
  let scrollEvents = 0, maxScrollDepth = 0;
  let clickEvents = 0, clickTargets = [];
  let keyEvents = 0;
  let focusLostCount = 0;
  let visibilityChanges = [];
  let selectionEvents = 0;
  let contextMenuEvents = 0;
  let copyEvents = 0;

  function trackBehavior() {
    document.addEventListener("mousemove", function(e) {
      mouseMovements++;
      if (mouseX.length < 20) { mouseX.push(e.clientX); mouseY.push(e.clientY); }
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    document.addEventListener("scroll", function() {
      scrollEvents++;
      const scrolled = window.scrollY || document.documentElement.scrollTop;
      const total = document.documentElement.scrollHeight - window.innerHeight;
      if (total > 0) {
        const depth = Math.round((scrolled / total) * 100);
        if (depth > maxScrollDepth) maxScrollDepth = depth;
      }
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    document.addEventListener("click", function(e) {
      clickEvents++;
      if (clickTargets.length < 10) clickTargets.push(e.target ? e.target.tagName : "unknown");
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    document.addEventListener("keydown", function() {
      keyEvents++;
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    document.addEventListener("selectionchange", function() { selectionEvents++; }, { passive: true });
    document.addEventListener("contextmenu", function() { contextMenuEvents++; }, { passive: true });
    document.addEventListener("copy", function() { copyEvents++; }, { passive: true });

    window.addEventListener("blur", function() { focusLostCount++; });
    window.addEventListener("focus", function() {});

    document.addEventListener("visibilitychange", function() {
      visibilityChanges.push({ state: document.visibilityState, ts: Date.now() - PAGE_LOAD_TS });
    });
  }

  // ── TRAFFIC SOURCE ────────────────────────────────────────────────────────
  function getTrafficSource() {
    const ref = document.referrer;
    const params = new URLSearchParams(window.location.search);
    return {
      referrer: ref || null,
      referrer_domain: ref ? (function(){ try { return new URL(ref).hostname; } catch(e){ return null; } })() : null,
      utm_source: params.get("utm_source"),
      utm_medium: params.get("utm_medium"),
      utm_campaign: params.get("utm_campaign"),
      utm_content: params.get("utm_content"),
      utm_term: params.get("utm_term"),
      gclid: params.get("gclid"),
      fbclid: params.get("fbclid"),
      page_url: window.location.href,
      page_path: window.location.pathname,
      page_hash: window.location.hash || null,
      page_title: document.title,
    };
  }

  // ── WEBRTC IP LEAK ────────────────────────────────────────────────────────
  function getWebRTCIPs(callback) {
    const ips = [];
    try {
      const pc = new (window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection)({
        iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
      });
      pc.createDataChannel("");
      pc.createOffer().then(offer => pc.setLocalDescription(offer));
      pc.onicecandidate = function(e) {
        if (!e || !e.candidate) { pc.close(); callback(ips); return; }
        const match = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
        if (match) match.forEach(ip => { if (!ips.includes(ip)) ips.push(ip); });
      };
      setTimeout(() => { try { pc.close(); } catch(e) {} callback(ips); }, 2500);
    } catch(e) { callback([]); }
  }

  // ── BATTERY API ───────────────────────────────────────────────────────────
  function getBattery(callback) {
    if (navigator.getBattery) {
      navigator.getBattery().then(b => {
        callback({ charging: b.charging, level: b.level, chargingTime: b.chargingTime, dischargingTime: b.dischargingTime });
      }).catch(() => callback(null));
    } else {
      callback(null);
    }
  }

  // ── SEND ──────────────────────────────────────────────────────────────────
  function send(logType, extra) {
    const payload = {
      log_type: logType,
      site_id: SITE_ID,
      test_run_id: TEST_RUN_ID,
      session_id: SESSION_ID,
      ts: new Date().toISOString(),
      time_on_page_ms: Date.now() - PAGE_LOAD_TS,
      fingerprint: getBrowserFingerprint(),
      behavior: {
        first_interaction_ms: firstInteraction,
        mouse_movements: mouseMovements,
        mouse_sample_x: mouseX,
        mouse_sample_y: mouseY,
        scroll_events: scrollEvents,
        click_events: clickEvents,
        click_targets: clickTargets,
        key_events: keyEvents,
        max_scroll_depth_pct: maxScrollDepth,
        focus_lost_count: focusLostCount,
        visibility_changes: visibilityChanges,
        selection_events: selectionEvents,
        context_menu_events: contextMenuEvents,
        copy_events: copyEvents,
      },
      performance: getPerformanceTiming(),
      paint: getPaintTiming(),
      resources: getResourceTiming(),
      traffic: getTrafficSource(),
      visit_memory: getVisitMemory(),
      outbound_requests: outboundRequests.slice(),
      errors: errors.slice(),
      ...extra,
    };

    const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
    if (navigator.sendBeacon) {
      navigator.sendBeacon(WORKER, blob);
    } else {
      fetch(WORKER, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload), keepalive: true }).catch(() => {});
    }
  }

  // ── INIT ──────────────────────────────────────────────────────────────────
  function init() {
    trackBehavior();

    window.addEventListener("load", function() {
      // Wait 1s for resources to settle, then fire with WebRTC + Battery
      setTimeout(function() {
        let rtcIPs = [];
        let battery = null;
        let done = 0;
        function maybeSend() {
          done++;
          if (done === 2) send("js_fingerprint", { webrtc_ips: rtcIPs, battery: battery });
        }
        getWebRTCIPs(function(ips) { rtcIPs = ips; maybeSend(); });
        getBattery(function(b) { battery = b; maybeSend(); });
      }, 1000);
    });

    // Heartbeat at 5s — captures early behavior
    setTimeout(function() {
      send("js_heartbeat_5s", { webrtc_ips: null, battery: null });
    }, 5000);

    // Heartbeat at 30s — captures deeper engagement
    setTimeout(function() {
      send("js_heartbeat_30s", { webrtc_ips: null, battery: null });
    }, 30000);

    // On unload — final snapshot
    window.addEventListener("beforeunload", function() {
      send("js_unload", { webrtc_ips: null, battery: null, final_time_on_page_ms: Date.now() - PAGE_LOAD_TS });
    });

    // Observe DOM mutations — detect if bot injects scripts/iframes
    try {
      const domChanges = [];
      const observer = new MutationObserver(function(mutations) {
        mutations.forEach(function(m) {
          m.addedNodes.forEach(function(node) {
            if (node.tagName === "SCRIPT" || node.tagName === "IFRAME" || node.tagName === "IMG") {
              domChanges.push({
                tag: node.tagName,
                src: node.src || node.href || null,
                ts: Date.now() - PAGE_LOAD_TS,
              });
            }
          });
        });
      });
      observer.observe(document.documentElement, { childList: true, subtree: true });
      // Send DOM changes at 10s
      setTimeout(function() {
        if (domChanges.length > 0) {
          send("js_dom_mutations", { dom_injections: domChanges, webrtc_ips: null, battery: null });
        }
      }, 10000);
    } catch(e) {}
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
