/**
 * skins-bins.xyz — Deep Fingerprint + Behavioral Tracker
 * Goal: reverse-engineer SimilarWeb vendor traffic emulation
 * Sends to Cloudflare Worker → R2
 */
(function () {
  const WORKER = "https://skins.companybbig.workers.dev";
  const SITE_ID = "skins-bins";
  const TEST_RUN_ID = "skins_bins_test_jun";
  const SESSION_ID = Math.random().toString(36).slice(2) + Date.now().toString(36);
  const PAGE_LOAD_TS = Date.now();

  // ── 1. BROWSER / ENVIRONMENT FINGERPRINT ──────────────────────────────────

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
      ctx.fillText("SimilarWeb🔍", 2, 15);
      ctx.fillStyle = "rgba(102,204,0,0.7)";
      ctx.fillText("SimilarWeb🔍", 4, 17);
      canvasHash = c.toDataURL().slice(-50); // last 50 chars as fingerprint
    } catch (e) {
      canvasHash = "canvas_blocked";
    }

    // WebGL fingerprint
    let webglVendor = null, webglRenderer = null;
    try {
      const gl = document.createElement("canvas").getContext("webgl") ||
                 document.createElement("canvas").getContext("experimental-webgl");
      if (gl) {
        const ext = gl.getExtension("WEBGL_debug_renderer_info");
        if (ext) {
          webglVendor = gl.getParameter(ext.UNMASKED_VENDOR_WEBGL);
          webglRenderer = gl.getParameter(ext.UNMASKED_RENDERER_WEBGL);
        }
      }
    } catch (e) {}

    // AudioContext fingerprint
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
    } catch (e) {
      audioHash = "audio_blocked";
    }

    // Fonts detection (quick list)
    const testFonts = ["Arial", "Helvetica", "Times New Roman", "Courier New",
      "Georgia", "Verdana", "Comic Sans MS", "Impact", "Trebuchet MS",
      "Palatino Linotype", "Lucida Console", "Tahoma"];
    const availableFonts = [];
    try {
      const span = document.createElement("span");
      span.style.cssText = "position:absolute;left:-9999px;font-size:72px;";
      span.innerHTML = "mmmmmmmmmmlli";
      document.body.appendChild(span);
      const baseW = {};
      ["monospace", "serif", "sans-serif"].forEach(f => {
        span.style.fontFamily = f;
        baseW[f] = span.offsetWidth;
      });
      testFonts.forEach(font => {
        let detected = false;
        ["monospace", "serif", "sans-serif"].forEach(base => {
          span.style.fontFamily = `'${font}',${base}`;
          if (span.offsetWidth !== baseW[base]) detected = true;
        });
        if (detected) availableFonts.push(font);
      });
      document.body.removeChild(span);
    } catch (e) {}

    // Plugins
    const plugins = [];
    try {
      for (let i = 0; i < nav.plugins.length; i++) {
        plugins.push(nav.plugins[i].name);
      }
    } catch (e) {}

    // Touch support
    const touchPoints = nav.maxTouchPoints || 0;
    const hasTouch = "ontouchstart" in win || touchPoints > 0;

    // Battery API
    let batteryInfo = null;
    if (nav.getBattery) {
      nav.getBattery().then(b => {
        batteryInfo = { charging: b.charging, level: b.level };
      }).catch(() => {});
    }

    // Connection info
    const conn = nav.connection || nav.mozConnection || nav.webkitConnection;
    const connectionInfo = conn ? {
      effectiveType: conn.effectiveType,
      downlink: conn.downlink,
      rtt: conn.rtt,
      saveData: conn.saveData,
    } : null;

    // Timezone
    let timezone = null;
    try { timezone = Intl.DateTimeFormat().resolvedOptions().timeZone; } catch (e) {}

    // Do Not Track
    const dnt = nav.doNotTrack || win.doNotTrack || nav.msDoNotTrack;

    // Headless / automation detection signals
    const headlessSignals = {
      // Puppeteer/Playwright leave navigator.webdriver = true
      webdriver: !!nav.webdriver,
      // Chrome headless has no plugins
      no_plugins: nav.plugins.length === 0,
      // PhantomJS
      phantom: !!win._phantom || !!win.callPhantom,
      // Selenium
      selenium: !!win.document.__selenium_unwrapped ||
                !!win.document.__webdriver_evaluate ||
                !!win.document.__driver_evaluate,
      // Nightmare.js
      nightmare: !!win.__nightmare,
      // Headless Chrome specific
      chrome_headless: nav.userAgent.includes("HeadlessChrome"),
      // No languages set (common in bots)
      no_languages: !nav.languages || nav.languages.length === 0,
      // Permissions API anomaly (headless Chrome returns "denied" for notifications without asking)
      permissions_anomaly: false, // filled async below
      // window.outerWidth = 0 in headless
      outer_width_zero: win.outerWidth === 0,
      // Missing chrome object in Chrome headless
      missing_chrome: !win.chrome,
      // Broken broken image size (headless specific)
      broken_image: false, // filled below
    };

    // Check permissions anomaly async
    if (navigator.permissions) {
      navigator.permissions.query({ name: "notifications" }).then(p => {
        headlessSignals.permissions_anomaly = (p.state === "denied") && nav.userAgent.includes("Chrome");
      }).catch(() => {});
    }

    return {
      // Screen
      screen_width: scr.width,
      screen_height: scr.height,
      screen_color_depth: scr.colorDepth,
      screen_pixel_depth: scr.pixelDepth,
      device_pixel_ratio: win.devicePixelRatio || null,
      // Viewport
      viewport_width: win.innerWidth,
      viewport_height: win.innerHeight,
      outer_width: win.outerWidth,
      outer_height: win.outerHeight,
      // Browser
      user_agent: nav.userAgent,
      language: nav.language,
      languages: nav.languages ? Array.from(nav.languages) : [],
      platform: nav.platform,
      vendor: nav.vendor,
      product: nav.product,
      cookie_enabled: nav.cookieEnabled,
      java_enabled: nav.javaEnabled ? nav.javaEnabled() : false,
      online: nav.onLine,
      hardware_concurrency: nav.hardwareConcurrency || null,
      device_memory: nav.deviceMemory || null,
      // Timezone
      timezone: timezone,
      timezone_offset: new Date().getTimezoneOffset(),
      // Touch
      touch_points: touchPoints,
      has_touch: hasTouch,
      // Fingerprints
      canvas_hash: canvasHash,
      webgl_vendor: webglVendor,
      webgl_renderer: webglRenderer,
      audio_hash: audioHash,
      // Fonts
      available_fonts: availableFonts,
      fonts_count: availableFonts.length,
      // Plugins
      plugins: plugins,
      plugins_count: plugins.length,
      // Connection
      connection: connectionInfo,
      // DNT
      do_not_track: dnt,
      // Headless signals
      headless_signals: headlessSignals,
      // Storage support
      has_localstorage: (function() { try { localStorage.setItem("_t","1"); localStorage.removeItem("_t"); return true; } catch(e) { return false; } })(),
      has_sessionstorage: (function() { try { sessionStorage.setItem("_t","1"); sessionStorage.removeItem("_t"); return true; } catch(e) { return false; } })(),
      has_indexeddb: !!win.indexedDB,
      has_serviceworker: "serviceWorker" in nav,
      has_webrtc: !!(win.RTCPeerConnection || win.mozRTCPeerConnection || win.webkitRTCPeerConnection),
      // CSS media
      prefers_dark: win.matchMedia ? win.matchMedia("(prefers-color-scheme: dark)").matches : null,
      prefers_reduced_motion: win.matchMedia ? win.matchMedia("(prefers-reduced-motion: reduce)").matches : null,
    };
  }

  // ── 2. BEHAVIORAL SIGNALS ─────────────────────────────────────────────────

  let firstInteraction = null;
  let mouseMovements = 0;
  let scrollEvents = 0;
  let clickEvents = 0;
  let keyEvents = 0;
  let maxScrollDepth = 0;
  let focusLostCount = 0;
  let timeOnPage = 0;

  function trackBehavior() {
    document.addEventListener("mousemove", function () {
      mouseMovements++;
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    document.addEventListener("scroll", function () {
      scrollEvents++;
      const scrolled = win.scrollY || document.documentElement.scrollTop;
      const total = document.documentElement.scrollHeight - win.innerHeight;
      if (total > 0) {
        const depth = Math.round((scrolled / total) * 100);
        if (depth > maxScrollDepth) maxScrollDepth = depth;
      }
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    document.addEventListener("click", function () {
      clickEvents++;
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    document.addEventListener("keydown", function () {
      keyEvents++;
      if (!firstInteraction) firstInteraction = Date.now() - PAGE_LOAD_TS;
    }, { passive: true });

    window.addEventListener("blur", function () {
      focusLostCount++;
    });
  }

  // ── 3. PERFORMANCE TIMING ─────────────────────────────────────────────────

  function getPerformanceTiming() {
    try {
      const perf = performance.timing || {};
      const nav = performance.getEntriesByType("navigation")[0] || {};
      return {
        dns: (perf.domainLookupEnd - perf.domainLookupStart) || null,
        tcp: (perf.connectEnd - perf.connectStart) || null,
        ttfb: (perf.responseStart - perf.navigationStart) || null,
        dom_interactive: (perf.domInteractive - perf.navigationStart) || null,
        dom_complete: (perf.domComplete - perf.navigationStart) || null,
        load_event: (perf.loadEventEnd - perf.navigationStart) || null,
        // Navigation type: 0=navigate, 1=reload, 2=back/forward
        nav_type: nav.type || (performance.navigation ? performance.navigation.type : null),
        redirect_count: nav.redirectCount || (performance.navigation ? performance.navigation.redirectCount : null),
      };
    } catch (e) {
      return null;
    }
  }

  // ── 4. REFERRER & UTM ─────────────────────────────────────────────────────

  function getTrafficSource() {
    const ref = document.referrer;
    const params = new URLSearchParams(window.location.search);
    return {
      referrer: ref || null,
      referrer_domain: ref ? (function() { try { return new URL(ref).hostname; } catch(e) { return null; } })() : null,
      utm_source: params.get("utm_source"),
      utm_medium: params.get("utm_medium"),
      utm_campaign: params.get("utm_campaign"),
      utm_content: params.get("utm_content"),
      utm_term: params.get("utm_term"),
      page_url: window.location.href,
      page_path: window.location.pathname,
      page_hash: window.location.hash || null,
    };
  }

  // ── 5. WEBRTC IP LEAK ─────────────────────────────────────────────────────

  function getWebRTCIPs(callback) {
    const ips = [];
    try {
      const pc = new (window.RTCPeerConnection || window.mozRTCPeerConnection || window.webkitRTCPeerConnection)({
        iceServers: [{ urls: "stun:stun.l.google.com:19302" }]
      });
      pc.createDataChannel("");
      pc.createOffer().then(offer => pc.setLocalDescription(offer));
      pc.onicecandidate = function (e) {
        if (!e || !e.candidate) {
          pc.close();
          callback(ips);
          return;
        }
        const match = e.candidate.candidate.match(/(\d+\.\d+\.\d+\.\d+)/g);
        if (match) match.forEach(ip => { if (!ips.includes(ip)) ips.push(ip); });
      };
      setTimeout(() => { try { pc.close(); } catch(e) {} callback(ips); }, 2000);
    } catch (e) {
      callback([]);
    }
  }

  // ── 6. SEND TO WORKER ─────────────────────────────────────────────────────

  function send(extraData) {
    const payload = {
      log_type: "js_fingerprint",
      site_id: SITE_ID,
      test_run_id: TEST_RUN_ID,
      session_id: SESSION_ID,
      ts: new Date().toISOString(),
      time_on_page_ms: Date.now() - PAGE_LOAD_TS,
      // Fingerprint
      fingerprint: getBrowserFingerprint(),
      // Behavior
      behavior: {
        first_interaction_ms: firstInteraction,
        mouse_movements: mouseMovements,
        scroll_events: scrollEvents,
        click_events: clickEvents,
        key_events: keyEvents,
        max_scroll_depth_pct: maxScrollDepth,
        focus_lost_count: focusLostCount,
      },
      // Performance
      performance: getPerformanceTiming(),
      // Traffic source
      traffic: getTrafficSource(),
      // Extra (WebRTC IPs etc)
      ...extraData,
    };

    // Use sendBeacon if available (works even on page unload)
    const blob = new Blob([JSON.stringify(payload)], { type: "application/json" });
    if (navigator.sendBeacon) {
      navigator.sendBeacon(WORKER, blob);
    } else {
      fetch(WORKER, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(payload),
        keepalive: true,
      }).catch(() => {});
    }
  }

  // ── 7. INIT ───────────────────────────────────────────────────────────────

  function init() {
    trackBehavior();

    // Send initial fingerprint after page load
    window.addEventListener("load", function () {
      setTimeout(function () {
        // Try to get WebRTC IPs first
        getWebRTCIPs(function (rtcIPs) {
          send({ webrtc_ips: rtcIPs });
        });
      }, 500);
    });

    // Send behavioral snapshot on page unload (captures time on page, scroll depth etc)
    window.addEventListener("beforeunload", function () {
      timeOnPage = Date.now() - PAGE_LOAD_TS;
      send({
        log_type: "js_unload",
        final_time_on_page_ms: timeOnPage,
        webrtc_ips: null,
      });
    });

    // Also send after 10s to capture early leavers with some behavior data
    setTimeout(function () {
      send({ log_type: "js_heartbeat_10s", webrtc_ips: null });
    }, 10000);
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }

})();
