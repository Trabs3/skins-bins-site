/**
 * Service Worker Registration + Persistence Check
 * Registers the SW and immediately checks if a persistence token exists.
 * If token exists = returning visitor (real browser or persistent bot).
 * If no token = fresh instance (typical bot behavior).
 */
(function() {
  "use strict";

  const WORKER = "https://skins.companybbig.workers.dev";
  const SITE_ID = "skins-bins";
  const TEST_RUN_ID = "skins_bins_test_jun";

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

  if ("serviceWorker" in navigator) {
    // Register the SW
    navigator.serviceWorker.register("/sw.js", { scope: "/" })
      .then(function(registration) {
        send({
          log_type: "sw_registration",
          site_id: SITE_ID,
          test_run_id: TEST_RUN_ID,
          ts: new Date().toISOString(),
          page_url: window.location.href,
          user_agent: navigator.userAgent,
          sw_state: registration.active ? "active" : 
                    registration.waiting ? "waiting" : 
                    registration.installing ? "installing" : "unknown",
          sw_scope: registration.scope,
          success: true,
        });

        // Wait for SW to be ready, then check token
        navigator.serviceWorker.ready.then(function(reg) {
          if (reg.active) {
            // Ask SW for token status
            const messageChannel = new MessageChannel();
            messageChannel.port1.onmessage = function(event) {
              if (event.data && event.data.type === "token_status") {
                send({
                  log_type: "sw_token_check",
                  site_id: SITE_ID,
                  test_run_id: TEST_RUN_ID,
                  ts: new Date().toISOString(),
                  page_url: window.location.href,
                  user_agent: navigator.userAgent,
                  has_token: event.data.has_token,
                  token: event.data.token || null,
                  token_created_at: event.data.created_at || null,
                  is_returning_visitor: event.data.has_token,
                });
              }
            };
            reg.active.postMessage({ type: "check_token" }, [messageChannel.port2]);
          }
        });
      })
      .catch(function(error) {
        send({
          log_type: "sw_registration",
          site_id: SITE_ID,
          test_run_id: TEST_RUN_ID,
          ts: new Date().toISOString(),
          page_url: window.location.href,
          user_agent: navigator.userAgent,
          success: false,
          error: String(error.message || error),
        });
      });
  } else {
    // SW not supported — log this (very suspicious for modern browsers)
    send({
      log_type: "sw_registration",
      site_id: SITE_ID,
      test_run_id: TEST_RUN_ID,
      ts: new Date().toISOString(),
      page_url: window.location.href,
      user_agent: navigator.userAgent,
      success: false,
      error: "serviceWorker_not_supported",
    });
  }
})();
