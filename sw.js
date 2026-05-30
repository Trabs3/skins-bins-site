/**
 * skins-bins.xyz — Service Worker Persistence Trap v1
 * 
 * Purpose: Test if the vendor's browser maintains state between visits.
 * 
 * How it works:
 * 1. On first visit, this SW is registered and stores a unique token in Cache API
 * 2. On subsequent visits, the SW checks if the token exists
 * 3. If token is missing = new browser instance (bot behavior)
 * 4. If token exists = same browser (real user or persistent bot)
 * 
 * Additionally:
 * - Intercepts all fetch requests to log what the bot loads
 * - Tracks install/activate lifecycle events
 * - Reports back to our worker via fetch
 */

const WORKER = "https://skins.companybbig.workers.dev";
const SITE_ID = "skins-bins";
const TEST_RUN_ID = "skins_bins_test_jun";
const CACHE_NAME = "sb-persistence-v1";
const TOKEN_KEY = "/sb-token.json";

// Generate a unique token for this SW installation
function generateToken() {
  return Date.now().toString(36) + "-" + Math.random().toString(36).slice(2, 12);
}

// Report SW events to our logging worker
function report(eventType, data) {
  const payload = {
    log_type: "sw_event",
    site_id: SITE_ID,
    test_run_id: TEST_RUN_ID,
    ts: new Date().toISOString(),
    sw_event: eventType,
    ...data,
  };
  
  // Use fetch directly (sendBeacon not available in SW)
  fetch(WORKER, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  }).catch(function() {});
}

// ── INSTALL EVENT ──────────────────────────────────────────────────────────
// Fires when SW is first installed (first visit ever, or after SW update)
self.addEventListener("install", function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      const token = generateToken();
      const tokenData = {
        token: token,
        created_at: new Date().toISOString(),
        install_count: 1,
      };
      
      // Store token in cache
      const response = new Response(JSON.stringify(tokenData), {
        headers: { "Content-Type": "application/json" }
      });
      
      report("install", {
        token: token,
        is_fresh_install: true,
      });
      
      return cache.put(TOKEN_KEY, response);
    })
  );
  
  // Skip waiting — activate immediately
  self.skipWaiting();
});

// ── ACTIVATE EVENT ─────────────────────────────────────────────────────────
// Fires when SW becomes active (after install, or on page revisit)
self.addEventListener("activate", function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.match(TOKEN_KEY).then(function(response) {
        if (response) {
          return response.json().then(function(tokenData) {
            report("activate", {
              token: tokenData.token,
              token_created_at: tokenData.created_at,
              is_returning: true,
              install_count: tokenData.install_count,
            });
          });
        } else {
          report("activate", {
            token: null,
            is_returning: false,
            note: "no_token_found_on_activate",
          });
        }
      });
    })
  );
  
  // Claim all clients immediately
  self.clients.claim();
});

// ── FETCH EVENT ────────────────────────────────────────────────────────────
// Intercept all requests from the page. Log them but don't modify responses.
// This lets us see exactly what resources the bot requests.
self.addEventListener("fetch", function(event) {
  const url = new URL(event.request.url);
  
  // Don't intercept requests to our own worker (avoid infinite loop)
  if (url.hostname === "skins.companybbig.workers.dev") {
    return;
  }
  
  // For trap URLs — log the hit and return a fake page
  if (url.pathname.startsWith("/trap/")) {
    event.respondWith(
      (async function() {
        report("trap_hit", {
          trap_path: url.pathname,
          referrer: event.request.referrer || null,
          mode: event.request.mode,
          destination: event.request.destination,
          user_agent: event.request.headers.get("user-agent"),
        });
        
        // Return a minimal HTML response so the bot thinks it found something
        return new Response(
          "<!DOCTYPE html><html><head><title>Page</title></head><body><p>Content</p></body></html>",
          { headers: { "Content-Type": "text/html" } }
        );
      })()
    );
    return;
  }
  
  // For all other requests — pass through but log navigation requests
  if (event.request.mode === "navigate") {
    // Check persistence token on each navigation
    event.respondWith(
      caches.open(CACHE_NAME).then(function(cache) {
        return cache.match(TOKEN_KEY).then(function(tokenResponse) {
          let tokenInfo = { has_token: false, token: null };
          
          const checkToken = tokenResponse 
            ? tokenResponse.clone().json().then(function(data) {
                tokenInfo = { has_token: true, token: data.token, created_at: data.created_at };
              })
            : Promise.resolve();
          
          return checkToken.then(function() {
            report("navigation", {
              path: url.pathname,
              token_status: tokenInfo,
              referrer: event.request.referrer || null,
            });
            
            // Pass through to network
            return fetch(event.request);
          });
        });
      }).catch(function() {
        return fetch(event.request);
      })
    );
    return;
  }
  
  // All other requests — pass through without modification
});

// ── MESSAGE EVENT ──────────────────────────────────────────────────────────
// Handle messages from the page (token check requests)
self.addEventListener("message", function(event) {
  if (event.data && event.data.type === "check_token") {
    caches.open(CACHE_NAME).then(function(cache) {
      return cache.match(TOKEN_KEY).then(function(response) {
        if (response) {
          return response.json().then(function(data) {
            event.source.postMessage({
              type: "token_status",
              has_token: true,
              token: data.token,
              created_at: data.created_at,
              install_count: data.install_count,
            });
          });
        } else {
          event.source.postMessage({
            type: "token_status",
            has_token: false,
          });
        }
      });
    });
  }
  
  if (event.data && event.data.type === "ping") {
    event.source.postMessage({ type: "pong", ts: Date.now() });
  }
});
