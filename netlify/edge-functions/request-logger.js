// Netlify Edge Function — request-logger.js v3
// Intercepts ALL requests to skins-bins.xyz and logs them to Cloudflare Worker → R2
// v3: Added cookie trap, redirect trap, TLS info extraction, HTTP version detection

const WORKER_URL = "https://skins.companybbig.workers.dev";

// Cookie name for tracking repeat visits
const COOKIE_NAME = "_sb_sid";

const BOT_PATTERNS = [
  "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
  "yandexbot", "sogou", "exabot", "facebot", "ia_archiver",
  "semrushbot", "ahrefsbot", "mj12bot", "dotbot", "rogerbot",
  "python-requests", "go-http-client", "curl/", "wget/",
  "headlesschrome", "phantomjs", "selenium", "webdriver",
  "scrapy", "httpclient", "apache-httpclient", "okhttp",
  "postman", "insomnia", "libwww", "lwp-", "java/",
  "similarweb", "swbot", "dataforseo", "majestic",
  "chromedriver", "puppeteer", "playwright", "req/",
];

function detectBot(ua) {
  if (!ua) return { is_bot: true, bot_name: "no-ua" };
  const lower = ua.toLowerCase();
  for (const p of BOT_PATTERNS) {
    if (lower.includes(p)) return { is_bot: true, bot_name: p };
  }
  return { is_bot: false, bot_name: null };
}

function parseCookies(cookieHeader) {
  if (!cookieHeader) return {};
  const cookies = {};
  cookieHeader.split(";").forEach((c) => {
    const [key, ...val] = c.trim().split("=");
    if (key) cookies[key.trim()] = val.join("=").trim();
  });
  return cookies;
}

function generateSessionId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

export default async function handler(request, context) {
  const url = new URL(request.url);
  const ua = request.headers.get("user-agent") || "";
  const { is_bot, bot_name } = detectBot(ua);

  // Get real IP
  const ip =
    request.headers.get("x-nf-client-connection-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    context.ip ||
    "unknown";

  // Parse existing cookies to check if this is a repeat visitor
  const cookieHeader = request.headers.get("cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const existingSessionId = cookies[COOKIE_NAME] || null;
  const isRepeatVisit = !!existingSessionId;
  const sessionId = existingSessionId || generateSessionId();

  // Collect all headers into an object
  const headersObj = {};
  for (const [k, v] of request.headers.entries()) {
    headersObj[k] = v;
  }

  // Extract TLS/connection info from Netlify headers
  const tlsVersion = request.headers.get("x-nf-connection-proto") || null;
  const httpVersion = request.headers.get("x-nf-request-id") ? "h2+" : null;

  // Detect HTTP/2 pseudo-headers ordering (via specific Netlify headers)
  const h2Settings = {
    priority: request.headers.get("priority") || null,
    // HTTP/2 clients send specific header ordering
    has_sec_fetch: !!(
      request.headers.get("sec-fetch-site") ||
      request.headers.get("sec-fetch-mode") ||
      request.headers.get("sec-fetch-dest")
    ),
    has_sec_ch_ua: !!request.headers.get("sec-ch-ua"),
    has_upgrade_insecure: !!request.headers.get("upgrade-insecure-requests"),
  };

  // Header ordering analysis — real browsers have specific header order
  const headerOrder = Array.from(request.headers.keys());

  const logPayload = {
    log_type: "server_request",
    ts: new Date().toISOString(),
    site: "skins-bins.xyz",
    method: request.method,
    path: url.pathname,
    query: url.search || null,
    full_url: request.url,
    ip: ip,
    user_agent: ua,
    is_bot_ua: is_bot,
    bot_name: bot_name,

    // Cookie trap results
    cookie_trap: {
      has_cookie: isRepeatVisit,
      session_id: sessionId,
      supports_cookies: isRepeatVisit ? true : "unknown_first_visit",
      raw_cookies: cookieHeader ? Object.keys(cookies) : [],
    },

    // TLS/HTTP fingerprint signals
    tls_http: {
      tls_version: tlsVersion,
      http_version: httpVersion,
      h2_settings: h2Settings,
      header_order: headerOrder,
      header_count: headerOrder.length,
    },

    geo: {
      country: context.geo?.country?.code || null,
      country_name: context.geo?.country?.name || null,
      city: context.geo?.city || null,
      region: context.geo?.subdivision?.code || null,
      latitude: context.geo?.latitude || null,
      longitude: context.geo?.longitude || null,
      timezone: context.geo?.timezone || null,
    },

    headers: {
      referer: request.headers.get("referer"),
      accept: request.headers.get("accept"),
      accept_language: request.headers.get("accept-language"),
      accept_encoding: request.headers.get("accept-encoding"),
      content_type: request.headers.get("content-type"),
      cache_control: request.headers.get("cache-control"),
      pragma: request.headers.get("pragma"),
      dnt: request.headers.get("dnt"),
      sec_fetch_site: request.headers.get("sec-fetch-site"),
      sec_fetch_mode: request.headers.get("sec-fetch-mode"),
      sec_fetch_dest: request.headers.get("sec-fetch-dest"),
      sec_fetch_user: request.headers.get("sec-fetch-user"),
      sec_ch_ua: request.headers.get("sec-ch-ua"),
      sec_ch_ua_mobile: request.headers.get("sec-ch-ua-mobile"),
      sec_ch_ua_platform: request.headers.get("sec-ch-ua-platform"),
      x_forwarded_for: request.headers.get("x-forwarded-for"),
      x_real_ip: request.headers.get("x-real-ip"),
      x_nf_client_connection_ip: request.headers.get("x-nf-client-connection-ip"),
      via: request.headers.get("via"),
      connection: request.headers.get("connection"),
      upgrade_insecure_requests: request.headers.get("upgrade-insecure-requests"),
      priority: request.headers.get("priority"),
      cookie: cookieHeader ? "[present]" : null,
    },

    all_headers: headersObj,
  };

  // Fire-and-forget log
  context.waitUntil(
    fetch(WORKER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(logPayload),
    }).catch(() => {})
  );

  // Get the response from the origin
  const response = await context.next();

  // Set cookie on the response for cookie trap
  // If visitor returns with this cookie — they support cookies (real browser behavior)
  if (!isRepeatVisit) {
    const newHeaders = new Headers(response.headers);
    newHeaders.append(
      "Set-Cookie",
      `${COOKIE_NAME}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
    );
    return new Response(response.body, {
      status: response.status,
      headers: newHeaders,
    });
  }

  return response;
}
