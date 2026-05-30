// Netlify Edge Function — request-logger.js v4
// Intercepts ALL requests to skins-bins.xyz and logs them to Cloudflare Worker → R2
// v4: Added full header order fingerprint, pseudo-header analysis, connection coalescing detection

const WORKER_URL = "https://skins.companybbig.workers.dev";

// Cookie name for tracking repeat visits
const COOKIE_NAME = "_sb_sid";
// Persistent visitor ID cookie (survives across sessions)
const PERSISTENT_COOKIE = "hp_vid";

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

// --- REFERER PARSER ---
const SEARCH_DOMAINS = ["google.", "bing.com", "yahoo.com", "duckduckgo.com", "yandex.", "baidu.com", "ecosia.org", "ask.com"];
const SOCIAL_DOMAINS = ["facebook.com", "fb.com", "instagram.com", "twitter.com", "x.com", "linkedin.com", "reddit.com", "tiktok.com", "youtube.com", "pinterest.com", "t.co"];

function parseReferer(referer) {
  if (!referer) return { referer_raw: null, referer_domain: null, referer_path: null, is_search_referrer: false, is_social_referrer: false, is_empty_referrer: true };
  try {
    const u = new URL(referer);
    const domain = u.hostname.replace(/^www\./, "");
    const isSearch = SEARCH_DOMAINS.some(d => domain.includes(d));
    const isSocial = SOCIAL_DOMAINS.some(d => domain.includes(d));
    return { referer_raw: referer, referer_domain: domain, referer_path: u.pathname, is_search_referrer: isSearch, is_social_referrer: isSocial, is_empty_referrer: false };
  } catch {
    return { referer_raw: referer, referer_domain: null, referer_path: null, is_search_referrer: false, is_social_referrer: false, is_empty_referrer: false };
  }
}

// --- SOURCE CLASSIFICATION ---
function classifySource(referer, query) {
  const ref = parseReferer(referer);
  const params = new URLSearchParams(query || "");
  const utmSource = params.get("utm_source");
  const utmMedium = params.get("utm_medium");
  const gclid = params.get("gclid");
  const fbclid = params.get("fbclid");
  const msclkid = params.get("msclkid");

  let source_type = "direct";
  if (gclid || msclkid || utmMedium === "cpc" || utmMedium === "ppc") {
    source_type = "paid_search";
  } else if (fbclid || utmSource === "facebook" || utmSource === "instagram") {
    source_type = "paid_social";
  } else if (ref.is_search_referrer) {
    source_type = "organic_search";
  } else if (ref.is_social_referrer) {
    source_type = "social";
  } else if (ref.referer_domain && !ref.is_empty_referrer) {
    source_type = "referral";
  }

  return {
    source_type,
    referer_parsed: ref,
    utm: {
      source: utmSource,
      medium: utmMedium,
      campaign: params.get("utm_campaign"),
      term: params.get("utm_term"),
      content: params.get("utm_content"),
    },
    click_ids: {
      gclid: gclid || null,
      fbclid: fbclid || null,
      msclkid: msclkid || null,
    },
  };
}

// --- BROWSER-LIKE SCORE ---
function computeBrowserScore(headers, headerAnalysis) {
  let score = 0;
  const reasons = [];

  if (headerAnalysis.has_accept_language) { score += 15; reasons.push("+lang"); }
  if (headerAnalysis.has_accept_encoding) { score += 10; reasons.push("+enc"); }
  if (headerAnalysis.has_accept) { score += 10; reasons.push("+accept"); }
  if (headerAnalysis.sec_header_count >= 3) { score += 20; reasons.push("+sec-fetch"); }
  if (headers.get("sec-ch-ua")) { score += 15; reasons.push("+client-hints"); }
  if (headers.get("upgrade-insecure-requests")) { score += 10; reasons.push("+upgrade"); }
  if (headerAnalysis.has_priority) { score += 5; reasons.push("+priority"); }
  if (!headerAnalysis.encoding_before_accept) { score += 10; reasons.push("+order-ok"); }
  if (headerAnalysis.lang_in_last_3) { score += 5; reasons.push("+lang-pos"); }

  // Penalties
  if (headerAnalysis.header_count <= 3) { score -= 30; reasons.push("-few-headers"); }
  if (headerAnalysis.ua_before_sec_ch) { score -= 10; reasons.push("-ua-order"); }
  if (!headerAnalysis.has_accept) { score -= 20; reasons.push("-no-accept"); }

  return { browser_like_score: Math.max(0, Math.min(100, score)), score_reasons: reasons };
}

function generateSessionId() {
  return Date.now().toString(36) + Math.random().toString(36).slice(2, 10);
}

// Compute a simple hash of header order for quick comparison
function hashHeaderOrder(headers) {
  const order = Array.from(headers.keys()).join("|");
  let hash = 0;
  for (let i = 0; i < order.length; i++) {
    hash = ((hash << 5) - hash) + order.charCodeAt(i);
    hash |= 0;
  }
  return hash;
}

// Known browser header orders for comparison
// Chrome typically sends: host, connection, sec-ch-ua, sec-ch-ua-mobile, sec-ch-ua-platform,
// upgrade-insecure-requests, user-agent, accept, sec-fetch-site, sec-fetch-mode, sec-fetch-user,
// sec-fetch-dest, accept-encoding, accept-language, cookie
// curl sends: host, user-agent, accept
// req/v3 sends: accept-encoding, user-agent (or similar minimal set)
function analyzeHeaderOrder(headers) {
  const order = Array.from(headers.keys());
  
  // Check for browser-like header patterns
  const secHeaders = order.filter(h => h.startsWith("sec-"));
  const acceptIdx = order.indexOf("accept");
  const uaIdx = order.indexOf("user-agent");
  const hostIdx = order.indexOf("host");
  const encodingIdx = order.indexOf("accept-encoding");
  const langIdx = order.indexOf("accept-language");
  
  // In real Chrome: sec-ch-ua comes BEFORE user-agent
  // In spoofed requests: user-agent often comes first
  const secChUaIdx = order.indexOf("sec-ch-ua");
  const uaBeforeSecCh = uaIdx !== -1 && secChUaIdx !== -1 && uaIdx < secChUaIdx;
  
  // Real browsers: accept-encoding comes AFTER accept
  // curl/req: accept-encoding often comes before or without accept
  const encodingBeforeAccept = encodingIdx !== -1 && (acceptIdx === -1 || encodingIdx < acceptIdx);
  
  // Real Chrome: accept-language is one of the last headers
  // Bots often omit it entirely
  const langIsLast3 = langIdx !== -1 && langIdx >= order.length - 3;
  
  return {
    full_order: order,
    order_hash: hashHeaderOrder(headers),
    header_count: order.length,
    sec_headers: secHeaders,
    sec_header_count: secHeaders.length,
    ua_before_sec_ch: uaBeforeSecCh,
    encoding_before_accept: encodingBeforeAccept,
    lang_in_last_3: langIsLast3,
    has_accept: acceptIdx !== -1,
    has_accept_language: langIdx !== -1,
    has_accept_encoding: encodingIdx !== -1,
    // Specific patterns
    starts_with_host: order[0] === "host",
    // Connection header presence (HTTP/1.1 only, not in HTTP/2)
    has_connection_header: order.includes("connection"),
    // Priority header (Chrome 91+)
    has_priority: order.includes("priority"),
  };
}

export default async function handler(request, context) {
  const url = new URL(request.url);

  // Force redirect from any netlify.app domain to the canonical domain
  if (url.hostname.includes("netlify.app")) {
    const canonical = `https://skins-bins.xyz${url.pathname}${url.search}`;
    return new Response(null, {
      status: 301,
      headers: { "Location": canonical }
    });
  }

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

  // Persistent visitor ID
  const existingVid = cookies[PERSISTENT_COOKIE] || null;
  const isReturningVisitor = !!existingVid;
  const visitorId = existingVid || crypto.randomUUID();

  // Source classification
  const sourceData = classifySource(request.headers.get("referer"), url.search);

  // Browser-like score
  const headerAnalysis = analyzeHeaderOrder(request.headers);
  const browserScore = computeBrowserScore(request.headers, headerAnalysis);

  // Collect all headers into an object (preserving order via array)
  const headersObj = {};
  const headersArray = []; // Ordered array of [key, value] pairs
  for (const [k, v] of request.headers.entries()) {
    headersObj[k] = v;
    headersArray.push([k, v.length > 200 ? v.slice(0, 200) + "..." : v]);
  }

  // Extract TLS/connection info from Netlify headers
  const tlsVersion = request.headers.get("x-nf-connection-proto") || null;
  const httpVersion = request.headers.get("x-nf-request-id") ? "h2+" : null;

  // Full header order analysis (already computed above)

  // Detect HTTP/2 pseudo-headers ordering (via specific Netlify headers)
  const h2Settings = {
    priority: request.headers.get("priority") || null,
    has_sec_fetch: !!(
      request.headers.get("sec-fetch-site") ||
      request.headers.get("sec-fetch-mode") ||
      request.headers.get("sec-fetch-dest")
    ),
    has_sec_ch_ua: !!request.headers.get("sec-ch-ua"),
    has_upgrade_insecure: !!request.headers.get("upgrade-insecure-requests"),
  };

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
      has_session_cookie: isRepeatVisit,
      session_id: sessionId,
      has_persistent_cookie: isReturningVisitor,
      visitor_id: visitorId,
      is_returning: isReturningVisitor,
      supports_cookies: isRepeatVisit ? true : "unknown_first_visit",
      raw_cookies: cookieHeader ? Object.keys(cookies) : [],
    },

    // Source classification
    source: sourceData,

    // Browser-like score (0-100, higher = more browser-like)
    browser_score: browserScore,

    // TLS/HTTP fingerprint signals
    tls_http: {
      tls_version: tlsVersion,
      http_version: httpVersion,
      h2_settings: h2Settings,
      header_order: headerAnalysis.full_order,
      header_order_hash: headerAnalysis.order_hash,
      header_count: headerAnalysis.header_count,
    },

    // NEW: Header order analysis for bot detection
    header_fingerprint: {
      order_hash: headerAnalysis.order_hash,
      sec_headers: headerAnalysis.sec_headers,
      sec_header_count: headerAnalysis.sec_header_count,
      ua_before_sec_ch: headerAnalysis.ua_before_sec_ch,
      encoding_before_accept: headerAnalysis.encoding_before_accept,
      lang_in_last_3: headerAnalysis.lang_in_last_3,
      has_accept: headerAnalysis.has_accept,
      has_accept_language: headerAnalysis.has_accept_language,
      has_accept_encoding: headerAnalysis.has_accept_encoding,
      starts_with_host: headerAnalysis.starts_with_host,
      has_connection_header: headerAnalysis.has_connection_header,
      has_priority: headerAnalysis.has_priority,
    },

    // NEW: Full ordered headers array for deep analysis
    headers_ordered: headersArray,

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
      sec_ch_ua_full_version_list: request.headers.get("sec-ch-ua-full-version-list"),
      sec_ch_ua_arch: request.headers.get("sec-ch-ua-arch"),
      sec_ch_ua_bitness: request.headers.get("sec-ch-ua-bitness"),
      sec_ch_ua_model: request.headers.get("sec-ch-ua-model"),
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

  // Set cookies on the response
  const newHeaders = new Headers(response.headers);
  
  // Session cookie (24h)
  if (!isRepeatVisit) {
    newHeaders.append(
      "Set-Cookie",
      `${COOKIE_NAME}=${sessionId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=86400`
    );
  }
  
  // Persistent visitor ID cookie (365 days)
  if (!isReturningVisitor) {
    newHeaders.append(
      "Set-Cookie",
      `${PERSISTENT_COOKIE}=${visitorId}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`
    );
  }

  return new Response(response.body, {
    status: response.status,
    headers: newHeaders,
  });
}
