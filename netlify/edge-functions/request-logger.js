// Netlify Edge Function — request-logger.js
// Intercepts ALL requests to skins-bins.xyz and logs them to Cloudflare Worker → R2
// Runs on Deno/V8 at the edge — no cold start, fires before any HTML is served

const WORKER_URL = "https://skins.companybbig.workers.dev";

const BOT_PATTERNS = [
  "googlebot", "bingbot", "slurp", "duckduckbot", "baiduspider",
  "yandexbot", "sogou", "exabot", "facebot", "ia_archiver",
  "semrushbot", "ahrefsbot", "mj12bot", "dotbot", "rogerbot",
  "python-requests", "go-http-client", "curl/", "wget/",
  "headlesschrome", "phantomjs", "selenium", "webdriver",
  "scrapy", "httpclient", "apache-httpclient", "okhttp",
  "postman", "insomnia", "libwww", "lwp-", "java/",
  "similarweb", "swbot", "dataforseo", "majestic",
  "chromedriver", "puppeteer", "playwright",
];

function detectBot(ua) {
  if (!ua) return { is_bot: true, bot_name: "no-ua" };
  const lower = ua.toLowerCase();
  for (const p of BOT_PATTERNS) {
    if (lower.includes(p)) return { is_bot: true, bot_name: p };
  }
  return { is_bot: false, bot_name: null };
}

export default async function handler(request, context) {
  const url = new URL(request.url);
  const ua = request.headers.get("user-agent") || "";
  const { is_bot, bot_name } = detectBot(ua);

  // Get real IP — Netlify provides x-nf-client-connection-ip
  const ip =
    request.headers.get("x-nf-client-connection-ip") ||
    request.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ||
    context.ip ||
    "unknown";

  // Collect all headers into an object
  const headersObj = {};
  for (const [k, v] of request.headers.entries()) {
    headersObj[k] = v;
  }

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
      sec_ch_ua: request.headers.get("sec-ch-ua"),
      sec_ch_ua_mobile: request.headers.get("sec-ch-ua-mobile"),
      sec_ch_ua_platform: request.headers.get("sec-ch-ua-platform"),
      x_forwarded_for: request.headers.get("x-forwarded-for"),
      x_real_ip: request.headers.get("x-real-ip"),
      x_nf_client_connection_ip: request.headers.get("x-nf-client-connection-ip"),
      via: request.headers.get("via"),
      connection: request.headers.get("connection"),
      upgrade_insecure_requests: request.headers.get("upgrade-insecure-requests"),
      authorization: request.headers.get("authorization"),
      cookie: request.headers.get("cookie") ? "[present]" : null,
    },
    all_headers: headersObj,
  };

  // Fire-and-forget — don't await so we don't slow down the response
  context.waitUntil(
    fetch(WORKER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(logPayload),
    }).catch(() => {})
  );

  // Pass request through to the actual page — transparent to the visitor
  return context.next();
}
