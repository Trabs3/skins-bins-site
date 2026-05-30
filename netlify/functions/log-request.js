// Netlify Serverless Function — log-request.js
// Works with drag-and-drop deployment (no build step needed)
// Called via _redirects: /log-req/* -> /.netlify/functions/log-request/:splat

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
];

function detectBot(ua) {
  if (!ua) return { is_bot: true, bot_name: "no-ua" };
  const lower = ua.toLowerCase();
  for (const p of BOT_PATTERNS) {
    if (lower.includes(p)) return { is_bot: true, bot_name: p };
  }
  return { is_bot: false, bot_name: null };
}

exports.handler = async function (event, context) {
  const startTime = Date.now();

  // Extract real path from query param (passed via _redirects)
  const requestedPath = event.queryStringParameters?.path || event.path || "/";
  const method = event.httpMethod;
  const headers = event.headers || {};

  const ua = headers["user-agent"] || "";
  const ip =
    headers["x-nf-client-connection-ip"] ||
    headers["x-forwarded-for"]?.split(",")[0]?.trim() ||
    headers["client-ip"] ||
    "unknown";

  const { is_bot, bot_name } = detectBot(ua);

  // Build log payload
  const logPayload = {
    log_type: "server_request",
    ts: new Date().toISOString(),
    site: "skins-bins.xyz",
    method: method,
    path: requestedPath,
    ip: ip,
    user_agent: ua,
    is_bot_ua: is_bot,
    bot_name: bot_name,
    headers: {
      referer: headers["referer"] || null,
      accept: headers["accept"] || null,
      accept_language: headers["accept-language"] || null,
      accept_encoding: headers["accept-encoding"] || null,
      content_type: headers["content-type"] || null,
      cache_control: headers["cache-control"] || null,
      pragma: headers["pragma"] || null,
      dnt: headers["dnt"] || null,
      sec_fetch_site: headers["sec-fetch-site"] || null,
      sec_fetch_mode: headers["sec-fetch-mode"] || null,
      sec_fetch_dest: headers["sec-fetch-dest"] || null,
      sec_ch_ua: headers["sec-ch-ua"] || null,
      sec_ch_ua_mobile: headers["sec-ch-ua-mobile"] || null,
      sec_ch_ua_platform: headers["sec-ch-ua-platform"] || null,
      x_forwarded_for: headers["x-forwarded-for"] || null,
      x_real_ip: headers["x-real-ip"] || null,
      x_nf_client_connection_ip: headers["x-nf-client-connection-ip"] || null,
      cf_connecting_ip: headers["cf-connecting-ip"] || null,
      cf_ipcountry: headers["cf-ipcountry"] || null,
      via: headers["via"] || null,
      connection: headers["connection"] || null,
      upgrade_insecure_requests: headers["upgrade-insecure-requests"] || null,
    },
    geo: {
      country: headers["x-country"] || headers["cf-ipcountry"] || null,
      city: headers["x-city"] || null,
      region: headers["x-region"] || null,
      latitude: headers["x-latitude"] || null,
      longitude: headers["x-longitude"] || null,
      timezone: headers["x-timezone"] || null,
    },
    netlify: {
      site_id: context.clientContext?.custom?.netlify?.site_id || null,
      deploy_id: headers["x-nf-deploy-id"] || null,
      request_id: headers["x-nf-request-id"] || null,
    },
    all_headers: headers,
    processing_ms: Date.now() - startTime,
  };

  // Fire-and-forget to Cloudflare Worker
  try {
    await fetch(WORKER_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(logPayload),
    });
  } catch (e) {
    // Don't fail the response if logging fails
  }

  // Return 204 No Content (invisible to the bot)
  return {
    statusCode: 204,
    body: "",
    headers: {
      "Cache-Control": "no-store",
    },
  };
};
