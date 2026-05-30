# Research Log: Reverse-Engineering SimilarWeb Traffic Manipulation

**Project:** skins-bins.xyz
**Goal:** Reverse-engineer how a third-party vendor successfully manipulates SimilarWeb traffic metrics, and replicate their methodology cost-effectively.

---

## 1. The Problem & Initial Observations

We hired a vendor to drive 10,000 visits to our site (`skins-bins.xyz`) with the expectation that these visits would reflect in SimilarWeb's panel. 

**Initial anomalies observed:**
- The vendor's traffic was almost entirely invisible in our Google Analytics (GA4) and custom JS trackers.
- In SimilarWeb, out of 10,000 purchased visits, only a tiny fraction (10-13 visits) actually appeared.
- The geo-distribution of the traffic that *did* appear in SimilarWeb did not match our requested target geos.
- The vendor's traffic appeared to be hitting `/wp-admin/install.php` and other random endpoints, alongside regular `GET` requests.

**Core Question:** How is the vendor generating this traffic, why is it invisible to JS analytics, and how does it actually reach SimilarWeb?

---

## 2. Iteration 1: Server-Side Logging (Edge Functions)

Because the vendor's traffic was bypassing our client-side JS trackers, we hypothesized they were using headless browsers or simple HTTP clients that do not execute JavaScript.

**Action taken:**
We deployed a Netlify Edge Function (`request-logger.js`) to intercept **all** HTTP requests at the CDN edge, before they even reach the site's HTML. This logger captured IP, ASN, Geo, User-Agent, and all HTTP headers, saving them to a Cloudflare R2 bucket.

**Findings from Server-Side Logs:**
1. **Infrastructure:** 100% of the suspicious traffic originated from **Amazon AWS** data centers across multiple regions (us-east-1, eu-central-1, sa-east-1, ap-southeast-1).
2. **User-Agents:** The traffic used a mix of:
   - `HeadlessChrome/131.0.6778.0 Linux x86_64`
   - Spoofed mobile UAs: `Mozilla/5.0 (iPhone; CPU iPhone OS 13_2_3 like Mac OS X)` with `Accept-Language: zh-CN`
   - `req/v3 (https://github.com/imroc/req)` — a Go-based HTTP client library.
3. **Behavior:** The requests were instantaneous. There was no sequential page navigation, no static asset loading (CSS/images), and no JS execution.

**Conclusion 1:** The vendor is running a distributed script on AWS EC2 instances. They are using a mix of Puppeteer/Playwright (HeadlessChrome) and simple Go HTTP clients (`req/v3`) to blast the site with GET requests.

---

## 3. Iteration 2: Maximum Surveillance (Client-Side)

To understand if *any* of the vendor's bots were executing JavaScript, and to see if they were communicating with SimilarWeb's servers directly, we deployed a "maximum surveillance" JS tracker (`tracker.js`).

**Action taken:**
We injected a script that captures:
- Deep JS fingerprints (Canvas, WebGL, Audio, hardware concurrency, plugins).
- Behavioral metrics (mouse movements, scroll depth, clicks).
- Network activity (Resource Timing API to see what assets load).
- Outbound requests (intercepting `fetch`/`XHR` and using CSP `report-uri` to catch requests to `similarweb.com`).

**Findings from Client-Side Logs:**
1. **Zero Human Behavior:** The bots that *did* execute JS (the HeadlessChrome ones) had 0 mouse movements, 0 scrolls, and 0 clicks.
2. **Hardware Fingerprints:** They exposed SwiftShader (software GPU), 0 plugins, and 0 fonts — classic headless signatures.
3. **No Outbound SW Calls:** We caught **zero** CSP violations or outbound requests to SimilarWeb's data collection APIs (`rank.similarweb.com` or `data.similarweb.com`).

**Conclusion 2:** The vendor's bots are **not** running the SimilarWeb browser extension, nor are they injecting SimilarWeb's tracking SDK into the page. 

---

## 4. Uncovering the SimilarWeb Data Collection Mechanism

If the vendor's bots aren't talking to SimilarWeb directly, how does SimilarWeb know about the traffic?

We researched SimilarWeb's official data methodology. They collect data from four sources:
1. **Direct Measurement:** Sites sharing their own GA data (not applicable here).
2. **Public Data Extraction:** Web scraping (not applicable for traffic metrics).
3. **Partnerships (ISP/Panel Data):** Buying aggregated HTTP request logs from Internet Service Providers (ISPs) and network operators.
4. **Contributory Network:** Millions of users who have installed the SimilarWeb browser extension (or partner extensions), which silently logs every URL visited.

### The Vendor's Strategy (Hypothesis A: ISP Data)
The vendor uses `req/v3` (a Go HTTP client that can spoof TLS fingerprints) to send millions of GET requests. To make these requests visible to SimilarWeb, they route them through **Residential Proxies** (e.g., Oxylabs, Bright Data). 
- **Flow:** Go Script (AWS) → Residential Proxy (Real ISP in Poland) → Our Site.
- **Result:** The Polish ISP logs the HTTP request and sells that data to SimilarWeb. SimilarWeb counts it as a visit.
- **Why it fails:** SimilarWeb aggressively filters this data. They deduplicate by IP and look for realistic session lengths. A naked GET request with 0 seconds dwell time is often discarded, which explains why 10,000 vendor visits resulted in only 10-13 SW visits (0.1% conversion).

### The "Holy Grail" Strategy (Hypothesis B: Extension Farm)
Our internal research (`sw-bot-dev-brief.md`) revealed how SimilarWeb's extension actually works. It assigns a unique "identity" to each Chrome profile and POSTs browsing data directly to `rank.similarweb.com`.
- **Flow:** Real Chrome Profile + SW Extension → Visits Site → Extension POSTs to SW.
- **Result:** SimilarWeb trusts this data implicitly because it comes from their own authenticated extension network. 1 visit = 1 SW visit (100% conversion).

---

## 5. Current State & Next Steps

We have successfully reverse-engineered that the current vendor is using a **low-quality, high-volume approach** (AWS + Go HTTP clients + Residential Proxies). This approach is cheap for them but yields terrible conversion rates in SimilarWeb.

**To build our own, superior system, we must pivot to the Extension Farm architecture:**

1. **Abandon naked HTTP GETs:** Sending requests via `req/v3` or curl is a waste of money if the goal is SimilarWeb manipulation.
2. **Build a Chrome Profile Farm:** We need a pool of persistent Chrome user profiles, each with the SimilarWeb extension installed.
3. **Identity Maturation:** Each profile must be "warmed up" by visiting normal sites (Google, Wikipedia) so SimilarWeb assigns it a trusted identity.
4. **Execution:** Use Playwright/Selenium (non-headless, via Xvfb) to drive these profiles to our target sites, routing through residential proxies to ensure the IP matches the profile's established geo-location.

### Immediate Action Items:
- [ ] Develop a proof-of-concept Python script using Playwright to launch a persistent Chrome profile with the unpacked SimilarWeb extension.
- [ ] Verify that the extension successfully registers an identity with `data.similarweb.com`.
- [ ] Run a test batch of 50 visits using this method and monitor SimilarWeb 48 hours later to calculate the conversion rate.

---

## 6. Iteration 3: Focused Data Collection (Cookie Trap, Redirect Trap, Header Order)

**Date:** 2026-05-30

Based on the realization that we need to understand the *exact mechanics* of how the vendor's requests differ from ours, we upgraded the logging infrastructure with targeted tests:

### 6.1 Cookie Trap
**What it does:** Edge Function sets a `_sb_sid` cookie on first visit. On subsequent visits, if the cookie is returned — the client supports cookies and maintains state.

**Why it matters:** 
- If vendor's bot returns cookies → it maintains session state (more sophisticated, like a real browser)
- If vendor's bot does NOT return cookies → it's stateless (each request is independent, like `curl`)
- Our headless Chrome approach returns cookies. If vendor doesn't → they're doing something fundamentally different.

### 6.2 Redirect Trap
**What it does:** `/r` returns 301 → `/home`. Edge Function logs both requests.

**Why it matters:**
- If we see `/r` in logs but NOT `/home` → bot doesn't follow redirects (simple HTTP client)
- If we see both → bot follows redirects (browser-like behavior)
- `req/v3` by default follows redirects, but this confirms it

### 6.3 Header Order Analysis
**What it does:** Edge Function now logs the exact order of HTTP headers as received.

**Why it matters:**
- Real Chrome sends headers in a specific order: `Host`, `Connection`, `sec-ch-ua`, `sec-ch-ua-mobile`, `sec-ch-ua-platform`, `Upgrade-Insecure-Requests`, `User-Agent`, `Accept`, etc.
- `req/v3` with `ImpersonateChrome()` attempts to replicate this order, but may have subtle differences
- Comparing header order between vendor traffic and our headless Chrome will show if they're using the same impersonation library

### 6.4 Updated Worker with ASN Enrichment
Worker now logs `tlsCipher`, `cf_botManagement`, and has an `/asn-lookup` endpoint to classify IPs as residential vs datacenter.

---

## 7. Key Open Questions

1. **Is the vendor using residential proxies at all?** We only see AWS IPs. Either:
   - They route through residential proxies but we see the AWS hop (unlikely with Netlify Edge)
   - They DON'T use residential proxies and have a different mechanism to reach SW

2. **Does `req/v3` with Chrome TLS impersonation fool ISP DPI?** If ISPs classify traffic based on TLS fingerprint, and `req/v3` perfectly mimics Chrome's JA3 — the ISP would log it as "Chrome visit" and sell that data to SW.

3. **Volume hypothesis:** Is the vendor simply sending 500k+ requests (as per `worker_configuration.md`) and relying on ~2-5% making it through SW's filters? That would explain why they deliver "correct" numbers — they just overshoot massively.

4. **Which specific ISPs are in SimilarWeb's data partnership?** This is the key unknown. If we knew which ISPs feed data to SW, we could buy proxies specifically from those networks.

---

## 8. Files & Infrastructure Reference

| Component | Location | Purpose |
|---|---|---|
| Edge Function | `netlify/edge-functions/request-logger.js` | Server-side logging of ALL requests |
| JS Tracker | `tracker.js` | Client-side fingerprint + behavioral logging |
| Cloudflare Worker | `worker-v3.js` (deployed to `skins.companybbig.workers.dev`) | R2 storage, CSP/NEL reports, ASN lookup |
| R2 Bucket | `skins-bins-logs/` | All log storage |
| GitHub Repo | `Trabs3/skins-bins-site` | Auto-deploys to Netlify on push |
| Analysis Scripts | `r2_analyze.py`, `r2_fingerprint.py`, `r2_full_report.py` | Log analysis |
| Dev Brief | `sw-bot-dev-brief.md` | Chrome Profile Farm architecture |
| Worker Config | `worker_configuration.md` | Vendor's bot service configuration (leaked/observed) |
