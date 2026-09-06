const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const UPSTREAM_API = "https://apifb-ten.vercel.app";
const JWT_SECRET = process.env.JWT_SECRET || "sakuda-secret-key-change-in-production";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "saqibsarwar@cc.cc";
const ADMIN_PASSWORD_HASH = "$2a$10$w7DIFMv06fhSC2ZXYv3Zse0ccEkzm9tJJrg.Rc5MKlYnutTclbVDC"; // Biscoe@@3

// Cloudflare KV credentials for permanent storage
const CF_ACCOUNT_ID = process.env.CF_ACCOUNT_ID || "7be17faee5f8104b96b7887ab587398f";
const CF_KV_NAMESPACE_ID = process.env.CF_KV_NAMESPACE_ID || "2cb8590f9479439c9391c78a555a4dc5";
const CF_AUTH_EMAIL = process.env.CF_AUTH_EMAIL || "";
const CF_AUTH_KEY = process.env.CF_AUTH_KEY || "";

const CF_KV_KEY = "SAKUDA_API_KEYS_DATA_V1";

// In-memory fallback / write-through cache
const memoryStore = global.__sakudaStore || (global.__sakudaStore = {
  keys: new Map(),
  stats: { totalRequests: 0 },
  lastLoaded: 0,
});

async function cfKvGet() {
  try {
    const url = `https://api.cloudflare.com/client/v4/accounts/${CF_ACCOUNT_ID}/storage/kv/namespaces/${CF_KV_NAMESPACE_ID}/values/${CF_KV_KEY}`;
    const r = await fetch(url, {
      headers: {
        "X-Auth-Email": CF_AUTH_EMAIL,
        "X-Auth-Key": CF_AUTH_KEY,
      },
      signal: AbortSignal.timeout(5000),
    });
    if (r.status === 404) return null;
    if (!r.ok) {
      console.error("CF KV get error:", r.status, await r.text().catch(() => ""));
      return null;
    }
    return await r.json();
  } catch (err) {
    console.error("CF KV fetch error:", err.message);
    return null;
  }
}

async function cfKvPut(data) {
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
      signal: AbortSignal.timeout(6000),
    });
    const res = await r.json().catch(() => ({}));
    if (!res.success) {
      console.error("CF KV put failed:", JSON.stringify(res));
    }
    return res.success;
  } catch (err) {
    console.error("CF KV put error:", err.message);
    return false;
  }
}

// Load data from Cloudflare KV with 30s cache TTL
async function loadState(force = false) {
  const now = Date.now();
  if (!force && memoryStore.lastLoaded && now - memoryStore.lastLoaded < 30000 && memoryStore.keys.size > 0) {
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
    // Seed default key if empty
    if (!memoryStore.keys.has("sakuda")) {
      memoryStore.keys.set("sakuda", {
        key: "sakuda",
        label: "Default key",
        documentation: "Permanent key provisioned by system.",
        createdAt: "permanent",
        active: true,
        uses: 0,
        lastUsed: null,
      });
      await saveState();
    }
    memoryStore.lastLoaded = now;
  }
}

// Save state to Cloudflare KV immediately
async function saveState() {
  const payload = {
    keys: [...memoryStore.keys.values()],
    stats: memoryStore.stats,
    updatedAt: new Date().toISOString(),
  };
  await cfKvPut(payload);
}

function setCors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
}

function json(res, status, body) {
  res.statusCode = status;
  res.setHeader("Content-Type", "application/json");
  res.end(JSON.stringify(body));
}

function readBody(req) {
  return new Promise((resolve) => {
    let data = "";
    req.on("data", (c) => (data += c));
    req.on("end", () => {
      try {
        resolve(JSON.parse(data || "{}"));
      } catch {
        resolve({});
      }
    });
  });
}

function authAdmin(req) {
  const auth = req.headers.authorization || "";
  if (!auth.startsWith("Bearer ")) return false;
  try {
    jwt.verify(auth.slice(7), JWT_SECRET);
    return true;
  } catch {
    return false;
  }
}

async function validateAndCountKey(key) {
  if (!key) return null;
  await loadState();
  const entry = memoryStore.keys.get(key);
  if (!entry || !entry.active) return null;

  entry.uses = (entry.uses || 0) + 1;
  entry.lastUsed = new Date().toISOString();
  memoryStore.stats.totalRequests = (memoryStore.stats.totalRequests || 0) + 1;

  // Persist update in background
  saveState().catch((e) => console.error("Error saving state:", e));
  return entry;
}

async function proxyToUpstream(res, upstreamPath) {
  try {
    const upstream = await fetch(`${UPSTREAM_API}${upstreamPath}`, {
      headers: { "User-Agent": "Sakuda-API/1.0" },
      signal: AbortSignal.timeout(15000),
    });
    const text = await upstream.text();
    res.statusCode = upstream.status;
    res.setHeader("Content-Type", upstream.headers.get("content-type") || "application/json");
    res.setHeader("Cache-Control", "no-store");
    res.end(text);
  } catch (e) {
    json(res, 502, { error: "Upstream API unreachable", detail: String(e && e.message || e) });
  }
}

module.exports = async (req, res) => {
  setCors(res);
  if (req.method === "OPTIONS") {
    res.statusCode = 204;
    return res.end();
  }

  const url = new URL(req.url, "http://localhost");
  const path = url.pathname;

  // ---- Health ----
  if (path === "/api/health" || path === "/api") {
    await loadState();
    return json(res, 200, {
      name: "Sakuda API",
      status: "online",
      version: "1.1.0",
      time: new Date().toISOString(),
      storage: "Cloudflare KV",
      totalRequests: memoryStore.stats.totalRequests || 0,
      totalKeys: memoryStore.keys.size,
      endpoints: {
        devices: "/api/{db_code}/devices?key=YOUR_KEY",
        messages: "/api/{db_code}/messages/{client_id}?key=YOUR_KEY&limit=5",
        admin: "/admin",
      },
    });
  }

  // ---- Admin login ----
  if (path === "/api/login" && req.method === "POST") {
    const body = await readBody(req);
    const okEmail = body.email === ADMIN_EMAIL;
    const okPass = body.password ? bcrypt.compareSync(body.password, ADMIN_PASSWORD_HASH) : false;
    if (!okEmail || !okPass) {
      return json(res, 401, { error: "Invalid email or password" });
    }
    const token = jwt.sign({ sub: ADMIN_EMAIL, role: "admin" }, JWT_SECRET, { expiresIn: "12h" });
    return json(res, 200, { token, email: ADMIN_EMAIL, expiresIn: "12h" });
  }

  // ---- Key management (admin only) ----
  if (path === "/api/keys" && req.method === "GET") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    await loadState(true); // force fresh sync from Cloudflare KV
    return json(res, 200, {
      keys: [...memoryStore.keys.values()].map((k) => ({ ...k })),
      total: memoryStore.keys.size,
      stats: memoryStore.stats,
      storage: "Cloudflare KV",
    });
  }

  if (path === "/api/keys" && req.method === "POST") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const body = await readBody(req);
    const key = (body.key || "").trim();
    if (!/^[a-zA-Z0-9_-]{3,64}$/.test(key)) {
      return json(res, 400, { error: "Key must be 3-64 chars: letters, numbers, - or _" });
    }

    await loadState(true);
    if (memoryStore.keys.has(key)) return json(res, 409, { error: "Key already exists" });

    const entry = {
      key,
      label: body.label || "API key",
      documentation: body.documentation || "",
      createdAt: new Date().toISOString(),
      active: true,
      uses: 0,
      lastUsed: null,
    };
    memoryStore.keys.set(key, entry);
    await saveState();

    return json(res, 201, {
      created: entry,
      usage: {
        devices: `https://sakuda-api.vercel.app/api/101/devices?key=${key}`,
        messages: `https://sakuda-api.vercel.app/api/101/messages/{client_id}?key=${key}`,
      },
      note: "Permanent key — saved to Cloudflare KV across all instances.",
    });
  }

  const keyDeleteMatch = path.match(/^\/api\/keys\/(.+)$/);
  if (keyDeleteMatch && req.method === "DELETE") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const key = decodeURIComponent(keyDeleteMatch[1]);
    if (key === "sakuda") return json(res, 400, { error: "Default key cannot be deleted" });

    await loadState(true);
    if (!memoryStore.keys.has(key)) return json(res, 404, { error: "Key not found" });

    memoryStore.keys.delete(key);
    await saveState();
    return json(res, 200, { deleted: key, status: "permanently deleted from Cloudflare KV" });
  }

  // ---- Toggle key active state ----
  const keyToggleMatch = path.match(/^\/api\/keys\/(.+)\/toggle$/);
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

  // ---- Proxy: /api/:db/devices ----
  const devicesMatch = path.match(/^\/api\/(\d+)\/devices$/);
  if (devicesMatch && req.method === "GET") {
    const key = url.searchParams.get("key");
    const valid = await validateAndCountKey(key);
    if (!valid) {
      return json(res, 401, {
        error: "Valid API key required",
        hint: "Append ?key=YOUR_KEY — get a key from the API admin",
      });
    }
    return proxyToUpstream(res, `/api/${devicesMatch[1]}/devices`);
  }

  // ---- Proxy: /api/:db/messages/:clientId ----
  const messagesMatch = path.match(/^\/api\/(\d+)\/messages\/([^/]+)$/);
  if (messagesMatch && req.method === "GET") {
    const key = url.searchParams.get("key");
    const valid = await validateAndCountKey(key);
    if (!valid) {
      return json(res, 401, {
        error: "Valid API key required",
        hint: "Append ?key=YOUR_KEY — get a key from the API admin",
      });
    }
    const limit = url.searchParams.get("limit") || "10";
    return proxyToUpstream(res, `/api/${messagesMatch[1]}/messages/${messagesMatch[2]}?limit=${encodeURIComponent(limit)}`);
  }

  return json(res, 404, { error: "Not found", path, hint: "See /api for endpoint docs" });
};
