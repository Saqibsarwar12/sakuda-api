const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const UPSTREAM_API = "https://apifb-ten.vercel.app";
const JWT_SECRET = process.env.JWT_SECRET || "sakuda-secret-key-change-in-production";
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || "saqibsarwar@cc.cc";
const ADMIN_PASSWORD_HASH = "$2a$10$w7DIFMv06fhSC2ZXYv3Zse0ccEkzm9tJJrg.Rc5MKlYnutTclbVDC"; // Biscoe@@3

// In-memory key store, seeded from env (comma-separated) + default key.
// Note: keys created via admin panel persist while the serverless instance is warm.
// To make keys permanent, add them to the SAKUDA_KEYS env var and redeploy.
const store = global.__sakudaStore || (global.__sakudaStore = {
  keys: new Map(),
  stats: { totalRequests: 0, perKey: {} },
});

function seedKeys() {
  const seed = (process.env.SAKUDA_KEYS || "sakuda").split(",").map((k) => k.trim()).filter(Boolean);
  for (const key of seed) {
    if (!store.keys.has(key)) {
      store.keys.set(key, {
        key,
        label: key === "sakuda" ? "Default key" : "Seeded key",
        documentation: "Permanent key provisioned via environment.",
        createdAt: "permanent",
        active: true,
        uses: 0,
      });
    }
  }
}
seedKeys();

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

function validateKey(key) {
  if (!key) return null;
  const entry = store.keys.get(key);
  if (!entry || !entry.active) return null;
  entry.uses += 1;
  entry.lastUsed = new Date().toISOString();
  store.stats.totalRequests += 1;
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
    return json(res, 200, {
      name: "Sakuda API",
      status: "online",
      version: "1.0.0",
      time: new Date().toISOString(),
      totalRequests: store.stats.totalRequests,
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
    return json(res, 200, {
      keys: [...store.keys.values()].map((k) => ({ ...k })),
      total: store.keys.size,
      stats: store.stats,
    });
  }

  if (path === "/api/keys" && req.method === "POST") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const body = await readBody(req);
    const key = (body.key || "").trim();
    if (!/^[a-zA-Z0-9_-]{3,64}$/.test(key)) {
      return json(res, 400, { error: "Key must be 3-64 chars: letters, numbers, - or _" });
    }
    if (store.keys.has(key)) return json(res, 409, { error: "Key already exists" });
    const entry = {
      key,
      label: body.label || "API key",
      documentation: body.documentation || "",
      createdAt: new Date().toISOString(),
      active: true,
      uses: 0,
    };
    store.keys.set(key, entry);
    return json(res, 201, {
      created: entry,
      usage: {
        devices: `https://sakuda-api.vercel.app/api/101/devices?key=${key}`,
        messages: `https://sakuda-api.vercel.app/api/101/messages/{client_id}?key=${key}`,
      },
      note: "Session key — persists while instance is warm. Add to SAKUDA_KEYS env var for permanence.",
    });
  }

  const keyDeleteMatch = path.match(/^\/api\/keys\/(.+)$/);
  if (keyDeleteMatch && req.method === "DELETE") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const key = decodeURIComponent(keyDeleteMatch[1]);
    if (key === "sakuda") return json(res, 400, { error: "Default key cannot be deleted" });
    if (!store.keys.has(key)) return json(res, 404, { error: "Key not found" });
    store.keys.delete(key);
    return json(res, 200, { deleted: key });
  }

  // ---- Toggle key active state ----
  const keyToggleMatch = path.match(/^\/api\/keys\/(.+)\/toggle$/);
  if (keyToggleMatch && req.method === "POST") {
    if (!authAdmin(req)) return json(res, 401, { error: "Unauthorized" });
    const key = decodeURIComponent(keyToggleMatch[1]);
    const entry = store.keys.get(key);
    if (!entry) return json(res, 404, { error: "Key not found" });
    entry.active = !entry.active;
    return json(res, 200, { key, active: entry.active });
  }

  // ---- Proxy: /api/:db/devices ----
  const devicesMatch = path.match(/^\/api\/(\d+)\/devices$/);
  if (devicesMatch && req.method === "GET") {
    const key = url.searchParams.get("key");
    const valid = validateKey(key);
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
    const valid = validateKey(key);
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
