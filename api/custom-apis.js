const crypto = require("node:crypto");
const auth = require("./auth");

const COOKIE = "txg_custom_apis";
const MAX_APIS = 8;
const MAX_COOKIE_BYTES = 3500;

function secret() {
  return process.env.AUTH_SECRET || "TXG-INFORMATION-AUTH-2026-CHANGE-ME";
}

function parseCookies(req) {
  const out = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i >= 0) out[part.slice(0, i).trim()] = decodeURIComponent(part.slice(i + 1).trim());
  }
  return out;
}

function encrypt(value) {
  const iv = crypto.randomBytes(12);
  const key = crypto.createHash("sha256").update(secret()).digest();
  const cipher = crypto.createCipheriv("aes-256-gcm", key, iv);
  const encrypted = Buffer.concat([cipher.update(value, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, encrypted]).toString("base64url");
}

function decrypt(value) {
  try {
    const raw = Buffer.from(String(value), "base64url");
    if (raw.length < 29) return [];
    const iv = raw.subarray(0, 12);
    const tag = raw.subarray(12, 28);
    const encrypted = raw.subarray(28);
    const key = crypto.createHash("sha256").update(secret()).digest();
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, iv);
    decipher.setAuthTag(tag);
    return JSON.parse(Buffer.concat([decipher.update(encrypted), decipher.final()]).toString("utf8"));
  } catch {
    return [];
  }
}

function getApis(req) {
  const value = parseCookies(req)[COOKIE];
  const apis = decrypt(value);
  return Array.isArray(apis) ? apis : [];
}

function validUrl(value) {
  try {
    const u = new URL(value);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function cleanApi(body) {
  return {
    id: crypto.randomUUID(),
    name: String(body.name || "Custom API").trim().slice(0, 60),
    url: String(body.url || "").trim().slice(0, 1200),
    key: String(body.key || "").slice(0, 1000),
    header: String(body.header || "Authorization").trim().slice(0, 80),
    method: String(body.method || "GET").toUpperCase() === "POST" ? "POST" : "GET"
  };
}

function save(res, apis) {
  const token = encrypt(JSON.stringify(apis.slice(0, MAX_APIS)));
  if (Buffer.byteLength(token, "utf8") > MAX_COOKIE_BYTES) {
    return res.status(413).json({ success: false, error: "Saved API list is too large. Remove one API and try again." });
  }
  res.setHeader("Set-Cookie", `${COOKIE}=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=31536000`);
  return null;
}

module.exports = async function handler(req, res) {
  if (!auth.authenticated(req)) return res.status(401).json({ success: false, error: "Login required" });

  if (req.method === "GET") {
    const apis = getApis(req).map(({ key, ...safe }) => ({ ...safe, has_key: Boolean(key) }));
    return res.status(200).json({ success: true, apis });
  }

  const body = req.body && typeof req.body === "object" ? req.body : {};
  let apis = getApis(req);

  if (req.method === "POST") {
    if (String(body.action || "") === "delete") {
      apis = apis.filter(x => x.id !== String(body.id || ""));
    } else {
      const api = cleanApi(body);
      if (!api.url || !validUrl(api.url)) return res.status(400).json({ success: false, error: "Enter a valid http/https API URL." });
      if (apis.length >= MAX_APIS) return res.status(400).json({ success: false, error: `Maximum ${MAX_APIS} saved APIs.` });
      apis.unshift(api);
    }
    const err = save(res, apis);
    if (err) return err;
    return res.status(200).json({ success: true, apis: apis.map(({ key, ...safe }) => ({ ...safe, has_key: Boolean(key) })) });
  }

  res.setHeader("Allow", "GET, POST");
  return res.status(405).json({ success: false, error: "Method not allowed" });
};

module.exports.getApis = getApis;
