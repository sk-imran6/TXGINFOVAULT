const crypto = require("node:crypto");

const COOKIE = "txg_admin_session";
const FALLBACK_PASSWORD = "TXG@Admin#2026!Secure";
const FALLBACK_SECRET = "TXG-INFORMATION-AUTH-2026-CHANGE-ME";

function getPassword() {
  return process.env.ADMIN_PASSWORD || FALLBACK_PASSWORD;
}

function getSecret() {
  return process.env.AUTH_SECRET || FALLBACK_SECRET;
}

function sign(value) {
  return crypto.createHmac("sha256", getSecret()).update(value).digest("hex");
}

function makeToken() {
  const payload = `${Date.now()}.${crypto.randomBytes(24).toString("hex")}`;
  return `${payload}.${sign(payload)}`;
}

function parseCookies(req) {
  const result = {};
  for (const part of String(req.headers.cookie || "").split(";")) {
    const i = part.indexOf("=");
    if (i >= 0) {
      result[part.slice(0, i).trim()] =
        decodeURIComponent(part.slice(i + 1).trim());
    }
  }
  return result;
}

function validToken(token) {
  if (!token) return false;

  const p = String(token).split(".");
  if (p.length !== 3) return false;

  const payload = `${p[0]}.${p[1]}`;
  const expected = sign(payload);

  if (p[2].length !== expected.length) return false;

  try {
    if (!crypto.timingSafeEqual(
      Buffer.from(p[2]),
      Buffer.from(expected)
    )) return false;
  } catch {
    return false;
  }

  const created = Number(p[0]);
  return Number.isFinite(created) &&
    Date.now() - created < 12 * 60 * 60 * 1000;
}

function authenticated(req) {
  return validToken(parseCookies(req)[COOKIE]);
}

function handler(req, res) {
  if (req.method === "GET") {
    return res.status(200).json({
      success: true,
      authenticated: authenticated(req)
    });
  }

  if (req.method !== "POST") {
    res.setHeader("Allow", "GET, POST");
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  const body = req.body && typeof req.body === "object" ? req.body : {};
  const action = String(body.action || "check");

  if (action === "check") {
    return res.status(200).json({
      success: true,
      authenticated: authenticated(req)
    });
  }

  if (action === "login") {
    if (String(body.password || "") !== getPassword()) {
      return res.status(401).json({
        success: false,
        error: "Invalid password"
      });
    }

    res.setHeader(
      "Set-Cookie",
      `${COOKIE}=${encodeURIComponent(makeToken())}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=43200`
    );

    return res.status(200).json({
      success: true,
      authenticated: true
    });
  }

  if (action === "logout") {
    res.setHeader(
      "Set-Cookie",
      `${COOKIE}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`
    );

    return res.status(200).json({
      success: true,
      authenticated: false
    });
  }

  return res.status(400).json({
    success: false,
    error: "Unknown action"
  });
}

handler.authenticated = authenticated;
module.exports = handler;
