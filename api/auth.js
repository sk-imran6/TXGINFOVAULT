const crypto = require("crypto");

const COOKIE_NAME = "txg_admin_session";
const SESSION_MS = 12 * 60 * 60 * 1000;

const ADMIN_PASSWORD =
  process.env.ADMIN_PASSWORD || "TXG@Admin#2026!Secure";

function sign(value) {
  return crypto
    .createHmac("sha256", ADMIN_PASSWORD)
    .update(value)
    .digest("hex");
}

function makeToken() {
  const expires = Date.now() + SESSION_MS;
  const payload = String(expires);
  return `${payload}.${sign(payload)}`;
}

function validToken(token) {
  if (!token || typeof token !== "string") return false;

  const parts = token.split(".");
  if (parts.length !== 2) return false;

  const expires = Number(parts[0]);
  const signature = parts[1];

  if (!Number.isFinite(expires)) return false;
  if (Date.now() > expires) return false;

  const expected = sign(parts[0]);

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch {
    return false;
  }
}

function getCookie(req) {
  if (req.cookies && req.cookies[COOKIE_NAME]) {
    return req.cookies[COOKIE_NAME];
  }

  const header = req.headers.cookie || "";

  const match = header.match(
    new RegExp(
      "(?:^|;\\s*)" +
        COOKIE_NAME.replace(/[.*+?^${}()|[\]\\]/g, "\\$&") +
        "=([^;]*)"
    )
  );

  return match ? decodeURIComponent(match[1]) : null;
}

function isAuthenticated(req) {
  return validToken(getCookie(req));
}

function cookieHeader(token, maxAge) {
  return [
    `${COOKIE_NAME}=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "SameSite=Lax",
    "Secure",
    `Max-Age=${maxAge}`
  ].join("; ");
}

async function handler(req, res) {
  try {
    const method = String(req.method || "GET").toUpperCase();

    if (method === "GET") {
      if (!isAuthenticated(req)) {
        return res.status(401).json({
          ok: false,
          authenticated: false
        });
      }

      return res.status(200).json({
        ok: true,
        authenticated: true
      });
    }

    if (method === "POST") {
      const body =
        req.body && typeof req.body === "object"
          ? req.body
          : {};

      const password = String(body.password || "");

      if (!password || password !== ADMIN_PASSWORD) {
        return res.status(401).json({
          ok: false,
          authenticated: false,
          error: "Invalid password"
        });
      }

      const token = makeToken();

      res.setHeader(
        "Set-Cookie",
        cookieHeader(token, Math.floor(SESSION_MS / 1000))
      );

      return res.status(200).json({
        ok: true,
        authenticated: true
      });
    }

    if (method === "DELETE") {
      res.setHeader(
        "Set-Cookie",
        cookieHeader("", 0)
      );

      return res.status(200).json({
        ok: true,
        authenticated: false
      });
    }

    res.setHeader("Allow", "GET, POST, DELETE");

    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });
  } catch (error) {
    console.error("AUTH ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: "Authentication server error"
    });
  }
}

handler.authenticated = isAuthenticated;

module.exports = handler;
