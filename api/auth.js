// api/auth.js

const crypto = require("crypto");

const COOKIE_NAME = "txg_admin_session";

const FALLBACK_PASSWORD = "TXG@Admin#2026!Secure";
const FALLBACK_SECRET =
  "TXG-INFORMATION-AUTH-2026-CHANGE-ME";

const SESSION_HOURS = 12;

function getPassword() {
  return process.env.ADMIN_PASSWORD || FALLBACK_PASSWORD;
}

function getSecret() {
  return process.env.AUTH_SECRET || FALLBACK_SECRET;
}

function createSession() {
  const timestamp = Date.now().toString();

  const signature = crypto
    .createHmac("sha256", getSecret())
    .update(timestamp)
    .digest("hex");

  return `${timestamp}.${signature}`;
}

function verifySession(token) {
  if (!token || typeof token !== "string") {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const timestamp = Number(parts[0]);
  const signature = parts[1];

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  const age = Date.now() - timestamp;

  // Session expired
  if (age < 0 || age > SESSION_HOURS * 60 * 60 * 1000) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", getSecret())
    .update(String(timestamp))
    .digest("hex");

  if (signature.length !== expected.length) {
    return false;
  }

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature, "utf8"),
      Buffer.from(expected, "utf8")
    );
  } catch {
    return false;
  }
}

function getSessionFromRequest(req) {
  // Vercel may provide parsed cookies
  if (req.cookies && req.cookies[COOKIE_NAME]) {
    return req.cookies[COOKIE_NAME];
  }

  // Fallback manual cookie parser
  const cookieHeader = req.headers.cookie || "";

  const cookies = cookieHeader.split(";");

  for (const cookie of cookies) {
    const index = cookie.indexOf("=");

    if (index === -1) continue;

    const name = cookie
      .slice(0, index)
      .trim();

    const value = cookie
      .slice(index + 1)
      .trim();

    if (name === COOKIE_NAME) {
      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }
    }
  }

  return null;
}

function setSessionCookie(res, token) {
  const maxAge =
    SESSION_HOURS * 60 * 60;

  res.setHeader(
    "Set-Cookie",
    [
      `${COOKIE_NAME}=${encodeURIComponent(token)}`,
      "Path=/",
      `Max-Age=${maxAge}`,
      "HttpOnly",
      "Secure",
      "SameSite=Lax"
    ].join("; ")
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    [
      `${COOKIE_NAME}=`,
      "Path=/",
      "Max-Age=0",
      "HttpOnly",
      "Secure",
      "SameSite=Lax"
    ].join("; ")
  );
}

function json(res, status, data) {
  res.status(status).json(data);
}

module.exports = async function handler(req, res) {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate"
  );

  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  // ==========================================
  // GET = CHECK LOGIN
  // ==========================================

  if (req.method === "GET") {
    const token = getSessionFromRequest(req);

    const authenticated =
      verifySession(token);

    return json(res, 200, {
      ok: true,
      authenticated
    });
  }

  // ==========================================
  // POST
  // ==========================================

  if (req.method === "POST") {
    const body =
      typeof req.body === "object" &&
      req.body
        ? req.body
        : {};

    const action =
      String(body.action || "login")
        .toLowerCase();

    // ========================================
    // LOGIN
    // ========================================

    if (action === "login") {
      const password =
        typeof body.password === "string"
          ? body.password
          : "";

      if (!password) {
        return json(res, 400, {
          ok: false,
          error: "Password is required."
        });
      }

      if (password !== getPassword()) {
        return json(res, 401, {
          ok: false,
          error: "Wrong password."
        });
      }

      const token = createSession();

      setSessionCookie(
        res,
        token
      );

      return json(res, 200, {
        ok: true,
        authenticated: true
      });
    }

    // ========================================
    // LOGOUT
    // ========================================

    if (action === "logout") {
      clearSessionCookie(res);

      return json(res, 200, {
        ok: true,
        authenticated: false
      });
    }

    // ========================================
    // CHECK
    // ========================================

    if (action === "check") {
      const token =
        getSessionFromRequest(req);

      const authenticated =
        verifySession(token);

      return json(res, 200, {
        ok: true,
        authenticated
      });
    }

    return json(res, 400, {
      ok: false,
      error: "Invalid auth action."
    });
  }

  res.setHeader(
    "Allow",
    "GET, POST"
  );

  return json(res, 405, {
    ok: false,
    error: "Method not allowed."
  });
};
