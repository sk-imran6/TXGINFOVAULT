const crypto = require("crypto");

const ADMIN_PASSWORD = "TXG@Admin#2026!Secure";

// Change this if you want to change the password.
// Keep this file private if the GitHub repository is private.

const SESSION_SECRET =
  "TXG_INFORMATION_CENTER_SESSION_SECRET_2026_CHANGE_THIS_RANDOM_VALUE";

const COOKIE_NAME = "txg_admin_session";
const SESSION_MAX_AGE = 12 * 60 * 60;

function hash(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("hex");
}

function createSession() {
  const timestamp = Math.floor(Date.now() / 1000);
  const payload = `${timestamp}.${sign(String(timestamp))}`;
  return Buffer.from(payload).toString("base64url");
}

function verifySession(token) {
  if (!token) return false;

  try {
    const decoded = Buffer.from(token, "base64url").toString();

    const parts = decoded.split(".");
    if (parts.length !== 2) return false;

    const timestamp = Number(parts[0]);
    const signature = parts[1];

    if (!Number.isFinite(timestamp)) return false;

    const now = Math.floor(Date.now() / 1000);

    if (now - timestamp > SESSION_MAX_AGE) {
      return false;
    }

    if (timestamp > now + 60) {
      return false;
    }

    const expected = sign(String(timestamp));

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch (e) {
    return false;
  }
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || "";

  const items = cookie.split(";");

  for (const item of items) {
    const [key, ...rest] = item.trim().split("=");

    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function setCookie(res, value, maxAge) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(value)}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${maxAge}`
  );
}

function clearCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0`
  );
}

function authenticated(req) {
  const token = getCookie(req, COOKIE_NAME);
  return verifySession(token);
}

module.exports = {
  authenticated
};

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  const action =
    req.method === "GET"
      ? String(req.query?.action || "status")
      : String(req.body?.action || "");

  if (req.method === "GET" && action === "status") {
    return res.status(200).json({
      ok: true,
      loggedIn: authenticated(req)
    });
  }

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });
  }

  if (action === "login") {
    const password = String(req.body?.password || "");

    if (!password) {
      return res.status(400).json({
        ok: false,
        error: "Password required"
      });
    }

    const correct = crypto.timingSafeEqual(
      Buffer.from(hash(password)),
      Buffer.from(hash(ADMIN_PASSWORD))
    );

    if (!correct) {
      return res.status(401).json({
        ok: false,
        error: "Invalid password"
      });
    }

    const session = createSession();

    setCookie(res, session, SESSION_MAX_AGE);

    return res.status(200).json({
      ok: true,
      loggedIn: true
    });
  }

  if (action === "logout") {
    clearCookie(res);

    return res.status(200).json({
      ok: true,
      loggedIn: false
    });
  }

  return res.status(400).json({
    ok: false,
    error: "Unknown action"
  });
};
