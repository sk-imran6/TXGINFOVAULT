const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

const redis = Redis.fromEnv();

const SESSION_TTL = 60 * 60 * 12; // 12 hours
const LOGIN_LIMIT = 10;
const LOGIN_WINDOW = 60 * 10; // 10 minutes

// Initial password requested for the panel.
// IMPORTANT: keep your GitHub repository PRIVATE.
const INITIAL_PASSWORD = "TXG@Admin#2026!Secure";

function hashPassword(password, salt = crypto.randomBytes(16).toString("hex")) {
  const hash = crypto
    .pbkdf2Sync(password, salt, 210000, 32, "sha256")
    .toString("hex");

  return `pbkdf2$${salt}$${hash}`;
}

function verifyPassword(password, stored) {
  try {
    if (!stored || !stored.startsWith("pbkdf2$")) {
      return false;
    }

    const parts = stored.split("$");

    if (parts.length !== 3) {
      return false;
    }

    const salt = parts[1];
    const expected = parts[2];

    const actual = crypto
      .pbkdf2Sync(password, salt, 210000, 32, "sha256")
      .toString("hex");

    return crypto.timingSafeEqual(
      Buffer.from(actual, "hex"),
      Buffer.from(expected, "hex")
    );
  } catch {
    return false;
  }
}

async function getPasswordHash() {
  let stored = await redis.get("txg:admin:password");

  if (!stored) {
    stored = hashPassword(INITIAL_PASSWORD);
    await redis.set("txg:admin:password", stored);
  }

  return stored;
}

async function checkPassword(password) {
  const stored = await getPasswordHash();
  return verifyPassword(password, stored);
}

async function changePassword(newPassword) {
  const newHash = hashPassword(newPassword);

  await redis.set("txg:admin:password", newHash);

  // Invalidate all existing sessions.
  await redis.incr("txg:auth:session_version");
}

function createSessionToken() {
  return crypto.randomBytes(32).toString("hex");
}

async function createSession() {
  const token = createSessionToken();

  const version =
    (await redis.get("txg:auth:session_version")) || 0;

  await redis.set(
    `txg:session:${token}`,
    {
      version: Number(version),
      createdAt: Date.now()
    },
    {
      ex: SESSION_TTL
    }
  );

  return token;
}

async function validateSession(token) {
  if (!token) {
    return false;
  }

  const session = await redis.get(`txg:session:${token}`);

  if (!session) {
    return false;
  }

  const currentVersion =
    Number(await redis.get("txg:auth:session_version")) || 0;

  return Number(session.version) === currentVersion;
}

async function destroySession(token) {
  if (token) {
    await redis.del(`txg:session:${token}`);
  }
}

function getCookieToken(req) {
  const cookie = req.headers.cookie || "";

  const match = cookie.match(
    /(?:^|;\s*)txg_session=([^;]+)/
  );

  return match ? decodeURIComponent(match[1]) : null;
}

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    [
      `txg_session=${encodeURIComponent(token)}`,
      "HttpOnly",
      "Secure",
      "SameSite=Strict",
      "Path=/",
      `Max-Age=${SESSION_TTL}`
    ].join("; ")
  );
}

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    [
      "txg_session=",
      "HttpOnly",
      "Secure",
      "SameSite=Strict",
      "Path=/",
      "Max-Age=0"
    ].join("; ")
  );
}

async function requireAuth(req, res) {
  const token = getCookieToken(req);
  const valid = await validateSession(token);

  if (!valid) {
    res.status(401).json({
      ok: false,
      error: "Unauthorized"
    });

    return null;
  }

  return token;
}

function getClientIP(req) {
  const forwarded = req.headers["x-forwarded-for"];

  if (forwarded) {
    return String(forwarded).split(",")[0].trim();
  }

  return req.socket?.remoteAddress || "unknown";
}

async function loginRateLimit(ip) {
  const safeIP = crypto
    .createHash("sha256")
    .update(ip)
    .digest("hex");

  const key = `txg:login:${safeIP}`;

  const count = await redis.incr(key);

  if (count === 1) {
    await redis.expire(key, LOGIN_WINDOW);
  }

  return count <= LOGIN_LIMIT;
}

module.exports = {
  redis,
  checkPassword,
  changePassword,
  createSession,
  destroySession,
  getCookieToken,
  setSessionCookie,
  clearSessionCookie,
  requireAuth,
  getClientIP,
  loginRateLimit
};
