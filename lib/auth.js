const crypto = require("crypto");
const { Redis } = require("@upstash/redis");

const redis = Redis.fromEnv();

const PASSWORD_KEY = "txg:admin:password";
const SESSION_PREFIX = "txg:session:";
const SESSION_TTL = 60 * 60 * 12;

const DEFAULT_PASSWORD = "TXG@Admin#2026!Secure";

function hashPassword(password) {
  return crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");
}

function createToken() {
  return crypto.randomBytes(32).toString("hex");
}

function getCookie(req, name) {
  const cookies = req.headers.cookie || "";

  const parts = cookies.split(";");

  for (const part of parts) {
    const item = part.trim();

    if (!item.startsWith(name + "=")) continue;

    return decodeURIComponent(
      item.substring(name.length + 1)
    );
  }

  return null;
}

async function ensurePassword() {
  let passwordHash = await redis.get(PASSWORD_KEY);

  if (!passwordHash) {
    passwordHash = hashPassword(DEFAULT_PASSWORD);

    await redis.set(
      PASSWORD_KEY,
      passwordHash
    );
  }

  return passwordHash;
}

async function isAuthenticated(req) {
  const token = getCookie(
    req,
    "txg_session"
  );

  if (!token) return false;

  const session = await redis.get(
    SESSION_PREFIX + token
  );

  return !!session;
}

async function createSession() {
  const token = createToken();

  await redis.set(
    SESSION_PREFIX + token,
    "authenticated",
    {
      ex: SESSION_TTL
    }
  );

  return token;
}

async function deleteSession(req) {
  const token = getCookie(
    req,
    "txg_session"
  );

  if (token) {
    await redis.del(
      SESSION_PREFIX + token
    );
  }
}

function sessionCookie(token) {
  return [
    `txg_session=${encodeURIComponent(token)}`,
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    `Max-Age=${SESSION_TTL}`
  ].join("; ");
}

function clearSessionCookie() {
  return [
    "txg_session=",
    "Path=/",
    "HttpOnly",
    "Secure",
    "SameSite=Strict",
    "Max-Age=0"
  ].join("; ");
}

module.exports = {
  redis,
  PASSWORD_KEY,
  DEFAULT_PASSWORD,
  SESSION_PREFIX,
  hashPassword,
  ensurePassword,
  isAuthenticated,
  createSession,
  deleteSession,
  sessionCookie,
  clearSessionCookie,
  getCookie
};
