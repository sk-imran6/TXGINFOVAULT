const crypto = require("crypto");

const ADMIN_PASSWORD = "TXG@Admin#2026!Secure";

const COOKIE_NAME = "txg_admin_session";

const SESSION_SECRET =
  "TXG_INFORMATION_CENTER_SESSION_SECRET_2026_9F7A3B2C";

const SESSION_MAX_AGE = 60 * 60 * 12;


// ==========================================
// HASH
// ==========================================

function sha256(value) {
  return crypto
    .createHash("sha256")
    .update(String(value))
    .digest("hex");
}


// ==========================================
// HMAC
// ==========================================

function sign(value) {
  return crypto
    .createHmac("sha256", SESSION_SECRET)
    .update(value)
    .digest("hex");
}


// ==========================================
// CREATE SESSION
// ==========================================

function createSession() {
  const payload = {
    iat: Date.now(),
    exp: Date.now() + SESSION_MAX_AGE * 1000,
    random: crypto.randomBytes(24).toString("hex")
  };

  const encoded = Buffer
    .from(JSON.stringify(payload))
    .toString("base64url");

  const signature = sign(encoded);

  return `${encoded}.${signature}`;
}


// ==========================================
// GET COOKIE
// ==========================================

function getCookie(req, name) {
  const cookieHeader = req.headers.cookie || "";

  const parts = cookieHeader.split(";");

  for (const part of parts) {
    const index = part.indexOf("=");

    if (index === -1) continue;

    const key = part
      .slice(0, index)
      .trim();

    const value = part
      .slice(index + 1)
      .trim();

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return null;
}


// ==========================================
// VERIFY SESSION
// ==========================================

function isAuthenticated(req) {
  try {
    const token = getCookie(
      req,
      COOKIE_NAME
    );

    if (!token) {
      return false;
    }

    const parts = token.split(".");

    if (parts.length !== 2) {
      return false;
    }

    const encoded = parts[0];
    const receivedSignature = parts[1];

    const expectedSignature = sign(encoded);

    if (
      receivedSignature.length !==
      expectedSignature.length
    ) {
      return false;
    }

    if (
      !crypto.timingSafeEqual(
        Buffer.from(receivedSignature),
        Buffer.from(expectedSignature)
      )
    ) {
      return false;
    }

    const payload = JSON.parse(
      Buffer
        .from(encoded, "base64url")
        .toString("utf8")
    );

    if (!payload.exp) {
      return false;
    }

    if (Date.now() > Number(payload.exp)) {
      return false;
    }

    return true;

  } catch (error) {
    console.error(
      "SESSION VERIFY ERROR:",
      error
    );

    return false;
  }
}


// ==========================================
// SET SESSION COOKIE
// ==========================================

function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Lax`
  );
}


// ==========================================
// CLEAR SESSION COOKIE
// ==========================================

function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Lax`
  );
}


// ==========================================
// MAIN API
// ==========================================

async function handler(req, res) {

  try {

    res.setHeader(
      "Content-Type",
      "application/json; charset=utf-8"
    );

    res.setHeader(
      "Cache-Control",
      "no-store"
    );


    // ========================================
    // STATUS
    // ========================================

    if (req.method === "GET") {

      const action =
        String(
          req.query?.action || "status"
        );

      if (action === "status") {

        return res.status(200).json({
          ok: true,
          loggedIn: isAuthenticated(req)
        });

      }

      return res.status(400).json({
        ok: false,
        error: "Unknown action"
      });
    }


    // ========================================
    // METHOD
    // ========================================

    if (req.method !== "POST") {

      return res.status(405).json({
        ok: false,
        error: "Method not allowed"
      });
    }


    // ========================================
    // BODY
    // ========================================

    let body = req.body;

    if (
      !body ||
      typeof body !== "object"
    ) {
      body = {};
    }


    const action =
      String(body.action || "");


    // ========================================
    // LOGIN
    // ========================================

    if (action === "login") {

      const password =
        String(body.password || "");

      if (!password) {

        return res.status(400).json({
          ok: false,
          error: "Password required"
        });
      }


      const enteredHash =
        sha256(password);

      const correctHash =
        sha256(ADMIN_PASSWORD);


      const valid =
        enteredHash.length ===
          correctHash.length &&
        crypto.timingSafeEqual(
          Buffer.from(enteredHash),
          Buffer.from(correctHash)
        );


      if (!valid) {

        return res.status(401).json({
          ok: false,
          error: "Invalid password"
        });
      }


      const token =
        createSession();


      setSessionCookie(
        res,
        token
      );


      return res.status(200).json({
        ok: true,
        loggedIn: true
      });
    }


    // ========================================
    // LOGOUT
    // ========================================

    if (action === "logout") {

      clearSessionCookie(res);

      return res.status(200).json({
        ok: true,
        loggedIn: false
      });
    }


    // ========================================
    // AUTH CHECK
    // ========================================

    if (action === "check") {

      return res.status(200).json({
        ok: true,
        loggedIn:
          isAuthenticated(req)
      });
    }


    // ========================================
    // UNKNOWN
    // ========================================

    return res.status(400).json({
      ok: false,
      error: "Unknown action"
    });

  } catch (error) {

    console.error(
      "AUTH ERROR:",
      error
    );

    return res.status(500).json({
      ok: false,
      error: "Authentication server error",
      details:
        error?.message ||
        "Unknown error"
    });
  }
}


// ==========================================
// IMPORTANT EXPORT
// ==========================================

handler.authenticated =
  isAuthenticated;

module.exports = handler;
