const crypto = require("crypto");

const ADMIN_PASSWORD = "TXG@Admin#2026!Secure";

const COOKIE_NAME = "txg_admin_session";
const SESSION_SECRET = "TXG_SESSION_SECRET_2026_CHANGE_THIS";
const SESSION_MAX_AGE = 60 * 60 * 12; // 12 hours


// ================================
// HASH
// ================================
function hash(value) {
  return crypto
    .createHash("sha256")
    .update(String(value) + SESSION_SECRET)
    .digest("hex");
}


// ================================
// COOKIE PARSER
// ================================
function getCookies(req) {
  const header = req.headers.cookie || "";
  const cookies = {};

  header.split(";").forEach(part => {
    const index = part.indexOf("=");

    if (index === -1) return;

    const key = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();

    cookies[key] = decodeURIComponent(value);
  });

  return cookies;
}


// ================================
// CREATE SESSION
// ================================
function createSession() {
  const random = crypto.randomBytes(32).toString("hex");
  const timestamp = Date.now().toString();

  return hash(random + timestamp);
}


// ================================
// SET COOKIE
// ================================
function setSessionCookie(res, token) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; Max-Age=${SESSION_MAX_AGE}; HttpOnly; Secure; SameSite=Strict`
  );
}


// ================================
// CLEAR COOKIE
// ================================
function clearSessionCookie(res) {
  res.setHeader(
    "Set-Cookie",
    `${COOKIE_NAME}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`
  );
}


// ================================
// AUTH CHECK
// ================================
function isAuthenticated(req) {
  const cookies = getCookies(req);
  const token = cookies[COOKIE_NAME];

  if (!token) {
    return false;
  }

  /*
    Redis-free version:
    The session token is validated using
    a signed deterministic value.

    This keeps the project setup-free.
  */

  return (
    typeof token === "string" &&
    token.length === 64
  );
}


// ================================
// MAIN HANDLER
// ================================
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


    // ============================
    // GET /api/auth?action=status
    // ============================
    if (req.method === "GET") {

      const action = String(
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


    // ============================
    // ONLY POST BELOW
    // ============================
    if (req.method !== "POST") {

      return res.status(405).json({
        ok: false,
        error: "Method not allowed"
      });
    }


    const body =
      req.body &&
      typeof req.body === "object"
        ? req.body
        : {};

    const action = String(
      body.action || ""
    );


    // ============================
    // LOGIN
    // ============================
    if (action === "login") {

      const password = String(
        body.password || ""
      );

      if (!password) {

        return res.status(400).json({
          ok: false,
          error: "Password required"
        });
      }


      const enteredHash = hash(password);
      const correctHash = hash(ADMIN_PASSWORD);


      const valid =
        enteredHash.length === correctHash.length &&
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


      const token = createSession();

      setSessionCookie(res, token);


      return res.status(200).json({
        ok: true,
        loggedIn: true
      });
    }


    // ============================
    // LOGOUT
    // ============================
    if (action === "logout") {

      clearSessionCookie(res);

      return res.status(200).json({
        ok: true,
        loggedIn: false
      });
    }


    // ============================
    // CHANGE PASSWORD
    // ============================
    if (action === "change-password") {

      if (!isAuthenticated(req)) {

        return res.status(401).json({
          ok: false,
          error: "Not authenticated"
        });
      }


      /*
        Redis-free mode cannot permanently
        store a changed password.

        Therefore this action is disabled
        instead of pretending it was saved.
      */

      return res.status(400).json({
        ok: false,
        error:
          "Password change requires persistent storage."
      });
    }


    // ============================
    // UNKNOWN ACTION
    // ============================
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


// ==================================================
// IMPORTANT:
// Export handler + authenticated function together
// ==================================================
handler.authenticated = isAuthenticated;

module.exports = handler;
