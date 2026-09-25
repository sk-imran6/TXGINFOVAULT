const {
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
} = require("../lib/auth");

function securityHeaders(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
}

function sameOrigin(req) {
  const origin = req.headers.origin;

  if (!origin) {
    return true;
  }

  const host = req.headers.host;

  try {
    return new URL(origin).host === host;
  } catch {
    return false;
  }
}

module.exports = async function handler(req, res) {
  securityHeaders(res);

  if (!sameOrigin(req)) {
    return res.status(403).json({
      ok: false,
      error: "Invalid origin"
    });
  }

  const action = req.query.action;

  try {
    if (req.method === "POST" && action === "login") {
      const ip = getClientIP(req);

      if (!(await loginRateLimit(ip))) {
        return res.status(429).json({
          ok: false,
          error: "Too many login attempts. Try again later."
        });
      }

      const password = String(req.body?.password || "");

      if (!password) {
        return res.status(400).json({
          ok: false,
          error: "Password required"
        });
      }

      const valid = await checkPassword(password);

      if (!valid) {
        return res.status(401).json({
          ok: false,
          error: "Invalid password"
        });
      }

      const token = await createSession();

      setSessionCookie(res, token);

      return res.status(200).json({
        ok: true
      });
    }

    if (req.method === "POST" && action === "logout") {
      const token = getCookieToken(req);

      await destroySession(token);
      clearSessionCookie(res);

      return res.status(200).json({
        ok: true
      });
    }

    if (req.method === "GET" && action === "status") {
      const token = getCookieToken(req);
      const valid = await requireAuth(req, res);

      if (!valid) {
        return;
      }

      return res.status(200).json({
        ok: true,
        loggedIn: true
      });
    }

    if (req.method === "POST" && action === "change-password") {
      const token = await requireAuth(req, res);

      if (!token) {
        return;
      }

      const currentPassword = String(
        req.body?.currentPassword || ""
      );

      const newPassword = String(
        req.body?.newPassword || ""
      );

      if (!currentPassword || !newPassword) {
        return res.status(400).json({
          ok: false,
          error: "Both passwords are required"
        });
      }

      if (newPassword.length < 10) {
        return res.status(400).json({
          ok: false,
          error: "New password must contain at least 10 characters"
        });
      }

      const currentValid =
        await checkPassword(currentPassword);

      if (!currentValid) {
        return res.status(401).json({
          ok: false,
          error: "Current password is incorrect"
        });
      }

      await changePassword(newPassword);
      clearSessionCookie(res);

      return res.status(200).json({
        ok: true,
        message: "Password changed. Please log in again."
      });
    }

    return res.status(404).json({
      ok: false,
      error: "Unknown action"
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      ok: false,
      error: "Server error"
    });
  }
};
