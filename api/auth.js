const {
  redis,
  PASSWORD_KEY,
  hashPassword,
  ensurePassword,
  isAuthenticated,
  createSession,
  deleteSession,
  sessionCookie,
  clearSessionCookie
} = require("../lib/auth");

module.exports = async (req, res) => {
  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      message: "POST required"
    });
  }

  try {
    const action = String(
      req.body?.action || ""
    );

    // ==============================
    // LOGIN
    // ==============================

    if (action === "login") {
      const password = String(
        req.body?.password || ""
      );

      if (!password) {
        return res.status(400).json({
          ok: false,
          message: "Password required"
        });
      }

      const savedHash =
        await ensurePassword();

      if (
        hashPassword(password) !==
        savedHash
      ) {
        return res.status(401).json({
          ok: false,
          message: "Wrong password"
        });
      }

      const token =
        await createSession();

      res.setHeader(
        "Set-Cookie",
        sessionCookie(token)
      );

      return res.status(200).json({
        ok: true,
        message: "Login successful"
      });
    }

    // ==============================
    // STATUS
    // ==============================

    if (action === "status") {
      const loggedIn =
        await isAuthenticated(req);

      return res.status(200).json({
        ok: true,
        loggedIn
      });
    }

    // ==============================
    // LOGOUT
    // ==============================

    if (action === "logout") {
      await deleteSession(req);

      res.setHeader(
        "Set-Cookie",
        clearSessionCookie()
      );

      return res.status(200).json({
        ok: true
      });
    }

    // ==============================
    // CHANGE PASSWORD
    // ==============================

    if (action === "change-password") {
      const loggedIn =
        await isAuthenticated(req);

      if (!loggedIn) {
        return res.status(401).json({
          ok: false,
          message: "Login required"
        });
      }

      const oldPassword = String(
        req.body?.oldPassword || ""
      );

      const newPassword = String(
        req.body?.newPassword || ""
      );

      if (
        !oldPassword ||
        !newPassword
      ) {
        return res.status(400).json({
          ok: false,
          message:
            "Old and new password required"
        });
      }

      if (newPassword.length < 8) {
        return res.status(400).json({
          ok: false,
          message:
            "New password must be at least 8 characters"
        });
      }

      const currentHash =
        await ensurePassword();

      if (
        hashPassword(oldPassword) !==
        currentHash
      ) {
        return res.status(401).json({
          ok: false,
          message:
            "Old password is incorrect"
        });
      }

      await redis.set(
        PASSWORD_KEY,
        hashPassword(newPassword)
      );

      await deleteSession(req);

      res.setHeader(
        "Set-Cookie",
        clearSessionCookie()
      );

      return res.status(200).json({
        ok: true,
        message:
          "Password changed. Login again."
      });
    }

    return res.status(400).json({
      ok: false,
      message: "Invalid action"
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      ok: false,
      message: "Authentication server error"
    });
  }
};
