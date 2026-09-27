const crypto = require("crypto");

const COOKIE_NAME = "txg_admin_session";
const FALLBACK_SECRET = "TXG-INFORMATION-AUTH-2026-CHANGE-ME";
const SESSION_HOURS = 12;

function getSecret() {
  return process.env.AUTH_SECRET || FALLBACK_SECRET;
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || "";

  for (const part of cookie.split(";")) {
    const item = part.trim();
    const i = item.indexOf("=");

    if (i === -1) continue;

    if (item.slice(0, i) === name) {
      return decodeURIComponent(item.slice(i + 1));
    }
  }

  return "";
}

function authenticated(req) {
  try {
    const token = getCookie(req, COOKIE_NAME);

    if (!token) return false;

    const parts = token.split(".");

    if (parts.length !== 3) return false;

    const user = parts[0];
    const timestamp = Number(parts[1]);
    const signature = parts[2];

    if (!user || !Number.isFinite(timestamp) || !signature) {
      return false;
    }

    const age = Date.now() - timestamp;

    if (age < 0 || age > SESSION_HOURS * 60 * 60 * 1000) {
      return false;
    }

    const expected = crypto
      .createHmac("sha256", getSecret())
      .update(user + "." + timestamp)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch (e) {
    return false;
  }
}

function getDatabase() {
  const { neon } = require("@neondatabase/serverless");

  const url =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.STORAGE_DATABASE_URL ||
    process.env.STORAGE_POSTGRES_URL;

  if (!url) {
    throw new Error("Neon database URL is not configured.");
  }

  return neon(url);
}

async function setupTable(sql) {

  await sql`
    CREATE TABLE IF NOT EXISTS custom_apis (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      method TEXT NOT NULL DEFAULT 'GET',
      description TEXT DEFAULT '',
      category TEXT DEFAULT 'Custom API',
      api_key TEXT DEFAULT '',
      api_header TEXT DEFAULT 'Authorization',
      created_at TIMESTAMPTZ DEFAULT NOW()
    )
  `;

  await sql`
    ALTER TABLE custom_apis
    ADD COLUMN IF NOT EXISTS api_key TEXT DEFAULT ''
  `;

  await sql`
    ALTER TABLE custom_apis
    ADD COLUMN IF NOT EXISTS api_header TEXT DEFAULT 'Authorization'
  `;
}

function clean(value, max) {
  return String(value || "")
    .replace(/[\r\n]/g, "")
    .trim()
    .slice(0, max || 5000);
}

async function handler(req, res) {

  try {

    if (!authenticated(req)) {
      return res.status(401).json({
        success: false,
        error: "Unauthorized"
      });
    }

    const sql = getDatabase();

    await setupTable(sql);

    // ==========================
    // GET SAVED APIs
    // ==========================

    if (req.method === "GET") {

      const rows = await sql`
        SELECT
          id,
          name,
          url,
          method,
          description,
          category,
          api_header,
          created_at
        FROM custom_apis
        ORDER BY id ASC
      `;

      return res.status(200).json({
        success: true,
        apis: rows
      });
    }

    // ==========================
    // SAVE API
    // ==========================

    if (req.method === "POST") {

      const body = req.body || {};

      const name = clean(body.name, 100);
      const url = clean(body.url, 3000);
      const method = clean(
        body.method || "GET",
        10
      ).toUpperCase();

      const description = clean(
        body.description,
        500
      );

      const category = clean(
        body.category || "Custom API",
        100
      );

      const apiKey = clean(
        body.api_key,
        3000
      );

      const apiHeader = clean(
        body.api_header || "Authorization",
        200
      );

      if (!name) {
        return res.status(400).json({
          success: false,
          error: "API name is required."
        });
      }

      if (!/^https?:\/\/.+/i.test(url)) {
        return res.status(400).json({
          success: false,
          error: "Enter a valid HTTP/HTTPS API URL."
        });
      }

      if (
        ![
          "GET",
          "POST",
          "PUT",
          "PATCH",
          "DELETE"
        ].includes(method)
      ) {
        return res.status(400).json({
          success: false,
          error: "Invalid HTTP method."
        });
      }

      const rows = await sql`
        INSERT INTO custom_apis
        (
          name,
          url,
          method,
          description,
          category,
          api_key,
          api_header
        )
        VALUES
        (
          ${name},
          ${url},
          ${method},
          ${description},
          ${category},
          ${apiKey},
          ${apiHeader}
        )
        RETURNING
          id,
          name,
          url,
          method,
          description,
          category,
          api_header,
          created_at
      `;

      return res.status(201).json({
        success: true,
        message: "API saved successfully.",
        api: rows[0]
      });
    }

    // ==========================
    // DELETE API
    // ==========================

    if (req.method === "DELETE") {

      const body = req.body || {};
      const id = Number(body.id);

      if (!Number.isInteger(id) || id <= 0) {
        return res.status(400).json({
          success: false,
          error: "Invalid API ID."
        });
      }

      await sql`
        DELETE FROM custom_apis
        WHERE id = ${id}
      `;

      return res.status(200).json({
        success: true,
        message: "API removed."
      });
    }

    return res.status(405).json({
      success: false,
      error: "Method not allowed."
    });

  } catch (error) {

    console.error(
      "CUSTOM API ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        error.message ||
        "Custom API server error."
    });
  }
}

module.exports = handler;
