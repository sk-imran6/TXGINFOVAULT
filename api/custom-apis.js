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
    const index = item.indexOf("=");

    if (index === -1) continue;

    const key = item.slice(0, index);
    const value = item.slice(index + 1);

    if (key === name) {
      return decodeURIComponent(value);
    }
  }

  return "";
}

function verifySession(token) {
  try {
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

    const data = user + "." + timestamp;

    const expected = crypto
      .createHmac("sha256", getSecret())
      .update(data)
      .digest("hex");

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch (e) {
    return false;
  }
}

function authenticated(req) {
  return verifySession(getCookie(req, COOKIE_NAME));
}

function database() {
  const { neon } = require("@neondatabase/serverless");

  const databaseUrl =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.STORAGE_DATABASE_URL ||
    process.env.STORAGE_POSTGRES_URL;

  if (!databaseUrl) {
    throw new Error("Database connection is not configured.");
  }

  return neon(databaseUrl);
}

async function ensureTable(sql) {
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
      headers_json TEXT DEFAULT '{}',
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

  await sql`
    ALTER TABLE custom_apis
    ADD COLUMN IF NOT EXISTS headers_json TEXT DEFAULT '{}'
  `;
}

function validUrl(value) {
  try {
    const url = new URL(value);

    return (
      url.protocol === "http:" ||
      url.protocol === "https:"
    );
  } catch (e) {
    return false;
  }
}

function clean(value, max = 5000) {
  return String(value || "")
    .replace(/[\r\n]/g, "")
    .trim()
    .slice(0, max);
}

async function handler(req, res) {
  try {
    if (!authenticated(req)) {
      return res.status(401).json({
        success: false,
        error: "Unauthorized."
      });
    }

    const sql = database();

    await ensureTable(sql);

    // =========================
    // GET
    // =========================

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

    // =========================
    // POST
    // =========================

    if (req.method === "POST") {
      const body = req.body || {};

      const name = clean(body.name, 100);
      const url = clean(body.url, 2000);
      const method = clean(body.method || "GET", 10).toUpperCase();
      const description = clean(body.description, 500);
      const category = clean(body.category || "Custom API", 100);
      const apiKey = clean(body.api_key, 2000);
      const apiHeader = clean(
        body.api_header || "Authorization",
        200
      );

      let headersJson = "{}";

      if (body.headers_json) {
        try {
          const parsed =
            typeof body.headers_json === "string"
              ? JSON.parse(body.headers_json)
              : body.headers_json;

          if (
            !parsed ||
            typeof parsed !== "object" ||
            Array.isArray(parsed)
          ) {
            throw new Error("Headers must be an object.");
          }

          headersJson = JSON.stringify(parsed);
        } catch (e) {
          return res.status(400).json({
            success: false,
            error: "Invalid extra headers JSON."
          });
        }
      }

      if (!name) {
        return res.status(400).json({
          success: false,
          error: "API name is required."
        });
      }

      if (!validUrl(url)) {
        return res.status(400).json({
          success: false,
          error: "Valid HTTP/HTTPS URL is required."
        });
      }

      if (
        !["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)
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
          api_header,
          headers_json
        )
        VALUES
        (
          ${name},
          ${url},
          ${method},
          ${description},
          ${category},
          ${apiKey},
          ${apiHeader},
          ${headersJson}
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
        api: rows[0]
      });
    }

    // =========================
    // DELETE
    // =========================

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
    console.error("custom-apis error:", error);

    return res.status(500).json({
      success: false,
      error: error.message || "Custom API server error."
    });
  }
}

module.exports = handler;
