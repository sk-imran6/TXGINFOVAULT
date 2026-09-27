const crypto = require("crypto");

const COOKIE_NAME = "txg_admin_session";
const FALLBACK_SECRET = "TXG-INFORMATION-AUTH-2026-CHANGE-ME";
const SESSION_HOURS = 12;
const TIMEOUT = 15000;
const MAX_BODY = 1024 * 1024;

function getSecret() {
  return process.env.AUTH_SECRET || FALLBACK_SECRET;
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || "";
  const parts = cookie.split(";");

  for (const part of parts) {
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

function json(res, status, data) {
  return res.status(status).json(data);
}

function isPrivateHost(hostname) {
  const host = String(hostname || "").toLowerCase();

  if (
    host === "localhost" ||
    host === "localhost.localdomain" ||
    host === "metadata.google.internal" ||
    host === "metadata.google" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    return true;
  }

  // IPv4 private/reserved ranges
  const match = host.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);

  if (match) {
    const a = Number(match[1]);
    const b = Number(match[2]);

    if (a === 10) return true;
    if (a === 127) return true;
    if (a === 169 && b === 254) return true;
    if (a === 172 && b >= 16 && b <= 31) return true;
    if (a === 192 && b === 168) return true;
    if (a === 0) return true;
  }

  // IPv6 localhost/private/link-local basics
  if (
    host === "::1" ||
    host.startsWith("fc") ||
    host.startsWith("fd") ||
    host.startsWith("fe80:")
  ) {
    return true;
  }

  return false;
}

function replaceVariables(value, params) {
  return String(value || "")
    .replace(/\{message\}/gi, encodeURIComponent(params.message || ""))
    .replace(/\{value\}/gi, encodeURIComponent(params.value || ""))
    .replace(/\{query\}/gi, encodeURIComponent(params.query || ""));
}

function cleanHeaderName(name) {
  return String(name || "")
    .replace(/[\r\n]/g, "")
    .trim();
}

function cleanHeaderValue(value) {
  return String(value || "")
    .replace(/[\r\n]/g, "")
    .trim();
}

function safeJsonParse(value) {
  try {
    if (!value) return {};
    const parsed = JSON.parse(value);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (e) {
    return {};
  }
}

function responseBodyToJson(text, contentType) {
  if (!text) return null;

  if (
    String(contentType || "")
      .toLowerCase()
      .includes("application/json")
  ) {
    try {
      return JSON.parse(text);
    } catch (e) {
      return text;
    }
  }

  try {
    return JSON.parse(text);
  } catch (e) {
    return text;
  }
}

async function requestWithTimeout(url, options) {
  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, TIMEOUT);

  try {
    return await fetch(url, {
      ...options,
      signal: controller.signal,
      redirect: "follow"
    });
  } finally {
    clearTimeout(timer);
  }
}

async function getApiById(id) {
  let sql;

  try {
    const { neon } = require("@neondatabase/serverless");

    const databaseUrl =
      process.env.DATABASE_URL ||
      process.env.POSTGRES_URL ||
      process.env.STORAGE_DATABASE_URL ||
      process.env.STORAGE_POSTGRES_URL;

    if (!databaseUrl) {
      throw new Error("Database connection is not configured.");
    }

    sql = neon(databaseUrl);

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

    // Safe upgrades for an older table
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

    const rows = await sql`
      SELECT
        id,
        name,
        url,
        method,
        description,
        category,
        api_key,
        api_header,
        headers_json
      FROM custom_apis
      WHERE id = ${Number(id)}
      LIMIT 1
    `;

    return rows[0] || null;
  } catch (error) {
    console.error("getApiById error:", error);
    throw error;
  }
}

async function handler(req, res) {
  try {
    if (req.method !== "POST") {
      return json(res, 405, {
        success: false,
        error: "POST method required."
      });
    }

    if (!authenticated(req)) {
      return json(res, 401, {
        success: false,
        error: "Unauthorized."
      });
    }

    const body = req.body || {};

    const id = Number(body.id);

    if (!Number.isInteger(id) || id <= 0) {
      return json(res, 400, {
        success: false,
        error: "Invalid API ID."
      });
    }

    const params = {
      message: String(body.message || ""),
      value: String(body.value || ""),
      query: String(body.query || "")
    };

    const api = await getApiById(id);

    if (!api) {
      return json(res, 404, {
        success: false,
        error: "Saved API not found."
      });
    }

    let targetUrl;

    try {
      targetUrl = replaceVariables(api.url, params);
      const parsed = new URL(targetUrl);

      if (!["http:", "https:"].includes(parsed.protocol)) {
        return json(res, 400, {
          success: false,
          error: "Only HTTP and HTTPS APIs are allowed."
        });
      }

      if (isPrivateHost(parsed.hostname)) {
        return json(res, 400, {
          success: false,
          error: "Private/internal API hosts are not allowed."
        });
      }
    } catch (e) {
      return json(res, 400, {
        success: false,
        error: "Saved API URL is invalid."
      });
    }

    const method = String(api.method || "GET").toUpperCase();

    if (!["GET", "POST", "PUT", "PATCH", "DELETE"].includes(method)) {
      return json(res, 400, {
        success: false,
        error: "Unsupported API method."
      });
    }

    const headers = {
      Accept: "application/json, text/plain, */*",
      "User-Agent": "TXG-Information-Center/1.0"
    };

    // Saved custom headers
    const extraHeaders = safeJsonParse(api.headers_json);

    for (const key of Object.keys(extraHeaders)) {
      const headerName = cleanHeaderName(key);

      if (!headerName) continue;

      headers[headerName] = cleanHeaderValue(extraHeaders[key]);
    }

    // API key
    if (api.api_key) {
      const headerName = cleanHeaderName(
        api.api_header || "Authorization"
      );

      if (headerName) {
        let keyValue = String(api.api_key);

        // Authorization automatically becomes Bearer KEY
        if (headerName.toLowerCase() === "authorization") {
          if (
            !/^bearer\s+/i.test(keyValue) &&
            !/^basic\s+/i.test(keyValue)
          ) {
            keyValue = "Bearer " + keyValue;
          }
        }

        headers[headerName] = cleanHeaderValue(keyValue);
      }
    }

    const options = {
      method,
      headers
    };

    if (["POST", "PUT", "PATCH"].includes(method)) {
      headers["Content-Type"] = "application/json";

      options.body = JSON.stringify({
        message: params.message,
        value: params.value,
        query: params.query
      });
    }

    const response = await requestWithTimeout(targetUrl, options);

    const contentType =
      response.headers.get("content-type") || "";

    const text = await response.text();

    if (text.length > MAX_BODY) {
      return json(res, 502, {
        success: false,
        error: "API response is too large."
      });
    }

    const data = responseBodyToJson(text, contentType);

    return json(res, 200, {
      success: response.ok,
      status: response.status,
      status_text: response.statusText,
      api: {
        id: api.id,
        name: api.name
      },
      data
    });
  } catch (error) {
    console.error("custom-proxy error:", error);

    return json(res, 500, {
      success: false,
      error:
        error.name === "AbortError"
          ? "API request timed out."
          : error.message || "Proxy request failed."
    });
  }
}

module.exports = handler;
