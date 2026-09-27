const crypto = require("crypto");

const COOKIE_NAME = "txg_admin_session";
const FALLBACK_SECRET = "TXG-INFORMATION-AUTH-2026-CHANGE-ME";
const SESSION_HOURS = 12;
const TIMEOUT = 15000;

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
      return decodeURIComponent(
        item.slice(i + 1)
      );
    }
  }

  return "";
}

function authenticated(req) {

  try {

    const token =
      getCookie(req, COOKIE_NAME);

    if (!token) return false;

    const parts =
      token.split(".");

    if (parts.length !== 3) {
      return false;
    }

    const user = parts[0];
    const timestamp = Number(parts[1]);
    const signature = parts[2];

    if (
      !user ||
      !Number.isFinite(timestamp) ||
      !signature
    ) {
      return false;
    }

    const age =
      Date.now() - timestamp;

    if (
      age < 0 ||
      age >
        SESSION_HOURS *
        60 *
        60 *
        1000
    ) {
      return false;
    }

    const expected =
      crypto
        .createHmac(
          "sha256",
          getSecret()
        )
        .update(
          user + "." + timestamp
        )
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

  const { neon } =
    require("@neondatabase/serverless");

  const url =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.STORAGE_DATABASE_URL ||
    process.env.STORAGE_POSTGRES_URL;

  if (!url) {
    throw new Error(
      "Neon database URL is not configured."
    );
  }

  return neon(url);
}

async function getApi(sql, id) {

  const rows = await sql`
    SELECT
      id,
      name,
      url,
      method,
      api_key,
      api_header
    FROM custom_apis
    WHERE id = ${id}
    LIMIT 1
  `;

  return rows[0] || null;
}

function replaceMessage(url, message) {

  /*
   * ONLY {message} is replaced.
   */

  return String(url).replace(
    /\{message\}/gi,
    encodeURIComponent(message)
  );
}

async function handler(req, res) {

  try {

    if (req.method !== "POST") {
      return res.status(405).json({
        success: false,
        error: "POST required."
      });
    }

    if (!authenticated(req)) {
      return res.status(401).json({
        success: false,
        error: "Unauthorized."
      });
    }

    const body = req.body || {};

    const id = Number(body.id);

    const message =
      String(body.message || "");

    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {
      return res.status(400).json({
        success: false,
        error: "Invalid API ID."
      });
    }

    if (!message.trim()) {
      return res.status(400).json({
        success: false,
        error: "Message is empty."
      });
    }

    const sql = getDatabase();

    const api =
      await getApi(sql, id);

    if (!api) {
      return res.status(404).json({
        success: false,
        error: "Saved API not found."
      });
    }

    /*
     * Example:
     *
     * https://example.com/search?query={message}
     *
     * becomes:
     *
     * https://example.com/search?query=hello
     */

    const targetUrl =
      replaceMessage(
        api.url,
        message
      );

    let parsed;

    try {

      parsed =
        new URL(targetUrl);

    } catch (e) {

      return res.status(400).json({
        success: false,
        error: "Saved API URL is invalid."
      });
    }

    if (
      parsed.protocol !== "https:" &&
      parsed.protocol !== "http:"
    ) {
      return res.status(400).json({
        success: false,
        error:
          "Only HTTP/HTTPS URLs are allowed."
      });
    }

    const headers = {
      "Accept":
        "application/json, text/plain, */*",
      "User-Agent":
        "TXG-Information-Center"
    };

    /*
     * API KEY
     */

    if (api.api_key) {

      const header =
        api.api_header ||
        "Authorization";

      let key =
        String(api.api_key);

      if (
        header.toLowerCase() ===
          "authorization" &&
        !/^bearer\s/i.test(key) &&
        !/^basic\s/i.test(key)
      ) {
        key =
          "Bearer " + key;
      }

      headers[header] = key;
    }

    const method =
      String(api.method || "GET")
        .toUpperCase();

    const controller =
      new AbortController();

    const timeout =
      setTimeout(
        () => controller.abort(),
        TIMEOUT
      );

    let response;

    try {

      response =
        await fetch(
          targetUrl,
          {
            method,
            headers,
            signal:
              controller.signal
          }
        );

    } finally {

      clearTimeout(timeout);

    }

    /*
     * SHOW EXACT API RESPONSE
     */

    const contentType =
      response.headers.get(
        "content-type"
      ) || "";

    const responseText =
      await response.text();

    let output =
      responseText;

    /*
     * If JSON, parse it so frontend
     * can display it nicely.
     *
     * If not JSON, keep original text.
     */

    if (
      contentType
        .toLowerCase()
        .includes("application/json")
    ) {

      try {

        output =
          JSON.parse(
            responseText
          );

      } catch (e) {

        output =
          responseText;

      }

    } else {

      try {

        output =
          JSON.parse(
            responseText
          );

      } catch (e) {

        output =
          responseText;

      }

    }

    return res.status(200).json({

      success: response.ok,

      api: api.name,

      http_status:
        response.status,

      response: output

    });

  } catch (error) {

    console.error(
      "CUSTOM PROXY ERROR:",
      error
    );

    return res.status(500).json({
      success: false,
      error:
        error.name ===
        "AbortError"
          ? "API request timed out."
          : (
              error.message ||
              "API request failed."
            )
    });
  }
}

module.exports = handler;
