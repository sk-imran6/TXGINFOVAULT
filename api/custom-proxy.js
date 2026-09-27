// api/custom-proxy.js

const dns = require("dns").promises;

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);

  if (p.length !== 4 || p.some(Number.isNaN)) {
    return false;
  }

  return (
    p[0] === 10 ||
    p[0] === 127 ||
    (p[0] === 172 && p[1] >= 16 && p[1] <= 31) ||
    (p[0] === 192 && p[1] === 168) ||
    (p[0] === 169 && p[1] === 254) ||
    p[0] === 0
  );
}

function isPrivateIPv6(ip) {
  const value = ip.toLowerCase();

  return (
    value === "::1" ||
    value === "::" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe8") ||
    value.startsWith("fe9") ||
    value.startsWith("fea") ||
    value.startsWith("feb")
  );
}

function isPrivateIP(ip) {
  return isPrivateIPv4(ip) || isPrivateIPv6(ip);
}

async function hostIsPrivate(hostname) {
  const host = hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local")
  ) {
    return true;
  }

  try {
    const records = await dns.lookup(host, {
      all: true,
      verbatim: true
    });

    return records.some(record => isPrivateIP(record.address));
  } catch {
    return false;
  }
}

function replaceMessage(value, message) {
  return String(value || "").replace(
    /\{message\}/g,
    encodeURIComponent(message)
  );
}

module.exports = async function handler(req, res) {
  try {
    const id = String(req.query?.id || "").trim();
    const message = String(req.query?.message || "");

    if (!id || id === "[object Object]") {
      return res.status(400).json({
        success: false,
        error: "Valid API ID is required"
      });
    }

    if (!message.trim()) {
      return res.status(400).json({
        success: false,
        error: "Message is required"
      });
    }

    const databaseUrl =
      process.env.DATABASE_URL ||
      process.env.POSTGRES_URL ||
      process.env.STORAGE_DATABASE_URL ||
      process.env.STORAGE_POSTGRES_URL;

    if (!databaseUrl) {
      return res.status(500).json({
        success: false,
        error: "DATABASE_URL is not configured"
      });
    }

    const { neon } = require("@neondatabase/serverless");
    const sql = neon(databaseUrl);

    const rows = await sql`
      SELECT id, name, url, method
      FROM custom_apis
      WHERE id = ${id}
      LIMIT 1
    `;

    if (!rows.length) {
      return res.status(404).json({
        success: false,
        error: "API not found"
      });
    }

    const api = rows[0];

    let targetUrl = replaceMessage(api.url, message);

    let parsed;

    try {
      parsed = new URL(targetUrl);
    } catch {
      return res.status(400).json({
        success: false,
        error: "Saved API URL is invalid"
      });
    }

    if (parsed.protocol !== "https:") {
      return res.status(400).json({
        success: false,
        error: "Only HTTPS APIs are allowed"
      });
    }

    if (await hostIsPrivate(parsed.hostname)) {
      return res.status(400).json({
        success: false,
        error: "Private network targets are not allowed"
      });
    }

    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, 15000);

    try {
      const headers = {
        Accept: "application/json, text/plain, */*",
        "User-Agent": "TXG-Information/1.0"
      };

      if (
        process.env.CUSTOM_API_KEY &&
        process.env.CUSTOM_API_HEADER
      ) {
        headers[process.env.CUSTOM_API_HEADER] =
          process.env.CUSTOM_API_KEY;
      }

      const options = {
        method: api.method,
        headers,
        signal: controller.signal
      };

      if (
        ["POST", "PUT", "PATCH"].includes(api.method)
      ) {
        options.headers["Content-Type"] =
          "application/json";

        options.body = JSON.stringify({
          message
        });
      }

      const response = await fetch(
        targetUrl,
        options
      );

      const contentType =
        response.headers.get("content-type") || "";

      let data;

      if (contentType.includes("application/json")) {
        try {
          data = await response.json();
        } catch {
          data = await response.text();
        }
      } else {
        data = await response.text();
      }

      return res.status(200).json({
        success: true,
        api: {
          id: api.id,
          name: api.name,
          method: api.method
        },
        request: {
          message
        },
        response: {
          status: response.status,
          ok: response.ok,
          data
        }
      });

    } finally {
      clearTimeout(timeout);
    }

  } catch (error) {
    console.error("custom-proxy:", error);

    if (error.name === "AbortError") {
      return res.status(504).json({
        success: false,
        error: "API request timed out"
      });
    }

    return res.status(500).json({
      success: false,
      error: error.message || "Proxy request failed"
    });
  }
};
