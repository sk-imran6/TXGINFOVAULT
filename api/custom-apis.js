// api/custom-apis.js

const crypto = require("crypto");

function getCookie(req, name) {
  const cookies = req.headers.cookie || "";

  for (const part of cookies.split(";")) {
    const [key, ...rest] = part.trim().split("=");
    if (key === name) {
      return decodeURIComponent(rest.join("="));
    }
  }

  return null;
}

function isAuthenticated(req) {
  const session = getCookie(req, "txg_admin_session");

  if (!session) return false;

  const secret =
    process.env.AUTH_SECRET ||
    "TXG-INFORMATION-AUTH-2026-CHANGE-ME";

  const [timestamp, signature] = session.split(".");

  if (!timestamp || !signature) return false;

  const time = Number(timestamp);

  if (!Number.isFinite(time)) return false;

  // 12 hours
  if (Date.now() - time > 12 * 60 * 60 * 1000) {
    return false;
  }

  const expected = crypto
    .createHmac("sha256", secret)
    .update(String(timestamp))
    .digest("hex");

  try {
    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );
  } catch {
    return false;
  }
}

function send(res, status, data) {
  res.status(status).json(data);
}

function clean(value, max = 500) {
  if (typeof value !== "string") return "";

  return value
    .trim()
    .replace(/[<>]/g, "")
    .slice(0, max);
}

function makeId() {
  return (
    Date.now().toString(36) +
    "-" +
    crypto.randomBytes(5).toString("hex")
  );
}

/*
  IMPORTANT:

  Vercel Functions are stateless.
  This file therefore uses an external Custom API storage endpoint
  when CUSTOM_API_STORE_URL is configured.

  Set these environment variables in Vercel:

  CUSTOM_API_STORE_URL=https://your-storage-api.example.com
  CUSTOM_API_STORE_KEY=your-secret-key

  Your storage API should support:

  GET    /apis
  POST   /apis
  DELETE /apis/:id

  If you haven't connected durable storage yet, GET/POST/DELETE
  will return a clear configuration error instead of pretending
  that data was permanently saved.
*/

const STORE_URL = (
  process.env.CUSTOM_API_STORE_URL || ""
).replace(/\/+$/, "");

const STORE_KEY =
  process.env.CUSTOM_API_STORE_KEY || "";

async function storeRequest(path, options = {}) {
  if (!STORE_URL) {
    throw new Error(
      "CUSTOM_API_STORE_URL is not configured."
    );
  }

  const headers = {
    "Content-Type": "application/json",
    ...(options.headers || {})
  };

  if (STORE_KEY) {
    headers["Authorization"] = `Bearer ${STORE_KEY}`;
  }

  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, 10000);

  try {
    const response = await fetch(
      `${STORE_URL}${path}`,
      {
        ...options,
        headers,
        signal: controller.signal
      }
    );

    const text = await response.text();

    let data;

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = {
        raw: text
      };
    }

    if (!response.ok) {
      throw new Error(
        data?.error ||
        data?.message ||
        `Storage API returned ${response.status}`
      );
    }

    return data;
  } finally {
    clearTimeout(timer);
  }
}

module.exports = async function handler(req, res) {
  res.setHeader(
    "Cache-Control",
    "no-store, no-cache, must-revalidate"
  );

  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  // -----------------------------
  // ADMIN LOGIN CHECK
  // -----------------------------

  if (!isAuthenticated(req)) {
    return send(res, 401, {
      ok: false,
      error: "Unauthorized"
    });
  }

  try {
    // -----------------------------
    // GET SAVED APIS
    // -----------------------------

    if (req.method === "GET") {
      const result = await storeRequest("/apis", {
        method: "GET"
      });

      const apis = Array.isArray(result)
        ? result
        : Array.isArray(result.apis)
          ? result.apis
          : [];

      return send(res, 200, {
        ok: true,
        apis
      });
    }

    // -----------------------------
    // ADD NEW API
    // -----------------------------

    if (req.method === "POST") {
      const body =
        typeof req.body === "object" && req.body
          ? req.body
          : {};

      const name = clean(body.name, 80);
      const url = clean(body.url, 2000);
      const method = clean(
        body.method || "GET",
        10
      ).toUpperCase();

      const description = clean(
        body.description || "",
        300
      );

      const category = clean(
        body.category || "Custom API",
        50
      );

      if (!name) {
        return send(res, 400, {
          ok: false,
          error: "API name is required."
        });
      }

      if (!url) {
        return send(res, 400, {
          ok: false,
          error: "API URL is required."
        });
      }

      // Only normal HTTP(S) API URLs.
      let parsed;

      try {
        parsed = new URL(url);
      } catch {
        return send(res, 400, {
          ok: false,
          error: "Invalid API URL."
        });
      }

      if (
        parsed.protocol !== "https:" &&
        parsed.protocol !== "http:"
      ) {
        return send(res, 400, {
          ok: false,
          error: "Only HTTP/HTTPS URLs are allowed."
        });
      }

      const allowedMethods = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE"
      ];

      if (!allowedMethods.includes(method)) {
        return send(res, 400, {
          ok: false,
          error: "Unsupported HTTP method."
        });
      }

      const api = {
        id: makeId(),
        name,
        url,
        method,
        description,
        category,
        createdAt: new Date().toISOString()
      };

      const result = await storeRequest("/apis", {
        method: "POST",
        body: JSON.stringify(api)
      });

      return send(res, 201, {
        ok: true,
        api:
          result?.api ||
          result ||
          api
      });
    }

    // -----------------------------
    // REMOVE SAVED API
    // -----------------------------

    if (req.method === "DELETE") {
      let id =
        req.query?.id ||
        req.body?.id;

      id = clean(id, 150);

      if (!id) {
        return send(res, 400, {
          ok: false,
          error: "API ID is required."
        });
      }

      const result = await storeRequest(
        `/apis/${encodeURIComponent(id)}`,
        {
          method: "DELETE"
        }
      );

      return send(res, 200, {
        ok: true,
        removed: id,
        result
      });
    }

    // -----------------------------
    // METHOD NOT ALLOWED
    // -----------------------------

    res.setHeader(
      "Allow",
      "GET, POST, DELETE"
    );

    return send(res, 405, {
      ok: false,
      error: "Method not allowed."
    });

  } catch (error) {
    console.error(
      "CUSTOM API ERROR:",
      error
    );

    return send(res, 500, {
      ok: false,
      error:
        error?.message ||
        "Custom API storage error."
    });
  }
};
