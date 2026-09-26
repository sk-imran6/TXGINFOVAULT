const dns = require("dns").promises;
const net = require("net");
const { authenticated } = require("./auth");

function response(res, status, data) {
  res.status(status).json(data);
}

function isPrivateIPv4(ip) {
  const p = ip.split(".").map(Number);

  if (
    p.length !== 4 ||
    p.some(x => !Number.isInteger(x) || x < 0 || x > 255)
  ) {
    return false;
  }

  const [a, b] = p;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}

function isPrivateIPv6(ip) {
  const x = ip.toLowerCase();

  return (
    x === "::1" ||
    x.startsWith("fc") ||
    x.startsWith("fd") ||
    x.startsWith("fe80:")
  );
}

async function hostnameIsSafe(hostname) {
  const host = hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return false;
  }

  if (net.isIP(host)) {
    if (net.isIPv4(host)) {
      return !isPrivateIPv4(host);
    }

    return !isPrivateIPv6(host);
  }

  const addresses = await dns.lookup(host, {
    all: true,
    verbatim: true
  });

  if (!addresses.length) {
    return false;
  }

  for (const item of addresses) {
    if (net.isIPv4(item.address)) {
      if (isPrivateIPv4(item.address)) return false;
    } else if (net.isIPv6(item.address)) {
      if (isPrivateIPv6(item.address)) return false;
    }
  }

  return true;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return response(res, 405, {
      ok: false,
      error: "Method not allowed"
    });
  }

  if (!authenticated(req)) {
    return response(res, 401, {
      ok: false,
      error: "Authentication required"
    });
  }

  const rawURL = String(req.body?.url || "").trim();
  const message = String(req.body?.message || "").slice(0, 5000);

  if (!rawURL) {
    return response(res, 400, {
      ok: false,
      error: "API URL required"
    });
  }

  let finalURL = rawURL.replaceAll("{message}", encodeURIComponent(message));

  let parsed;

  try {
    parsed = new URL(finalURL);
  } catch {
    return response(res, 400, {
      ok: false,
      error: "Invalid API URL"
    });
  }

  if (parsed.protocol !== "https:") {
    return response(res, 400, {
      ok: false,
      error: "Only HTTPS APIs are allowed"
    });
  }

  try {
    const safe = await hostnameIsSafe(parsed.hostname);

    if (!safe) {
      return response(res, 403, {
        ok: false,
        error: "This destination is blocked"
      });
    }
  } catch {
    return response(res, 400, {
      ok: false,
      error: "Could not verify API hostname"
    });
  }

  try {
    const controller = new AbortController();

    const timer = setTimeout(() => {
      controller.abort();
    }, 15000);

    let result;

    try {
      result = await fetch(parsed.toString(), {
        method: "GET",
        redirect: "manual",
        headers: {
          "User-Agent": "TXG-Information-Center/3.0"
        },
        signal: controller.signal
      });
    } finally {
      clearTimeout(timer);
    }

    const contentType =
      result.headers.get("content-type") || "text/plain";

    const body = await result.text();

    let output = body;

    if (contentType.includes("application/json")) {
      try {
        output = JSON.parse(body);
      } catch {
        output = body;
      }
    }

    return response(res, 200, {
      ok: true,
      httpStatus: result.status,
      contentType,
      response: output
    });
  } catch (error) {
    return response(res, 502, {
      ok: false,
      error:
        error.name === "AbortError"
          ? "API request timed out"
          : error.message || "API request failed"
    });
  }
};
