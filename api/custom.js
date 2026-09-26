const dns = require("dns").promises;
const net = require("net");
const { authenticated } = require("./auth");

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(n => !Number.isInteger(n))) {
    return true;
  }

  const [a, b] = parts;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 0) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;

  return false;
}

function isPrivateIPv6(ip) {
  const value = ip.toLowerCase();

  return (
    value === "::1" ||
    value === "::" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:")
  );
}

async function hostIsBlocked(hostname) {
  const host = hostname.toLowerCase();

  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {
    return true;
  }

  if (net.isIP(host) === 4) {
    return isPrivateIPv4(host);
  }

  if (net.isIP(host) === 6) {
    return isPrivateIPv6(host);
  }

  try {
    const addresses = await dns.lookup(host, {
      all: true,
      verbatim: true
    });

    for (const item of addresses) {
      if (
        (item.family === 4 && isPrivateIPv4(item.address)) ||
        (item.family === 6 && isPrivateIPv6(item.address))
      ) {
        return true;
      }
    }
  } catch {
    return true;
  }

  return false;
}

async function handler(req, res) {
  try {
    if (!authenticated(req)) {
      return res.status(401).json({
        ok: false,
        error: "Unauthorized"
      });
    }

    if (req.method !== "POST") {
      res.setHeader("Allow", "POST");

      return res.status(405).json({
        ok: false,
        error: "Method not allowed"
      });
    }

    const body =
      req.body && typeof req.body === "object"
        ? req.body
        : {};

    const rawUrl = String(body.url || "").trim();
    const message =
      body.message === undefined ||
      body.message === null
        ? ""
        : String(body.message);

    if (!rawUrl) {
      return res.status(400).json({
        ok: false,
        error: "API URL is required"
      });
    }

    let parsed;

    try {
      parsed = new URL(rawUrl);
    } catch {
      return res.status(400).json({
        ok: false,
        error: "Invalid API URL"
      });
    }

    if (parsed.protocol !== "https:") {
      return res.status(400).json({
        ok: false,
        error: "Only HTTPS API URLs are allowed"
      });
    }

    if (await hostIsBlocked(parsed.hostname)) {
      return res.status(403).json({
        ok: false,
        error: "Blocked API host"
      });
    }

    const finalUrl = rawUrl.replace(
      /\{message\}/g,
      encodeURIComponent(message)
    );

    let finalParsed;

    try {
      finalParsed = new URL(finalUrl);
    } catch {
      return res.status(400).json({
        ok: false,
        error: "Invalid generated API URL"
      });
    }

    if (finalParsed.protocol !== "https:") {
      return res.status(400).json({
        ok: false,
        error: "Generated URL must use HTTPS"
      });
    }

    if (await hostIsBlocked(finalParsed.hostname)) {
      return res.status(403).json({
        ok: false,
        error: "Blocked generated API host"
      });
    }

    const controller = new AbortController();

    const timeout = setTimeout(() => {
      controller.abort();
    }, 15000);

    let response;

    try {
      response = await fetch(finalUrl, {
        method: "GET",
        redirect: "follow",
        signal: controller.signal,
        headers: {
          "User-Agent": "TXG-Information-Center/1.0",
          "Accept": "*/*"
        }
      });
    } finally {
      clearTimeout(timeout);
    }

    const contentType =
      response.headers.get("content-type") || "text/plain";

    const text = await response.text();

    let data = text;

    if (contentType.includes("application/json")) {
      try {
        data = JSON.parse(text);
      } catch {
        data = text;
      }
    }

    return res.status(200).json({
      ok: response.ok,
      status: response.status,
      contentType,
      data
    });
  } catch (error) {
    console.error("CUSTOM API ERROR:", error);

    if (error && error.name === "AbortError") {
      return res.status(504).json({
        ok: false,
        error: "API request timed out"
      });
    }

    return res.status(500).json({
      ok: false,
      error: error.message || "Custom API request failed"
    });
  }
}

module.exports = handler;
