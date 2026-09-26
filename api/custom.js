const dns = require("dns").promises;
const net = require("net");

const {
  authenticated
} = require("./auth");


// ==========================================
// RESPONSE
// ==========================================

function send(res, status, data) {

  return res
    .status(status)
    .json(data);
}


// ==========================================
// PRIVATE IP CHECK
// ==========================================

function isPrivateIPv4(ip) {

  const parts =
    ip.split(".").map(Number);

  if (parts.length !== 4) {
    return true;
  }


  const [
    a,
    b,
    c,
    d
  ] = parts;


  if (
    a === 10 ||
    a === 127
  ) {
    return true;
  }


  if (
    a === 192 &&
    b === 168
  ) {
    return true;
  }


  if (
    a === 172 &&
    b >= 16 &&
    b <= 31
  ) {
    return true;
  }


  if (
    a === 169 &&
    b === 254
  ) {
    return true;
  }


  if (
    a === 0
  ) {
    return true;
  }


  return false;
}


// ==========================================
// PRIVATE IP CHECK
// ==========================================

function isPrivateIP(ip) {

  const type =
    net.isIP(ip);


  if (type === 4) {

    return isPrivateIPv4(ip);
  }


  if (type === 6) {

    const normalized =
      ip.toLowerCase();


    return (
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      normalized.startsWith("fe80:")
    );
  }


  return false;
}


// ==========================================
// HOST CHECK
// ==========================================

async function isSafeHost(hostname) {

  const host =
    hostname.toLowerCase();


  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal")
  ) {

    return false;
  }


  if (
    net.isIP(host)
  ) {

    return !isPrivateIP(host);
  }


  try {

    const addresses =
      await dns.lookup(
        host,
        {
          all: true
        }
      );


    for (
      const address
      of addresses
    ) {

      if (
        isPrivateIP(
          address.address
        )
      ) {

        return false;
      }
    }


    return true;

  } catch {

    return false;
  }
}


// ==========================================
// MAIN
// ==========================================

async function handler(req, res) {

  try {

    if (
      !authenticated(req)
    ) {

      return send(
        res,
        401,
        {
          ok: false,
          error:
            "Authentication required"
        }
      );
    }


    if (
      req.method !== "POST"
    ) {

      return send(
        res,
        405,
        {
          ok: false,
          error:
            "Method not allowed"
        }
      );
    }


    const body =
      req.body &&
      typeof req.body === "object"
        ? req.body
        : {};


    const rawURL =
      String(
        body.url || ""
      ).trim();


    const message =
      String(
        body.message || ""
      );


    if (!rawURL) {

      return send(
        res,
        400,
        {
          ok: false,
          error:
            "API URL required"
        }
      );
    }


    if (
      rawURL.length > 2000
    ) {

      return send(
        res,
        400,
        {
          ok: false,
          error:
            "API URL is too long"
        }
      );
    }


    let finalURL =
      rawURL.replace(
        /\{message\}/g,
        encodeURIComponent(message)
      );


    let parsed;

    try {

      parsed =
        new URL(finalURL);

    } catch {

      return send(
        res,
        400,
        {
          ok: false,
          error:
            "Invalid API URL"
        }
      );
    }


    if (
      parsed.protocol !==
      "https:"
    ) {

      return send(
        res,
        400,
        {
          ok: false,
          error:
            "Only HTTPS API URLs are allowed"
        }
      );
    }


    const safe =
      await isSafeHost(
        parsed.hostname
      );


    if (!safe) {

      return send(
        res,
        400,
        {
          ok: false,
          error:
            "This API host is not allowed"
        }
      );
    }


    const controller =
      new AbortController();


    const timeout =
      setTimeout(
        () => controller.abort(),
        15000
      );


    let response;

    try {

      response =
        await fetch(
          parsed.toString(),
          {
            method: "GET",

            headers: {
              "User-Agent":
                "TXG-Information-Center/4.0",
              "Accept":
                "*/*"
            },

            redirect: "follow",

            signal:
              controller.signal
          }
        );

    } finally {

      clearTimeout(timeout);
    }


    const text =
      await response.text();


    let data =
      text;


    const contentType =
      response.headers.get(
        "content-type"
      ) || "";


    if (
      contentType
        .toLowerCase()
        .includes("json")
    ) {

      try {

        data =
          JSON.parse(text);

      } catch {

        data = text;
      }

    } else {

      try {

        data =
          JSON.parse(text);

      } catch {

        data = text;
      }
    }


    return send(
      res,
      200,
      {
        ok: true,

        httpStatus:
          response.status,

        contentType,

        response: data
      }
    );

  } catch (error) {

    console.error(
      "CUSTOM API ERROR:",
      error
    );


    if (
      error?.name ===
      "AbortError"
    ) {

      return send(
        res,
        504,
        {
          ok: false,
          error:
            "API request timed out"
        }
      );
    }


    return send(
      res,
      500,
      {
        ok: false,
        error:
          error?.message ||
          "Custom API request failed"
      }
    );
  }
}


module.exports = handler;
