// api/custom-proxy.js

const { neon } = require("@neondatabase/serverless");
const dns = require("dns").promises;
const net = require("net");


// ==========================================
// DATABASE
// ==========================================

function getDatabase() {

  const url =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL;

  if (!url) {
    throw new Error(
      "DATABASE_URL is not configured"
    );
  }

  return neon(url);
}


// ==========================================
// RESPONSE
// ==========================================

function send(res, status, data) {

  return res
    .status(status)
    .setHeader(
      "Content-Type",
      "application/json"
    )
    .json(data);

}


// ==========================================
// PRIVATE / LOCAL IP CHECK
// ==========================================

function isBlockedIP(ip) {

  if (net.isIPv4(ip)) {

    const parts =
      ip
        .split(".")
        .map(Number);

    // 10.0.0.0/8
    if (parts[0] === 10) {
      return true;
    }

    // 127.0.0.0/8
    if (parts[0] === 127) {
      return true;
    }

    // 169.254.0.0/16
    if (
      parts[0] === 169 &&
      parts[1] === 254
    ) {
      return true;
    }

    // 172.16.0.0/12
    if (
      parts[0] === 172 &&
      parts[1] >= 16 &&
      parts[1] <= 31
    ) {
      return true;
    }

    // 192.168.0.0/16
    if (
      parts[0] === 192 &&
      parts[1] === 168
    ) {
      return true;
    }

    return false;
  }


  if (net.isIPv6(ip)) {

    const lower =
      ip.toLowerCase();

    // localhost
    if (
      lower === "::1"
    ) {
      return true;
    }

    // Unique local
    if (
      lower.startsWith("fc") ||
      lower.startsWith("fd")
    ) {
      return true;
    }

    // Link local
    if (
      lower.startsWith("fe80:")
    ) {
      return true;
    }

    return false;
  }


  return true;
}


// ==========================================
// SAFE TARGET URL
// ==========================================

async function validateTarget(
  rawURL
) {

  const url =
    new URL(rawURL);


  // Only HTTPS
  if (
    url.protocol !== "https:"
  ) {

    throw new Error(
      "Only HTTPS API URLs are allowed"
    );

  }


  // Resolve hostname
  const addresses =
    await dns.lookup(
      url.hostname,
      {
        all: true
      }
    );


  if (
    !addresses ||
    !addresses.length
  ) {

    throw new Error(
      "Unable to resolve API host"
    );

  }


  // Prevent internal/private targets
  for (
    const item of addresses
  ) {

    if (
      isBlockedIP(
        item.address
      )
    ) {

      throw new Error(
        "API host is not allowed"
      );

    }

  }


  return url;
}


// ==========================================
// MAIN HANDLER
// ==========================================

module.exports = async function handler(
  req,
  res
) {

  try {

    // --------------------------------------
    // GET ONLY
    // --------------------------------------

    if (
      req.method !== "GET"
    ) {

      return send(
        res,
        405,
        {

          success: false,

          error:
            "GET method required"

        }
      );

    }


    // --------------------------------------
    // API ID
    // --------------------------------------

    const id =
      Number(
        req.query?.id
      );


    if (
      !Number.isInteger(id) ||
      id <= 0
    ) {

      return send(
        res,
        400,
        {

          success: false,

          error:
            "Invalid API ID"

        }
      );

    }


    // --------------------------------------
    // MESSAGE
    // --------------------------------------

    const message =
      String(
        req.query?.message ||
        ""
      );


    // --------------------------------------
    // DATABASE
    // --------------------------------------

    const sql =
      getDatabase();


    const rows =
      await sql`

        SELECT *

        FROM custom_apis

        WHERE id = ${id}

        LIMIT 1

      `;


    if (!rows.length) {

      return send(
        res,
        404,
        {

          success: false,

          error:
            "Saved API not found"

        }
      );

    }


    const api =
      rows[0];


    // --------------------------------------
    // BUILD TARGET URL
    // --------------------------------------

    let targetURL =
      String(api.url);


    /*
      Supported placeholder:

      {message}

      Example:

      https://example.com/api?number={message}
    */


    targetURL =
      targetURL.replace(
        /\{message\}/gi,
        encodeURIComponent(
          message
        )
      );


    // --------------------------------------
    // VALIDATE TARGET
    // --------------------------------------

    const safeURL =
      await validateTarget(
        targetURL
      );


    // --------------------------------------
    // HTTP METHOD
    // --------------------------------------

    const method =
      String(
        api.method ||
        "GET"
      ).toUpperCase();


    const allowedMethods = [

      "GET",

      "POST",

      "PUT",

      "PATCH",

      "DELETE"

    ];


    if (
      !allowedMethods.includes(
        method
      )
    ) {

      return send(
        res,
        400,
        {

          success: false,

          error:
            "Unsupported HTTP method"

        }
      );

    }


    // --------------------------------------
    // REQUEST HEADERS
    // --------------------------------------

    const headers = {

      "Accept":
        "application/json,text/plain,*/*"

    };


    /*
      Optional server-side API key.

      These values are NEVER exposed
      in index.html.
    */

    if (
      process.env.CUSTOM_API_KEY
    ) {

      const headerName =
        process.env.CUSTOM_API_HEADER ||
        "Authorization";


      if (
        headerName.toLowerCase() ===
        "authorization"
      ) {

        headers[headerName] =
          "Bearer " +
          process.env.CUSTOM_API_KEY;

      } else {

        headers[headerName] =
          process.env.CUSTOM_API_KEY;

      }

    }


    // --------------------------------------
    // TIMEOUT
    // --------------------------------------

    const controller =
      new AbortController();


    const timer =
      setTimeout(
        () => {
          controller.abort();
        },
        15000
      );


    let response;


    try {

      response =
        await fetch(
          safeURL.toString(),
          {

            method,

            headers,

            signal:
              controller.signal

          }
        );

    } finally {

      clearTimeout(
        timer
      );

    }


    // --------------------------------------
    // READ RESPONSE
    // --------------------------------------

    const contentType =
      response.headers.get(
        "content-type"
      ) || "";


    let responseData;


    if (
      contentType.includes(
        "application/json"
      )
    ) {

      responseData =
        await response
          .json()
          .catch(
            () => null
          );

    } else {

      responseData =
        await response.text();

    }


    // --------------------------------------
    // FINAL RESPONSE
    // --------------------------------------

    return send(
      res,
      200,
      {

        success:
          response.ok,

        status:
          response.status,

        status_text:
          response.statusText,

        api_id:
          id,

        api_name:
          api.name,

        method,

        query:
          message,

        response:
          responseData

      }
    );


  } catch (error) {

    console.error(
      "Custom proxy error:",
      error
    );


    if (
      error.name ===
      "AbortError"
    ) {

      return send(
        res,
        504,
        {

          success: false,

          error:
            "External API request timed out"

        }
      );

    }


    return send(
      res,
      500,
      {

        success: false,

        error:
          error.message ||
          "Custom API request failed"

      }
    );

  }

};
