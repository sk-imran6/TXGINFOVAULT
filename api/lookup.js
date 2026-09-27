// api/lookup.js

const crypto = require("crypto");

const TIMEOUT = 10000;
const MAX_RESULTS = 15;

const COOKIE_NAME = "txg_admin_session";

const FALLBACK_SECRET =
  "TXG-INFORMATION-AUTH-2026-CHANGE-ME";

const SESSION_HOURS = 12;


// ==========================================
// AUTH SECRET
// ==========================================

function getSecret() {
  return (
    process.env.AUTH_SECRET ||
    FALLBACK_SECRET
  );
}


// ==========================================
// COOKIE
// ==========================================

function getCookie(req, name) {

  const header =
    req.headers.cookie || "";

  for (const item of header.split(";")) {

    const index =
      item.indexOf("=");

    if (index === -1) {
      continue;
    }

    const key =
      item.slice(0, index).trim();

    const value =
      item.slice(index + 1).trim();

    if (key === name) {

      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }

    }

  }

  return null;
}


// ==========================================
// VERIFY SESSION
// ==========================================

function verifySession(token) {

  if (!token) {
    return false;
  }

  const parts =
    token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const timestamp =
    Number(parts[0]);

  const signature =
    parts[1];

  if (!Number.isFinite(timestamp)) {
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
        String(timestamp)
      )
      .digest("hex");

  if (
    signature.length !==
    expected.length
  ) {
    return false;
  }

  try {

    return crypto.timingSafeEqual(
      Buffer.from(
        signature,
        "utf8"
      ),
      Buffer.from(
        expected,
        "utf8"
      )
    );

  } catch {

    return false;

  }

}


// ==========================================
// AUTH CHECK
// ==========================================

function isAuthenticated(req) {

  const token =
    getCookie(
      req,
      COOKIE_NAME
    );

  return verifySession(token);
}


// ==========================================
// CLEAN
// ==========================================

function clean(value) {

  return String(
    value || ""
  )
    .trim()
    .slice(0, 500);

}


// ==========================================
// RESULT
// ==========================================

function result(
  name,
  source,
  data,
  status = "success"
) {

  return {
    name,
    source,
    status,
    data
  };

}


// ==========================================
// HTTP REQUEST
// ==========================================

async function request(
  url,
  options = {}
) {

  const controller =
    new AbortController();

  const timer =
    setTimeout(
      () => controller.abort(),
      TIMEOUT
    );

  try {

    const response =
      await fetch(
        url,
        {
          ...options,

          signal:
            controller.signal,

          headers: {
            "User-Agent":
              "TXG-Information/10.0",

            "Accept":
              "application/json,text/plain,*/*",

            ...(options.headers || {})
          }
        }
      );


    const text =
      await response.text();


    let data;


    try {

      data =
        text
          ? JSON.parse(text)
          : {};

    } catch {

      data =
        text.slice(
          0,
          15000
        );

    }


    return {
      ok:
        response.ok,

      status:
        response.status,

      headers:
        response.headers,

      data
    };

  } finally {

    clearTimeout(
      timer
    );

  }

}


// ==========================================
// DETECTORS
// ==========================================

function isEmail(v) {

  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/
    .test(v);

}


function isIP(v) {

  return (
    /^(?:\d{1,3}\.){3}\d{1,3}$/
      .test(v)
    ||
    v.includes(":")
  );

}


function isPIN(v) {

  return /^\d{6}$/.test(v);

}


function isIFSC(v) {

  return /^[A-Z]{4}0[A-Z0-9]{6}$/i
    .test(v);

}


function isUPI(v) {

  return /^[a-zA-Z0-9._-]{2,}@[a-zA-Z0-9.-]{2,}$/
    .test(v);

}


function isPhone(v) {

  const digits =
    v.replace(
      /\D/g,
      ""
    );

  return (
    digits.length >= 8 &&
    digits.length <= 15
  );

}


function isURL(v) {

  return (
    /^https?:\/\//i.test(v)
    ||
    /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i
      .test(v)
  );

}


// ==========================================
// HOST
// ==========================================

function getHost(value) {

  try {

    return new URL(
      /^https?:\/\//i.test(value)
        ? value
        : `https://${value}`
    )
      .hostname
      .toLowerCase();

  } catch {

    return null;

  }

}


// ==========================================
// DNS
// ==========================================

async function dns(
  domain,
  type
) {

  const r =
    await request(
      `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
      {
        headers: {
          Accept:
            "application/dns-json"
        }
      }
    );


  return r.ok
    ? r.data
    : {
        error:
          `DNS HTTP ${r.status}`
      };

}


// ==========================================
// EMAIL
// ==========================================

async function emailLookup(
  value
) {

  const parts =
    value.split("@");

  const local =
    parts[0];

  const domain =
    parts[1].toLowerCase();


  const dnsData = {};


  for (
    const type of [
      "A",
      "AAAA",
      "MX",
      "NS",
      "TXT",
      "CAA"
    ]
  ) {

    try {

      dnsData[type] =
        await dns(
          domain,
          type
        );

    } catch (e) {

      dnsData[type] = {
        error:
          e.message
      };

    }

  }


  return result(
    "EMAIL",
    "Google DNS",
    {
      input:
        value,

      normalized:
        value.toLowerCase(),

      local_part:
        local,

      domain,

      dns:
        dnsData
    }
  );

}


// ==========================================
// DOMAIN / URL
// ==========================================

async function domainLookup(
  value
) {

  const host =
    getHost(value);


  if (!host) {

    throw new Error(
      "Invalid URL/domain"
    );

  }


  let rdap;


  try {

    const r =
      await request(
        `https://rdap.org/domain/${encodeURIComponent(host)}`
      );


    rdap =
      r.ok
        ? r.data
        : {
            error:
              `RDAP HTTP ${r.status}`
          };

  } catch (e) {

    rdap = {
      error:
        e.message
    };

  }


  const dnsData = {};


  for (
    const type of [
      "A",
      "AAAA",
      "MX",
      "NS",
      "TXT",
      "CAA"
    ]
  ) {

    try {

      dnsData[type] =
        await dns(
          host,
          type
        );

    } catch (e) {

      dnsData[type] = {
        error:
          e.message
      };

    }

  }


  let http;


  try {

    const url =
      /^https?:\/\//i.test(value)
        ? value
        : `https://${value}`;


    const r =
      await request(
        url,
        {
          redirect:
            "manual"
        }
      );


    http = {
      status:
        r.status,

      location:
        r.headers.get(
          "location"
        ),

      content_type:
        r.headers.get(
          "content-type"
        ),

      server:
        r.headers.get(
          "server"
        ),

      powered_by:
        r.headers.get(
          "x-powered-by"
        ),

      strict_transport_security:
        r.headers.get(
          "strict-transport-security"
        ),

      content_security_policy:
        r.headers.get(
          "content-security-policy"
        ),

      x_frame_options:
        r.headers.get(
          "x-frame-options"
        )
    };

  } catch (e) {

    http = {
      error:
        e.message
    };

  }


  return result(
    "URL / DOMAIN",
    "RDAP + DNS + HTTP",
    {
      hostname:
        host,

      rdap,

      dns:
        dnsData,

      http
    }
  );

}


// ==========================================
// IP
// ==========================================

async function ipLookup(
  value
) {

  const template =
    process.env.IP_API_URL ||
    "https://ipwho.is/{ip}";


  const url =
    template.replace(
      "{ip}",
      encodeURIComponent(value)
    );


  const r =
    await request(url);


  if (!r.ok) {

    throw new Error(
      `IP API HTTP ${r.status}`
    );

  }


  return result(
    "IP",
    "IP API",
    r.data
  );

}


// ==========================================
// PIN
// ==========================================

async function pinLookup(
  value
) {

  const template =
    process.env.PIN_API_URL ||
    "https://api.postalpincode.in/pincode/{pin}";


  const url =
    template.replace(
      "{pin}",
      encodeURIComponent(value)
    );


  const r =
    await request(url);


  if (!r.ok) {

    throw new Error(
      `PIN API HTTP ${r.status}`
    );

  }


  return result(
    "PIN",
    "India Post PIN API",
    r.data
  );

}


// ==========================================
// IFSC
// ==========================================

async function ifscLookup(
  value
) {

  const template =
    process.env.IFSC_API_URL ||
    "https://ifsc.razorpay.com/{ifsc}";


  const url =
    template.replace(
      "{ifsc}",
      encodeURIComponent(
        value.toUpperCase()
      )
    );


  const r =
    await request(url);


  if (!r.ok) {

    throw new Error(
      `IFSC API HTTP ${r.status}`
    );

  }


  return result(
    "IFSC",
    "IFSC API",
    r.data
  );

}


// ==========================================
// MOBILE
// ==========================================

function mobileLookup(
  value
) {

  const digits =
    value.replace(
      /\D/g,
      ""
    );


  return result(
    "MOBILE",
    "Local validation",
    {
      input:
        value,

      digits,

      length:
        digits.length,

      country_guess:
        digits.startsWith("91") ||
        (
          digits.length === 10 &&
          /^[6-9]/.test(digits)
        )
          ? "India"
          : "Unknown",

      possible_number:
        digits.length >= 8 &&
        digits.length <= 15
    }
  );

}


// ==========================================
// UPI
// ==========================================

function upiLookup(
  value
) {

  const valid =
    isUPI(value);


  return result(
    "UPI",
    "Format validation",
    {
      input:
        value,

      valid_format:
        valid,

      handle:
        valid
          ? value.split("@")[1]
          : null,

      note:
        "Format validation does not prove account existence or ownership."
    }
  );

}


// ==========================================
// COMPANY
// ==========================================

function companyLookup(
  value
) {

  return result(
    "COMPANY",
    "TXG public-input analysis",
    {
      query:
        value,

      note:
        "Live company records require an authorized public/company-data provider. Private owner/KYC data is not returned."
    },
    "not_configured"
  );

}


// ==========================================
// VEHICLE
// ==========================================

async function vehicleLookup(
  value
) {

  const template =
    process.env.VEHICLE_API_URL;


  if (!template) {

    return result(
      "VEHICLE",
      "Authorized vehicle provider",
      {
        registration_number:
          value.toUpperCase(),

        configured:
          false,

        note:
          "Add an authorized vehicle API in VEHICLE_API_URL to enable live vehicle data."
      },
      "not_configured"
    );

  }


  const headers = {};


  if (
    process.env.VEHICLE_API_KEY
  ) {

    headers[
      process.env.VEHICLE_API_HEADER ||
      "Authorization"
    ] =
      process.env.VEHICLE_API_KEY;

  }


  const url =
    template.replace(
      "{registration}",
      encodeURIComponent(
        value.toUpperCase()
      )
    );


  const r =
    await request(
      url,
      {
        headers
      }
    );


  if (!r.ok) {

    throw new Error(
      `Vehicle API HTTP ${r.status}`
    );

  }


  return result(
    "VEHICLE",
    "Authorized vehicle API",
    r.data
  );

}


// ==========================================
// CRM
// ==========================================

async function crmLookup(
  value
) {

  const token =
    process.env.ZOHO_ACCESS_TOKEN;


  if (!token) {

    return result(
      "CRM",
      "Zoho CRM",
      {
        configured:
          false,

        query:
          value,

        note:
          "Set ZOHO_ACCESS_TOKEN to enable authorized Zoho CRM search."
      },
      "not_configured"
    );

  }


  const base =
    (
      process.env.ZOHO_API_BASE ||
      "https://www.zohoapis.in/crm/v8"
    )
      .replace(
        /\/+$/,
        ""
      );


  const modules = [
    "Contacts",
    "Leads",
    "Accounts",
    "Deals"
  ];


  const matches = [];


  for (
    const module of modules
  ) {

    try {

      const url =
        `${base}/${module}/search?word=${encodeURIComponent(value)}`;


      const r =
        await request(
          url,
          {
            headers: {
              Authorization:
                `Zoho-oauthtoken ${token}`
            }
          }
        );


      matches.push({
        module,

        http_status:
          r.status,

        data:
          r.data
      });

    } catch (e) {

      matches.push({
        module,

        error:
          e.message
      });

    }

  }


  return result(
    "CRM",
    "Zoho CRM",
    {
      query:
        value,

      matches
    }
  );

}


// ==========================================
// MAIN HANDLER
// ==========================================

async function handler(
  req,
  res
) {

  try {

    // ======================================
    // METHOD
    // ======================================

    if (
      req.method !==
      "GET"
    ) {

      res.setHeader(
        "Allow",
        "GET"
      );


      return res
        .status(405)
        .json({
          success:
            false,

          error:
            "Method not allowed"
        });

    }


    // ======================================
    // AUTH
    // ======================================

    if (
      !isAuthenticated(req)
    ) {

      return res
        .status(401)
        .json({
          success:
            false,

          error:
            "Login required"
        });

    }


    // ======================================
    // INPUT
    // ======================================

    const value =
      clean(
        req.query?.value
      );


    let type =
      clean(
        req.query?.type
      )
        .toLowerCase();


    if (!value) {

      return res
        .status(400)
        .json({
          success:
            false,

          error:
            "Enter a value"
        });

    }


    // ======================================
    // AUTO DETECTION
    // ======================================

    if (
      !type ||
      type === "auto"
    ) {

      if (
        isEmail(value)
      ) {

        type =
          "email";

      } else if (
        isIP(value)
      ) {

        type =
          "ip";

      } else if (
        isPIN(value)
      ) {

        type =
          "pin";

      } else if (
        isIFSC(value)
      ) {

        type =
          "ifsc";

      } else if (
        isUPI(value)
      ) {

        type =
          "upi";

      } else if (
        isURL(value)
      ) {

        type =
          "url";

      } else if (
        isPhone(value)
      ) {

        type =
          "mobile";

      } else {

        type =
          "company";

      }

    }


    // ======================================
    // RESULTS
    // ======================================

    const results = [];


    async function add(
      fn
    ) {

      try {

        const item =
          await fn();


        if (item) {

          results.push(
            item
          );

        }

      } catch (e) {

        results.push(
          result(
            "ERROR",
            "TXG",
            {
              message:
                e?.message ||
                "Lookup failed"
            },
            "error"
          )
        );

      }

    }


    // ======================================
    // MOBILE
    // ======================================

    if (
      type === "mobile"
    ) {

      await add(
        () =>
          mobileLookup(
            value
          )
      );


      await add(
        () =>
          crmLookup(
            value
          )
      );

    }


    // ======================================
    // EMAIL
    // ======================================

    else if (
      type === "email"
    ) {

      await add(
        () =>
          emailLookup(
            value
          )
      );


      const domain =
        value.split("@")[1];


      if (domain) {

        await add(
          () =>
            domainLookup(
              domain
            )
        );

      }


      await add(
        () =>
          crmLookup(
            value
          )
      );

    }


    // ======================================
    // IP
    // ======================================

    else if (
      type === "ip"
    ) {

      await add(
        () =>
          ipLookup(
            value
          )
      );

    }


    // ======================================
    // PIN
    // ======================================

    else if (
      type === "pin"
    ) {

      await add(
        () =>
          pinLookup(
            value
          )
      );

    }


    // ======================================
    // IFSC
    // ======================================

    else if (
      type === "ifsc"
    ) {

      await add(
        () =>
          ifscLookup(
            value
          )
      );

    }


    // ======================================
    // UPI
    // ======================================

    else if (
      type === "upi"
    ) {

      await add(
        () =>
          upiLookup(
            value
          )
      );

    }


    // ======================================
    // URL
    // ======================================

    else if (
      type === "url" ||
      type === "domain"
    ) {

      await add(
        () =>
          domainLookup(
            value
          )
      );


      await add(
        () =>
          crmLookup(
            getHost(value) ||
            value
          )
      );

    }


    // ======================================
    // VEHICLE
    // ======================================

    else if (
      type === "vehicle"
    ) {

      await add(
        () =>
          vehicleLookup(
            value
          )
      );

    }


    // ======================================
    // COMPANY
    // ======================================

    else if (
      type === "company"
    ) {

      await add(
        () =>
          companyLookup(
            value
          )
      );


      await add(
        () =>
          crmLookup(
            value
          )
      );

    }


    // ======================================
    // CRM
    // ======================================

    else if (
      type === "crm"
    ) {

      await add(
        () =>
          crmLookup(
            value
          )
      );

    }


    // ======================================
    // UNKNOWN
    // ======================================

    else {

      await add(
        () =>
          companyLookup(
            value
          )
      );

    }


    // ======================================
    // FINAL RESPONSE
    // ======================================

    return res
      .status(200)
      .json({
        success:
          true,

        query:
          value,

        type,

        result_count:
          Math.min(
            results.length,
            MAX_RESULTS
          ),

        results:
          results.slice(
            0,
            MAX_RESULTS
          )
      });


  } catch (error) {

    // ======================================
    // NEVER CRASH VERCEL FUNCTION
    // ======================================

    console.error(
      "TXG LOOKUP ERROR:",
      error
    );


    return res
      .status(500)
      .json({
        success:
          false,

        error:
          error?.message ||
          "Lookup server error"
      });

  }

}


module.exports =
  handler;
