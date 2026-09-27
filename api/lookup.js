// api/lookup.js

const dns = require("dns").promises;
const net = require("net");


// ================================
// BASIC HELPERS
// ================================

function send(res, status, data) {
  return res
    .status(status)
    .setHeader("Content-Type", "application/json")
    .json(data);
}


async function fetchJSON(url, options = {}) {
  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, 12000);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    const contentType =
      response.headers.get("content-type") || "";

    let data;

    if (contentType.includes("application/json")) {
      data = await response.json().catch(() => null);
    } else {
      data = await response.text();
    }

    return {
      ok: response.ok,
      status: response.status,
      data
    };

  } finally {
    clearTimeout(timer);
  }
}


// ================================
// MOBILE
// ================================

function mobileLookup(value) {

  const input = String(value).trim();

  const digits =
    input.replace(/\D/g, "");

  const indiaValid =
    /^(?:91)?[6-9]\d{9}$/.test(digits);

  let country = "Unknown";
  let countryCode = "";

  if (indiaValid) {
    country = "India";
    countryCode = "+91";
  }

  return {
    input,
    normalized: indiaValid
      ? "+91" + digits.slice(-10)
      : input,

    country,
    country_code: countryCode,

    type: indiaValid
      ? "Mobile"
      : "Unknown",

    valid: indiaValid,

    note:
      "This lookup does not expose private subscriber, IMEI, live-location, or owner-KYC data."
  };
}


// ================================
// EMAIL
// ================================

async function emailLookup(value) {

  const input =
    String(value).trim().toLowerCase();

  const parts =
    input.split("@");

  const valid =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(input);

  const local =
    parts.length === 2
      ? parts[0]
      : "";

  const domain =
    parts.length === 2
      ? parts[1]
      : "";

  let dnsRecords = {};

  if (domain) {
    dnsRecords =
      await getDNS(domain);
  }

  return {
    input,
    valid,
    local,
    domain,

    tld:
      domain.includes(".")
        ? domain.split(".").pop()
        : "",

    dns:
      dnsRecords
  };
}


// ================================
// IP
// ================================

async function ipLookup(value) {

  const input =
    String(value).trim();

  if (!net.isIP(input)) {
    return {
      input,
      valid: false,
      error: "Invalid IP address"
    };
  }

  const response =
    await fetchJSON(
      "https://ipwho.is/" +
      encodeURIComponent(input)
    );

  return {
    input,
    version:
      net.isIPv4(input)
        ? 4
        : 6,

    data:
      response.data
  };
}


// ================================
// DNS
// ================================

async function getDNS(host) {

  const result = {};

  const types = [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME"
  ];

  for (const type of types) {

    try {

      result[type] =
        await dns.resolve(
          host,
          type
        );

    } catch {

      result[type] = [];

    }

  }

  return result;
}


// ================================
// URL / DOMAIN
// ================================

async function urlLookup(value) {

  let input =
    String(value).trim();

  let url =
    input;

  if (!/^https?:\/\//i.test(url)) {
    url =
      "https://" + url;
  }

  let parsed;

  try {

    parsed =
      new URL(url);

  } catch {

    return {
      input,
      valid: false,
      error: "Invalid URL"
    };

  }

  const hostname =
    parsed.hostname;

  const dnsRecords =
    await getDNS(hostname);

  let rdap = null;

  try {

    const rdapResponse =
      await fetchJSON(
        "https://rdap.org/domain/" +
        encodeURIComponent(hostname)
      );

    if (rdapResponse.ok) {
      rdap =
        rdapResponse.data;
    }

  } catch {}

  return {

    input,

    valid: true,

    protocol:
      parsed.protocol,

    hostname,

    port:
      parsed.port || "",

    pathname:
      parsed.pathname,

    search:
      parsed.search,

    hash:
      parsed.hash,

    dns:
      dnsRecords,

    rdap
  };
}


// ================================
// PIN CODE
// ================================

async function pinLookup(value) {

  const pin =
    String(value)
      .trim()
      .replace(/\D/g, "");

  if (!/^\d{6}$/.test(pin)) {

    return {
      input: value,
      valid: false,
      error: "PIN must contain 6 digits"
    };

  }

  const response =
    await fetchJSON(
      "https://api.postalpincode.in/pincode/" +
      encodeURIComponent(pin)
    );

  return {
    input: pin,
    valid: true,
    data: response.data
  };
}


// ================================
// IFSC
// ================================

async function ifscLookup(value) {

  const ifsc =
    String(value)
      .trim()
      .toUpperCase();

  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) {

    return {
      input: ifsc,
      valid: false,
      error: "Invalid IFSC format"
    };

  }

  const response =
    await fetchJSON(
      "https://ifsc.razorpay.com/" +
      encodeURIComponent(ifsc)
    );

  if (!response.ok) {

    return {
      input: ifsc,
      valid: false,
      error: "IFSC not found"
    };

  }

  return {
    input: ifsc,
    valid: true,
    data: response.data
  };
}


// ================================
// UPI
// ================================

function upiLookup(value) {

  const input =
    String(value).trim();

  const valid =
    /^[A-Za-z0-9._-]{2,256}@[A-Za-z0-9._-]{2,64}$/
      .test(input);

  let id = "";
  let handle = "";

  if (valid) {

    const parts =
      input.split("@");

    id = parts[0];
    handle = parts.slice(1).join("@");

  }

  return {

    input,

    valid,

    id,

    handle,

    note:
      "Format validation only. This does not verify account ownership or expose private banking information."
  };
}


// ================================
// VEHICLE
// ================================

async function vehicleLookup(value) {

  const registration =
    String(value)
      .trim()
      .toUpperCase();

  if (!process.env.VEHICLE_API_URL) {

    return {

      input: registration,

      available: false,

      note:
        "No authorized vehicle-data provider is configured."
    };

  }

  let url =
    process.env.VEHICLE_API_URL
      .replace(
        "{registration}",
        encodeURIComponent(registration)
      );

  const headers = {};

  if (process.env.VEHICLE_API_KEY) {

    const header =
      process.env.VEHICLE_API_HEADER ||
      "Authorization";

    headers[header] =
      header === "Authorization"
        ? "Bearer " +
          process.env.VEHICLE_API_KEY
        : process.env.VEHICLE_API_KEY;
  }

  const response =
    await fetchJSON(
      url,
      {
        headers
      }
    );

  return {

    input: registration,

    authorized_provider:
      true,

    data:
      response.data

  };
}


// ================================
// COMPANY
// ================================

function companyLookup(value) {

  const input =
    String(value).trim();

  return {

    input,

    type:
      "company",

    note:
      "Company lookup provider is not configured yet.",

    available:
      false

  };
}


// ================================
// CRM
// ================================

async function crmLookup(value) {

  if (!process.env.CRM_API_URL) {

    return {

      input: value,

      available: false,

      note:
        "Authorized CRM provider is not configured."

    };

  }

  const url =
    process.env.CRM_API_URL.replace(
      "{query}",
      encodeURIComponent(value)
    );

  const headers = {};

  if (process.env.CRM_API_KEY) {

    const header =
      process.env.CRM_API_HEADER ||
      "Authorization";

    headers[header] =
      header === "Authorization"
        ? "Bearer " +
          process.env.CRM_API_KEY
        : process.env.CRM_API_KEY;

  }

  const response =
    await fetchJSON(
      url,
      {
        headers
      }
    );

  return {

    input: value,

    authorized_provider:
      true,

    data:
      response.data

  };
}


// ================================
// AUTO DETECTION
// ================================

function detectType(value) {

  const input =
    String(value).trim();

  if (/^\d{6}$/.test(input)) {
    return "pin";
  }

  if (
    /^[A-Z]{4}0[A-Z0-9]{6}$/i
      .test(input)
  ) {
    return "ifsc";
  }

  if (
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/
      .test(input)
  ) {
    return "email";
  }

  if (
    /^\+?\d{10,15}$/
      .test(input)
  ) {
    return "mobile";
  }

  if (net.isIP(input)) {
    return "ip";
  }

  if (
    /^https?:\/\//i.test(input) ||
    /^[A-Za-z0-9.-]+\.[A-Za-z]{2,}$/
      .test(input)
  ) {
    return "url";
  }

  if (
    /^[A-Za-z0-9._-]+@[A-Za-z0-9._-]+$/
      .test(input)
  ) {
    return "upi";
  }

  return "company";
}


// ================================
// MAIN HANDLER
// ================================

module.exports = async function handler(
  req,
  res
) {

  try {

    if (req.method !== "GET") {

      return send(
        res,
        405,
        {
          success: false,
          error: "GET method required"
        }
      );

    }

    const value =
      String(
        req.query?.value || ""
      ).trim();

    let type =
      String(
        req.query?.type || "auto"
      ).toLowerCase();


    if (!value) {

      return send(
        res,
        400,
        {
          success: false,
          error: "Value is required"
        }
      );

    }


    if (type === "auto") {

      type =
        detectType(value);

    }


    let result;


    switch (type) {

      case "mobile":

        result =
          mobileLookup(value);

        break;


      case "email":

        result =
          await emailLookup(value);

        break;


      case "ip":

        result =
          await ipLookup(value);

        break;


      case "url":

      case "domain":

        result =
          await urlLookup(value);

        break;


      case "pin":

        result =
          await pinLookup(value);

        break;


      case "ifsc":

        result =
          await ifscLookup(value);

        break;


      case "upi":

        result =
          upiLookup(value);

        break;


      case "vehicle":

        result =
          await vehicleLookup(value);

        break;


      case "company":

        result =
          companyLookup(value);

        break;


      case "crm":

        result =
          await crmLookup(value);

        break;


      default:

        result = {

          input: value,

          type,

          available: false,

          note:
            "This lookup type is not configured."

        };

    }


    return send(
      res,
      200,
      {
        success: true,

        query: value,

        type,

        result_count: 1,

        results: [
          result
        ]
      }
    );


  } catch (error) {

    console.error(
      "TXG lookup error:",
      error
    );

    return send(
      res,
      500,
      {
        success: false,

        error:
          error.name === "AbortError"
            ? "External API timeout"
            : (
                error.message ||
                "Lookup failed"
              )
      }
    );

  }

};
