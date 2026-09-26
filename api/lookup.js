const {
  parsePhoneNumberFromString
} = require("libphonenumber-js");

const dns = require("dns").promises;

const {
  authenticated
} = require("./auth");


// ==========================================
// JSON RESPONSE
// ==========================================

function send(res, status, data) {

  return res
    .status(status)
    .json(data);
}


// ==========================================
// FETCH JSON
// ==========================================

async function fetchJSON(url, options = {}) {

  const response = await fetch(url, {
    ...options,
    headers: {
      "User-Agent":
        "TXG-Information-Center/4.0",
      "Accept":
        "application/json",
      ...(options.headers || {})
    }
  });


  const text =
    await response.text();


  let data;

  try {
    data = JSON.parse(text);
  } catch {
    data = text;
  }


  return {
    ok: response.ok,
    status: response.status,
    data
  };
}


// ==========================================
// MOBILE
// ==========================================

async function mobileLookup(input) {

  const raw =
    String(input || "").trim();

  if (!raw) {
    throw new Error(
      "Mobile number required"
    );
  }


  let phone =
    parsePhoneNumberFromString(
      raw,
      "IN"
    );


  if (!phone) {

    phone =
      parsePhoneNumberFromString(
        "+" + raw
      );
  }


  if (!phone) {

    return {
      type: "mobile",
      valid: false,
      message:
        "Could not parse this number."
    };
  }


  return {
    type: "mobile",

    input: raw,

    valid:
      phone.isValid(),

    possible:
      phone.isPossible(),

    country:
      phone.country || null,

    callingCode:
      phone.countryCallingCode || null,

    international:
      phone.formatInternational(),

    national:
      phone.formatNational(),

    e164:
      phone.number,

    uri:
      phone.getURI(),

    countryCallingCode:
      phone.countryCallingCode
  };
}


// ==========================================
// PIN
// ==========================================

async function pinLookup(input) {

  const pin =
    String(input || "")
      .replace(/\D/g, "");

  if (!/^\d{6}$/.test(pin)) {

    throw new Error(
      "Enter a valid 6 digit PIN code."
    );
  }


  const result =
    await fetchJSON(
      `https://api.postalpincode.in/pincode/${pin}`
    );


  if (
    !result.ok ||
    !Array.isArray(result.data)
  ) {

    throw new Error(
      "PIN service unavailable."
    );
  }


  return {
    type: "pin",
    pin,
    response: result.data
  };
}


// ==========================================
// IFSC
// ==========================================

async function ifscLookup(input) {

  const ifsc =
    String(input || "")
      .trim()
      .toUpperCase();


  if (
    !/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)
  ) {

    throw new Error(
      "Enter a valid IFSC code."
    );
  }


  const result =
    await fetchJSON(
      `https://ifsc.razorpay.com/${encodeURIComponent(ifsc)}`
    );


  if (!result.ok) {

    throw new Error(
      "IFSC code not found."
    );
  }


  return {
    type: "ifsc",
    ifsc,
    response: result.data
  };
}


// ==========================================
// IP
// ==========================================

async function ipLookup(input) {

  let ip =
    String(input || "").trim();


  if (!ip) {

    const result =
      await fetchJSON(
        "https://ipwho.is/"
      );

    return {
      type: "ip",
      response: result.data
    };
  }


  const result =
    await fetchJSON(
      `https://ipwho.is/${encodeURIComponent(ip)}`
    );


  if (!result.ok) {

    throw new Error(
      "IP lookup failed."
    );
  }


  return {
    type: "ip",
    ip,
    response: result.data
  };
}


// ==========================================
// URL
// ==========================================

async function urlLookup(input) {

  const value =
    String(input || "").trim();


  if (!value) {

    throw new Error(
      "URL required."
    );
  }


  let urlString = value;

  if (
    !/^https?:\/\//i.test(urlString)
  ) {
    urlString =
      "https://" + urlString;
  }


  let parsed;

  try {
    parsed =
      new URL(urlString);
  } catch {

    throw new Error(
      "Invalid URL."
    );
  }


  const hostname =
    parsed.hostname;


  let dnsRecords = {};

  try {

    const [
      ipv4,
      ipv6,
      mx,
      ns
    ] = await Promise.allSettled([
      dns.resolve4(hostname),
      dns.resolve6(hostname),
      dns.resolveMx(hostname),
      dns.resolveNs(hostname)
    ]);


    dnsRecords = {
      A:
        ipv4.status === "fulfilled"
          ? ipv4.value
          : [],

      AAAA:
        ipv6.status === "fulfilled"
          ? ipv6.value
          : [],

      MX:
        mx.status === "fulfilled"
          ? mx.value
          : [],

      NS:
        ns.status === "fulfilled"
          ? ns.value
          : []
    };

  } catch {
    dnsRecords = {};
  }


  return {
    type: "url",

    original:
      value,

    protocol:
      parsed.protocol,

    hostname:
      parsed.hostname,

    port:
      parsed.port ||
      (
        parsed.protocol ===
        "https:"
          ? "443"
          : "80"
      ),

    pathname:
      parsed.pathname,

    query:
      parsed.search,

    hash:
      parsed.hash,

    origin:
      parsed.origin,

    dns:
      dnsRecords
  };
}


// ==========================================
// UPI
// ==========================================

async function upiLookup(input) {

  const upi =
    String(input || "")
      .trim()
      .toLowerCase();


  if (
    !/^[a-z0-9._-]{2,256}@[a-z0-9.-]{2,64}$/.test(
      upi
    )
  ) {

    throw new Error(
      "Enter a valid UPI ID."
    );
  }


  const parts =
    upi.split("@");


  return {
    type: "upi",

    upi,

    validFormat: true,

    username:
      parts[0],

    handle:
      parts[1],

    note:
      "Format validated. Beneficiary name or account details require an authorized UPI verification provider."
  };
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


    const type =
      String(body.type || "")
        .toLowerCase();

    const input =
      String(body.input || "")
        .trim();


    if (!type) {

      return send(
        res,
        400,
        {
          ok: false,
          error:
            "Lookup type required"
        }
      );
    }


    let result;


    if (type === "mobile") {

      result =
        await mobileLookup(input);

    } else if (type === "pin") {

      result =
        await pinLookup(input);

    } else if (type === "ifsc") {

      result =
        await ifscLookup(input);

    } else if (type === "ip") {

      result =
        await ipLookup(input);

    } else if (type === "url") {

      result =
        await urlLookup(input);

    } else if (type === "upi") {

      result =
        await upiLookup(input);

    } else {

      return send(
        res,
        400,
        {
          ok: false,
          error:
            "Unknown lookup type"
        }
      );
    }


    return send(
      res,
      200,
      {
        ok: true,
        result
      }
    );

  } catch (error) {

    console.error(
      "LOOKUP ERROR:",
      error
    );

    return send(
      res,
      500,
      {
        ok: false,
        error:
          error?.message ||
          "Lookup failed"
      }
    );
  }
}


module.exports = handler;
