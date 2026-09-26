const { parsePhoneNumberFromString } = require("libphonenumber-js");
const dns = require("dns").promises;
const { authenticated } = require("./auth");

function send(res, status, data) {
  res.status(status).json(data);
}

function clean(value, max = 500) {
  return String(value || "").trim().slice(0, max);
}

async function getJSON(url, options = {}) {
  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, 10000);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal
    });

    const text = await response.text();

    let data;

    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }

    return {
      status: response.status,
      ok: response.ok,
      data
    };
  } finally {
    clearTimeout(timer);
  }
}

function normalizeIP(ip) {
  return ip
    .trim()
    .replace(/^\[/, "")
    .replace(/\]$/, "");
}

function isIPv4(ip) {
  return /^(\d{1,3}\.){3}\d{1,3}$/.test(ip);
}

function isPrivateIPv4(ip) {
  if (!isIPv4(ip)) return false;

  const p = ip.split(".").map(Number);

  if (p.some(x => x < 0 || x > 255)) return true;

  const [a, b] = p;

  if (a === 10) return true;
  if (a === 127) return true;
  if (a === 169 && b === 254) return true;
  if (a === 172 && b >= 16 && b <= 31) return true;
  if (a === 192 && b === 168) return true;

  return false;
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

async function mobileLookup(value) {
  let phone = parsePhoneNumberFromString(value, "IN");

  if (!phone) {
    phone = parsePhoneNumberFromString(value);
  }

  if (!phone) {
    return {
      type: "Mobile",
      valid: false,
      possible: false,
      message: "Invalid phone number format"
    };
  }

  return {
    type: "Mobile",
    input: value,
    valid: phone.isValid(),
    possible: phone.isPossible(),
    country: phone.country || null,
    countryCallingCode: phone.countryCallingCode || null,
    nationalNumber: phone.nationalNumber || null,
    internationalFormat: phone.formatInternational(),
    nationalFormat: phone.formatNational(),
    uri: phone.getURI()
  };
}

async function pinLookup(pin) {
  if (!/^\d{6}$/.test(pin)) {
    throw new Error("Enter a valid 6-digit PIN code");
  }

  const result = await getJSON(
    `https://api.postalpincode.in/pincode/${encodeURIComponent(pin)}`
  );

  if (!result.ok || !Array.isArray(result.data)) {
    throw new Error("PIN service unavailable");
  }

  return {
    type: "PIN",
    pincode: pin,
    response: result.data
  };
}

async function ifscLookup(ifsc) {
  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/i.test(ifsc)) {
    throw new Error("Invalid IFSC format");
  }

  const result = await getJSON(
    `https://ifsc.razorpay.com/${encodeURIComponent(ifsc.toUpperCase())}`
  );

  if (!result.ok) {
    throw new Error("IFSC not found");
  }

  return {
    type: "IFSC",
    response: result.data
  };
}

async function ipLookup(input) {
  let ip = normalizeIP(input);

  if (!ip) {
    const publicIP = await getJSON("https://api.ipify.org?format=json");

    if (!publicIP.ok || !publicIP.data?.ip) {
      throw new Error("Could not detect public IP");
    }

    ip = publicIP.data.ip;
  }

  if (isPrivateIPv4(ip) || isPrivateIPv6(ip)) {
    throw new Error("Private/local IP lookup is not supported");
  }

  const result = await getJSON(
    `https://ipwho.is/${encodeURIComponent(ip)}`
  );

  if (!result.ok) {
    throw new Error("IP lookup failed");
  }

  return {
    type: "IP",
    response: result.data
  };
}

async function urlLookup(input) {
  let value = input;

  if (!/^https?:\/\//i.test(value)) {
    value = "https://" + value;
  }

  let parsed;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only HTTP/HTTPS URLs are supported");
  }

  let dnsResult = null;

  try {
    dnsResult = await dns.lookup(parsed.hostname, {
      all: true
    });
  } catch {
    dnsResult = [];
  }

  return {
    type: "URL",
    protocol: parsed.protocol,
    hostname: parsed.hostname,
    port: parsed.port || null,
    pathname: parsed.pathname,
    query: parsed.search || null,
    hash: parsed.hash || null,
    origin: parsed.origin,
    dns: dnsResult
  };
}

async function upiLookup(upi) {
  const value = upi.trim();

  if (!/^[A-Za-z0-9._-]{2,256}@[A-Za-z0-9.-]{2,64}$/.test(value)) {
    throw new Error("Invalid UPI ID format");
  }

  const result = {
    type: "UPI",
    upiId: value,
    handle: value.split("@")[1],
    verified: false,
    providerResponse: null,
    message:
      "Format is valid. Beneficiary verification requires an authorized UPI verification provider."
  };

  // Optional authorized provider.
  // No environment variables are required for this project.
  // If you later add your own server-side provider, it can be connected here.

  return result;
}

module.exports = async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return send(res, 405, {
      ok: false,
      error: "Method not allowed"
    });
  }

  if (!authenticated(req)) {
    return send(res, 401, {
      ok: false,
      error: "Authentication required"
    });
  }

  const type = String(req.body?.type || "").toLowerCase();
  const input = clean(req.body?.input, 1000);

  if (!input && type !== "ip") {
    return send(res, 400, {
      ok: false,
      error: "Input required"
    });
  }

  try {
    let result;

    if (type === "mobile") {
      result = await mobileLookup(input);
    } else if (type === "pin") {
      result = await pinLookup(input);
    } else if (type === "ifsc") {
      result = await ifscLookup(input);
    } else if (type === "ip") {
      result = await ipLookup(input);
    } else if (type === "url") {
      result = await urlLookup(input);
    } else if (type === "upi") {
      result = await upiLookup(input);
    } else {
      return send(res, 400, {
        ok: false,
        error: "Unknown lookup type"
      });
    }

    return send(res, 200, {
      ok: true,
      result
    });
  } catch (error) {
    return send(res, 400, {
      ok: false,
      error: error.message || "Lookup failed"
    });
  }
};
