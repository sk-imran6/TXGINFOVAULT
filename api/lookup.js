import {
  parsePhoneNumberFromString
} from "libphonenumber-js/max";

import crypto from "crypto";

const SESSION_SECRET = process.env.SESSION_SECRET;

function base64urlDecode(value) {
  value = value.replace(/-/g, "+").replace(/_/g, "/");

  while (value.length % 4) {
    value += "=";
  }

  return Buffer.from(value, "base64").toString();
}

function sign(data) {
  return Buffer.from(
    crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(data)
      .digest()
  )
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function verifyToken(token) {
  try {
    if (!token || !SESSION_SECRET) return false;

    const parts = token.split(".");

    if (parts.length !== 2) return false;

    const encoded = parts[0];
    const signature = parts[1];

    const expected = sign(encoded);

    const a = Buffer.from(signature);
    const b = Buffer.from(expected);

    if (
      a.length !== b.length ||
      !crypto.timingSafeEqual(a, b)
    ) {
      return false;
    }

    const payload = JSON.parse(
      base64urlDecode(encoded)
    );

    if (!payload.exp || Date.now() > payload.exp) {
      return false;
    }

    return true;
  } catch {
    return false;
  }
}

function clean(value, max = 200) {
  return String(value || "")
    .trim()
    .slice(0, max);
}

function maskNumber(number) {
  const digits = String(number).replace(/\D/g, "");

  if (digits.length <= 6) {
    return "*".repeat(digits.length);
  }

  return (
    digits.slice(0, 4) +
    "*".repeat(Math.max(1, digits.length - 6)) +
    digits.slice(-2)
  );
}

function isPrivateIP(ip) {
  const value = String(ip);

  if (
    value === "127.0.0.1" ||
    value === "::1" ||
    value.startsWith("10.") ||
    value.startsWith("192.168.") ||
    value.startsWith("172.16.") ||
    value.startsWith("172.17.") ||
    value.startsWith("172.18.") ||
    value.startsWith("172.19.") ||
    value.startsWith("172.20.") ||
    value.startsWith("172.21.") ||
    value.startsWith("172.22.") ||
    value.startsWith("172.23.") ||
    value.startsWith("172.24.") ||
    value.startsWith("172.25.") ||
    value.startsWith("172.26.") ||
    value.startsWith("172.27.") ||
    value.startsWith("172.28.") ||
    value.startsWith("172.29.") ||
    value.startsWith("172.30.") ||
    value.startsWith("172.31.")
  ) {
    return true;
  }

  return false;
}

async function jsonFetch(url) {
  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, 7000);

  try {
    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "TXG-Information/1.0"
      },
      signal: controller.signal
    });

    if (!response.ok) {
      throw new Error("Provider error");
    }

    return await response.json();
  } finally {
    clearTimeout(timer);
  }
}

async function dnsLookup(name, type) {
  const host = encodeURIComponent(name);

  return await jsonFetch(
    `https://dns.google/resolve?name=${host}&type=${type}`
  );
}

async function mobileLookup(value) {
  const phone = parsePhoneNumberFromString(
    value,
    "IN"
  );

  if (!phone) {
    return {
      type: "mobile",
      valid: false,
      error: "Could not parse number"
    };
  }

  const valid = phone.isValid();
  const possible = phone.isPossible();

  return {
    type: "mobile",
    valid,
    possible,
    number: maskNumber(phone.number),
    country: phone.country || null,
    countryCode: "+" + phone.countryCallingCode,
    nationalFormat: phone.formatNational(),
    internationalFormat: phone.formatInternational(),
    numberType: phone.getType() || "UNKNOWN",
    ownerName: "Not available",
    address: "Not available",
    liveLocation: "Not available"
  };
}

async function ifscLookup(value) {
  const ifsc = clean(value, 20).toUpperCase();

  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) {
    return {
      type: "ifsc",
      valid: false,
      error: "Invalid IFSC format"
    };
  }

  const data = await jsonFetch(
    `https://ifsc.razorpay.com/${encodeURIComponent(ifsc)}`
  );

  return {
    type: "ifsc",
    valid: true,
    ...data
  };
}

async function pinLookup(value) {
  const pin = clean(value, 10);

  if (!/^\d{6}$/.test(pin)) {
    return {
      type: "pincode",
      valid: false,
      error: "PIN must contain 6 digits"
    };
  }

  const data = await jsonFetch(
    `https://api.postalpincode.in/pincode/${pin}`
  );

  const first = Array.isArray(data)
    ? data[0]
    : null;

  return {
    type: "pincode",
    pin,
    status: first?.Status || null,
    message: first?.Message || null,
    postOffices: first?.PostOffice || []
  };
}

async function emailLookup(value) {
  const email = clean(value, 254).toLowerCase();

  const match =
    /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

  if (!match) {
    return {
      type: "email",
      valid: false,
      email
    };
  }

  const domain = email.split("@")[1];

  const mx = await dnsLookup(domain, "MX");

  const ns = await dnsLookup(domain, "NS");

  return {
    type: "email",
    valid: true,
    email,
    domain,
    mxAvailable:
      Array.isArray(mx.Answer) &&
      mx.Answer.length > 0,
    mxRecords: mx.Answer || [],
    nsRecords: ns.Answer || [],
    ownerName: "Not available"
  };
}

async function ipLookup(value) {
  const ip = clean(value, 80);

  if (isPrivateIP(ip)) {
    return {
      type: "ip",
      valid: false,
      error: "Private/local IP addresses are not queried"
    };
  }

  const data = await jsonFetch(
    `https://ipwho.is/${encodeURIComponent(ip)}`
  );

  return {
    type: "ip",
    ...data
  };
}

async function domainLookup(value) {
  let domain = clean(value, 253)
    .toLowerCase()
    .replace(/^https?:\/\//, "")
    .split("/")[0];

  if (
    !domain ||
    domain.length > 253 ||
    !/^[a-z0-9.-]+$/.test(domain)
  ) {
    return {
      type: "domain",
      valid: false,
      error: "Invalid domain"
    };
  }

  const [a, mx, ns, txt] = await Promise.all([
    dnsLookup(domain, "A"),
    dnsLookup(domain, "MX"),
    dnsLookup(domain, "NS"),
    dnsLookup(domain, "TXT")
  ]);

  return {
    type: "domain",
    valid: true,
    domain,
    aRecords: a.Answer || [],
    mxRecords: mx.Answer || [],
    nsRecords: ns.Answer || [],
    txtRecords: txt.Answer || []
  };
}

async function urlLookup(value) {
  const raw = clean(value, 2048);

  let url;

  try {
    url = new URL(
      /^https?:\/\//i.test(raw)
        ? raw
        : "https://" + raw
    );
  } catch {
    return {
      type: "url",
      valid: false,
      error: "Invalid URL"
    };
  }

  if (
    url.protocol !== "http:" &&
    url.protocol !== "https:"
  ) {
    return {
      type: "url",
      valid: false,
      error: "Only HTTP/HTTPS URLs are supported"
    };
  }

  const hostname = url.hostname;

  if (
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname.endsWith(".local")
  ) {
    return {
      type: "url",
      valid: false,
      error: "Local URLs are blocked"
    };
  }

  const dns = await dnsLookup(hostname, "A");

  return {
    type: "url",
    valid: true,
    protocol: url.protocol,
    hostname,
    port: url.port || null,
    pathname: url.pathname,
    hasQuery: Boolean(url.search),
    hasFragment: Boolean(url.hash),
    dnsRecords: dns.Answer || [],
    note:
      "This checker does not download or execute the target URL."
  };
}

async function upiLookup(value) {
  const upi = clean(value, 200).toLowerCase();

  const valid =
    /^[a-z0-9._-]{2,256}@[a-z0-9.-]{2,64}$/.test(upi);

  let detectedNumber = null;

  if (valid) {
    const beforeAt = upi.split("@")[0];

    if (/^\d{8,15}$/.test(beforeAt)) {
      detectedNumber = beforeAt;
    }
  }

  return {
    type: "upi",
    valid,
    upiId: upi,
    detectedNumber,
    providerHandle:
      valid ? upi.split("@")[1] : null,
    ownerName: "Not available",
    linkedMobile: "Not available"
  };
}

async function ffLookup(value) {
  const id = clean(value, 50);

  return {
    type: "ffid",
    valid: Boolean(id),
    ffId: id,
    status:
      "Public/authorized FF profile provider not configured",
    information: null
  };
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader(
    "Referrer-Policy",
    "no-referrer"
  );

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "POST only"
    });
  }

  const auth =
    req.headers.authorization || "";

  const token = auth.startsWith("Bearer ")
    ? auth.slice(7)
    : "";

  if (!verifyToken(token)) {
    return res.status(401).json({
      success: false,
      error: "Session expired"
    });
  }

  try {
    const body = req.body || {};

    const moduleName = clean(
      body.module,
      30
    );

    const value = clean(
      body.value,
      2048
    );

    if (!value) {
      return res.status(400).json({
        success: false,
        error: "Input required"
      });
    }

    let result;

    switch (moduleName) {
      case "mobile":
        result = await mobileLookup(value);
        break;

      case "ifsc":
        result = await ifscLookup(value);
        break;

      case "pincode":
        result = await pinLookup(value);
        break;

      case "email":
        result = await emailLookup(value);
        break;

      case "ip":
        result = await ipLookup(value);
        break;

      case "domain":
        result = await domainLookup(value);
        break;

      case "url":
        result = await urlLookup(value);
        break;

      case "upi":
        result = await upiLookup(value);
        break;

      case "ffid":
        result = await ffLookup(value);
        break;

      default:
        return res.status(400).json({
          success: false,
          error: "Unknown lookup"
        });
    }

    return res.status(200).json({
      success: true,
      result
    });

  } catch (error) {
    return res.status(500).json({
      success: false,
      error: "Lookup provider unavailable"
    });
  }
}
