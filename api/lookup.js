const dns = require("dns").promises;
const net = require("net");

const {
  requireAuth
} = require("../lib/auth");

const {
  parsePhoneNumberFromString
} = require("libphonenumber-js");

function headers(res) {
  res.setHeader("Cache-Control", "no-store");
  res.setHeader("X-Content-Type-Options", "nosniff");
  res.setHeader("X-Frame-Options", "DENY");
  res.setHeader("Referrer-Policy", "no-referrer");
}

function maskName(value) {
  value = String(value || "").trim();

  if (!value || value === "Not available") {
    return "Not available";
  }

  return value
    .split(/\s+/)
    .map(word => {
      if (word.length <= 3) {
        return "*".repeat(word.length);
      }

      return (
        word.slice(0, 2) +
        "*".repeat(word.length - 3) +
        word.slice(-1)
      );
    })
    .join(" ");
}

function maskAddress(value) {
  value = String(value || "").trim();

  if (!value || value === "Not available") {
    return "Not available";
  }

  return value
    .split(/\s+/)
    .map(word => {
      if (word.length <= 3) {
        return "*".repeat(word.length);
      }

      return (
        word.slice(0, 2) +
        "*".repeat(word.length - 3) +
        word.slice(-1)
      );
    })
    .join(" ");
}

/*
 * IMPORTANT:
 *
 * This function intentionally does NOT scrape telecom/KYC databases.
 *
 * If you have an authorized provider that legitimately returns
 * subscriber information, integrate that provider here.
 */
async function getAuthorizedSubscriberData(phone) {
  return {
    name: null,
    address: null
  };
}

async function mobileLookup(input) {
  const raw = String(input || "").trim();

  const phone = parsePhoneNumberFromString(
    raw,
    "IN"
  );

  if (!phone) {
    return {
      valid: false,
      error: "Invalid phone number"
    };
  }

  const subscriber =
    await getAuthorizedSubscriberData(phone.number);

  return {
    valid: phone.isValid(),
    possible: phone.isPossible(),

    number: phone.number,
    country: phone.country || "Unknown",
    countryCode: phone.countryCallingCode,

    nationalFormat: phone.formatNational(),
    internationalFormat: phone.formatInternational(),

    numberType:
      phone.getType?.() || "Unknown",

    ownerName: maskName(subscriber.name),
    address: maskAddress(subscriber.address),

    liveLocation: "Not available"
  };
}

async function ifscLookup(ifsc) {
  const code = String(ifsc || "")
    .trim()
    .toUpperCase();

  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test(code)) {
    return {
      valid: false,
      error: "Invalid IFSC format"
    };
  }

  const response = await fetch(
    `https://ifsc.razorpay.com/${encodeURIComponent(code)}`
  );

  if (!response.ok) {
    return {
      valid: false,
      error: "IFSC not found"
    };
  }

  const data = await response.json();

  return {
    valid: true,
    ifsc: data.IFSC || code,
    bank: data.BANK || "Unknown",
    branch: data.BRANCH || "Unknown",
    address: data.ADDRESS || "Unknown",
    city: data.CITY || "Unknown",
    district: data.DISTRICT || "Unknown",
    state: data.STATE || "Unknown"
  };
}

async function pinLookup(pin) {
  const code = String(pin || "").trim();

  if (!/^\d{6}$/.test(code)) {
    return {
      valid: false,
      error: "PIN must contain 6 digits"
    };
  }

  const response = await fetch(
    `https://api.postalpincode.in/pincode/${code}`
  );

  if (!response.ok) {
    return {
      valid: false,
      error: "PIN lookup failed"
    };
  }

  const data = await response.json();

  const result = data?.[0];

  if (!result || result.Status !== "Success") {
    return {
      valid: false,
      error: "PIN not found"
    };
  }

  return {
    valid: true,
    pin: code,
    message: result.Message,
    offices: (result.PostOffice || []).map(item => ({
      name: item.Name,
      branchType: item.BranchType,
      deliveryStatus: item.DeliveryStatus,
      district: item.District,
      division: item.Division,
      region: item.Region,
      state: item.State,
      country: item.Country
    }))
  };
}

async function emailLookup(email) {
  const value = String(email || "")
    .trim()
    .toLowerCase();

  const match =
    value.match(/^[^\s@]+@([^\s@]+\.[^\s@]+)$/);

  if (!match) {
    return {
      valid: false,
      error: "Invalid email address"
    };
  }

  const domain = match[1];

  let mx = [];
  let ns = [];

  try {
    mx = await dns.resolveMx(domain);
  } catch {}

  try {
    ns = await dns.resolveNs(domain);
  } catch {}

  return {
    valid: true,
    email: value,
    domain,
    hasMX: mx.length > 0,
    mx: mx.sort((a, b) => a.priority - b.priority),
    ns
  };
}

async function ipLookup(ip) {
  const value = String(ip || "").trim();

  if (!net.isIP(value)) {
    return {
      valid: false,
      error: "Invalid IP address"
    };
  }

  const response = await fetch(
    `https://ipwho.is/${encodeURIComponent(value)}`
  );

  if (!response.ok) {
    return {
      valid: false,
      error: "IP lookup failed"
    };
  }

  const data = await response.json();

  return {
    valid: Boolean(data.success),
    ip: data.ip || value,
    type: data.type || "Unknown",
    continent: data.continent || "Unknown",
    country: data.country || "Unknown",
    region: data.region || "Unknown",
    city: data.city || "Unknown",
    latitude: data.latitude ?? null,
    longitude: data.longitude ?? null,
    isp: data.connection?.isp || "Unknown",
    organization: data.connection?.org || "Unknown",
    asn: data.connection?.asn || "Unknown",
    note: "IP geolocation is approximate and is not a person's exact location."
  };
}

async function domainLookup(domain) {
  let value = String(domain || "")
    .trim()
    .toLowerCase();

  value = value.replace(/^https?:\/\//, "");
  value = value.split("/")[0];

  if (
    !/^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i.test(
      value
    )
  ) {
    return {
      valid: false,
      error: "Invalid domain"
    };
  }

  const result = {
    valid: true,
    domain: value,
    A: [],
    AAAA: [],
    MX: [],
    NS: [],
    TXT: []
  };

  try {
    result.A = await dns.resolve4(value);
  } catch {}

  try {
    result.AAAA = await dns.resolve6(value);
  } catch {}

  try {
    result.MX = await dns.resolveMx(value);
  } catch {}

  try {
    result.NS = await dns.resolveNs(value);
  } catch {}

  try {
    result.TXT = await dns.resolveTxt(value);
  } catch {}

  return result;
}

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return false;
  }

  const [a, b] = parts;

  return (
    a === 10 ||
    a === 127 ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    a === 0
  );
}

function isBlockedHostname(hostname) {
  const host = hostname.toLowerCase();

  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host === "0.0.0.0"
  );
}

async function urlLookup(input) {
  let parsed;

  try {
    parsed = new URL(String(input || "").trim());
  } catch {
    return {
      valid: false,
      error: "Invalid URL"
    };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    return {
      valid: false,
      error: "Only HTTP and HTTPS URLs are supported"
    };
  }

  const hostname = parsed.hostname;

  if (isBlockedHostname(hostname)) {
    return {
      valid: false,
      safe: false,
      error: "Local/internal hostnames are blocked"
    };
  }

  if (net.isIP(hostname) === 4 && isPrivateIPv4(hostname)) {
    return {
      valid: false,
      safe: false,
      error: "Private IP targets are blocked"
    };
  }

  let addresses = [];

  try {
    addresses = await dns.lookup(hostname, {
      all: true
    });
  } catch {
    return {
      valid: false,
      safe: false,
      error: "Hostname could not be resolved"
    };
  }

  const privateTarget = addresses.some(item => {
    return net.isIP(item.address) === 4 &&
      isPrivateIPv4(item.address);
  });

  if (privateTarget) {
    return {
      valid: false,
      safe: false,
      error: "URL resolves to a private IP"
    };
  }

  return {
    valid: true,
    safe: true,
    protocol: parsed.protocol,
    hostname,
    port: parsed.port || "default",
    pathname: parsed.pathname,
    resolvedAddresses: addresses,
    note: "This check does not guarantee that a website is malware-free."
  };
}

function upiLookup(value) {
  const input = String(value || "")
    .trim()
    .toLowerCase();

  const match = input.match(
    /^([a-z0-9._-]{2,})@([a-z0-9.-]{2,})$/
  );

  if (!match) {
    return {
      valid: false,
      error: "Invalid UPI ID format"
    };
  }

  const localPart = match[1];
  const handle = match[2];

  const visibleNumber =
    /^\d{8,15}$/.test(localPart)
      ? localPart
      : null;

  return {
    valid: true,
    upi: input,
    handle,
    visibleNumber: visibleNumber
      ? maskNumber(visibleNumber)
      : "Not present in UPI ID",

    ownerName: "Not available",
    linkedMobile: "Not available",
    address: "Not available",

    note:
      "A UPI ID does not by itself reveal hidden private KYC or linked-mobile data."
  };
}

function maskNumber(number) {
  const value = String(number || "");

  if (value.length <= 4) {
    return "*".repeat(value.length);
  }

  return (
    value.slice(0, 2) +
    "*".repeat(value.length - 4) +
    value.slice(-2)
  );
}

async function ffLookup(ffid) {
  const id = String(ffid || "").trim();

  if (!id) {
    return {
      valid: false,
      error: "FF ID required"
    };
  }

  return {
    valid: true,
    ffId: id,
    status: "Provider not configured",
    playerName: "Not available",
    region: "Not available",
    note:
      "Connect an authorized/public FF profile provider to retrieve profile information."
  };
}

module.exports = async function handler(req, res) {
  headers(res);

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "POST required"
    });
  }

  const authenticated = await requireAuth(req, res);

  if (!authenticated) {
    return;
  }

  try {
    const {
      type,
      value
    } = req.body || {};

    let data;

    switch (type) {
      case "mobile":
        data = await mobileLookup(value);
        break;

      case "upi":
        data = upiLookup(value);
        break;

      case "ifsc":
        data = await ifscLookup(value);
        break;

      case "pin":
        data = await pinLookup(value);
        break;

      case "email":
        data = await emailLookup(value);
        break;

      case "ip":
        data = await ipLookup(value);
        break;

      case "domain":
        data = await domainLookup(value);
        break;

      case "url":
        data = await urlLookup(value);
        break;

      case "ffid":
        data = await ffLookup(value);
        break;

      default:
        return res.status(400).json({
          ok: false,
          error: "Unknown lookup type"
        });
    }

    return res.status(200).json({
      ok: true,
      type,
      data
    });
  } catch (error) {
    console.error(error);

    return res.status(500).json({
      ok: false,
      error: "Lookup failed"
    });
  }
};
