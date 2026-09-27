const auth = require("./auth");

const TIMEOUT = 10000;
const MAX_RESULTS = 15;

function clean(value) {
  return String(value || "").trim().slice(0, 500);
}

function result(name, source, data, status = "success") {
  return { name, source, status, data };
}

async function request(url, options = {}) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), TIMEOUT);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "User-Agent": "TXG-Information/9.0",
        "Accept": "application/json,text/plain,*/*",
        ...(options.headers || {})
      }
    });

    const text = await response.text();
    let data;

    try {
      data = JSON.parse(text);
    } catch {
      data = text.slice(0, 15000);
    }

    return {
      ok: response.ok,
      status: response.status,
      headers: response.headers,
      data
    };
  } finally {
    clearTimeout(timer);
  }
}

function isEmail(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}

function isIP(v) {
  return /^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) || v.includes(":");
}

function isPIN(v) {
  return /^\d{6}$/.test(v);
}

function isIFSC(v) {
  return /^[A-Z]{4}0[A-Z0-9]{6}$/i.test(v);
}

function isUPI(v) {
  return /^[a-zA-Z0-9._-]{2,}@[a-zA-Z0-9.-]{2,}$/.test(v);
}

function isPhone(v) {
  const digits = v.replace(/\D/g, "");
  return digits.length >= 8 && digits.length <= 15;
}

function isURL(v) {
  return /^https?:\/\//i.test(v) ||
    /^[a-z0-9.-]+\.[a-z]{2,}(\/.*)?$/i.test(v);
}

function getHost(value) {
  try {
    return new URL(
      /^https?:\/\//i.test(value) ? value : `https://${value}`
    ).hostname.toLowerCase();
  } catch {
    return null;
  }
}

function envURL(name, fallback, placeholder) {
  return (process.env[name] || fallback).replace(
    placeholder,
    encodeURIComponent
  );
}

async function dns(domain, type) {
  const r = await request(
    `https://dns.google/resolve?name=${encodeURIComponent(domain)}&type=${type}`,
    { headers: { Accept: "application/dns-json" } }
  );

  return r.ok
    ? r.data
    : { error: `DNS HTTP ${r.status}` };
}

async function emailLookup(value) {
  const domain = value.split("@")[1].toLowerCase();
  const dnsData = {};

  for (const type of ["A", "AAAA", "MX", "NS", "TXT", "CAA"]) {
    try {
      dnsData[type] = await dns(domain, type);
    } catch (e) {
      dnsData[type] = { error: e.message };
    }
  }

  return result("EMAIL", "Google DNS", {
    input: value,
    normalized: value.toLowerCase(),
    local_part: value.split("@")[0],
    domain,
    dns: dnsData
  });
}

async function domainLookup(value) {
  const host = getHost(value);
  if (!host) throw new Error("Invalid URL/domain");

  let rdap;

  try {
    const r = await request(
      `https://rdap.org/domain/${encodeURIComponent(host)}`
    );

    rdap = r.ok
      ? r.data
      : { error: `RDAP HTTP ${r.status}` };
  } catch (e) {
    rdap = { error: e.message };
  }

  const dnsData = {};

  for (const type of ["A", "AAAA", "MX", "NS", "TXT", "CAA"]) {
    try {
      dnsData[type] = await dns(host, type);
    } catch (e) {
      dnsData[type] = { error: e.message };
    }
  }

  let http;

  try {
    const url = /^https?:\/\//i.test(value)
      ? value
      : `https://${value}`;

    const r = await fetch(url, {
      redirect: "manual",
      signal: AbortSignal.timeout(TIMEOUT),
      headers: { "User-Agent": "TXG-Information/9.0" }
    });

    http = {
      status: r.status,
      location: r.headers.get("location"),
      content_type: r.headers.get("content-type"),
      server: r.headers.get("server"),
      powered_by: r.headers.get("x-powered-by"),
      strict_transport_security:
        r.headers.get("strict-transport-security"),
      content_security_policy:
        r.headers.get("content-security-policy"),
      x_frame_options:
        r.headers.get("x-frame-options")
    };
  } catch (e) {
    http = { error: e.message };
  }

  return result("URL / DOMAIN", "RDAP + DNS + HTTP", {
    hostname: host,
    rdap,
    dns: dnsData,
    http
  });
}

async function ipLookup(value) {
  const template = process.env.IP_API_URL ||
    "https://ipwho.is/{ip}";

  const url = template.replace(
    "{ip}",
    encodeURIComponent(value)
  );

  const r = await request(url);

  if (!r.ok) {
    throw new Error(`IP API HTTP ${r.status}`);
  }

  return result("IP", "IP API", r.data);
}

async function pinLookup(value) {
  const template = process.env.PIN_API_URL ||
    "https://api.postalpincode.in/pincode/{pin}";

  const url = template.replace(
    "{pin}",
    encodeURIComponent(value)
  );

  const r = await request(url);

  if (!r.ok) {
    throw new Error(`PIN API HTTP ${r.status}`);
  }

  return result("PIN", "PIN API", r.data);
}

async function ifscLookup(value) {
  const template = process.env.IFSC_API_URL ||
    "https://ifsc.razorpay.com/{ifsc}";

  const url = template.replace(
    "{ifsc}",
    encodeURIComponent(value.toUpperCase())
  );

  const r = await request(url);

  if (!r.ok) {
    throw new Error(`IFSC API HTTP ${r.status}`);
  }

  return result("IFSC", "IFSC API", r.data);
}

function mobileLookup(value) {
  const digits = value.replace(/\D/g, "");

  return result("MOBILE", "Local validation", {
    input: value,
    digits,
    length: digits.length,
    country_guess:
      digits.startsWith("91") ||
      (digits.length === 10 && /^[6-9]/.test(digits))
        ? "India"
        : "Unknown",
    possible_number:
      digits.length >= 8 && digits.length <= 15
  });
}

function upiLookup(value) {
  return result("UPI", "Format validation", {
    input: value,
    valid_format: isUPI(value),
    handle: isUPI(value) ? value.split("@")[1] : null,
    note:
      "Format validation does not prove account existence or ownership."
  });
}

function companyLookup(value) {
  return result(
    "COMPANY",
    "TXG public-input analysis",
    {
      query: value,
      note:
        "Live company records require an authorized public/company-data provider. Private owner/KYC data is not returned."
    },
    "not_configured"
  );
}

function vehicleLookup(value) {
  const template = process.env.VEHICLE_API_URL;

  if (!template) {
    return result(
      "VEHICLE",
      "Authorized vehicle provider",
      {
        registration_number: value.toUpperCase(),
        configured: false,
        note:
          "Add an authorized vehicle API in VEHICLE_API_URL to enable live vehicle data."
      },
      "not_configured"
    );
  }

  return request(template.replace(
    "{registration}",
    encodeURIComponent(value.toUpperCase())
  ), {
    headers: process.env.VEHICLE_API_KEY
      ? {
          [process.env.VEHICLE_API_HEADER || "Authorization"]:
            process.env.VEHICLE_API_KEY
        }
      : {}
  }).then(r => {
    if (!r.ok) throw new Error(`Vehicle API HTTP ${r.status}`);

    return result(
      "VEHICLE",
      "Authorized vehicle API",
      r.data
    );
  });
}

async function crmLookup(value) {
  const token = process.env.ZOHO_ACCESS_TOKEN;

  if (!token) {
    return result(
      "CRM",
      "Zoho CRM",
      {
        configured: false,
        query: value,
        note:
          "Set ZOHO_ACCESS_TOKEN to enable authorized Zoho CRM search."
      },
      "not_configured"
    );
  }

  const base =
    (process.env.ZOHO_API_BASE ||
      "https://www.zohoapis.in/crm/v8").replace(/\/+$/, "");

  const modules = [
    "Contacts",
    "Leads",
    "Accounts",
    "Deals"
  ];

  const matches = [];

  for (const module of modules) {
    try {
      const url =
        `${base}/${module}/search?word=${encodeURIComponent(value)}`;

      const r = await request(url, {
        headers: {
          Authorization: `Zoho-oauthtoken ${token}`
        }
      });

      matches.push({
        module,
        http_status: r.status,
        data: r.data
      });
    } catch (e) {
      matches.push({
        module,
        error: e.message
      });
    }
  }

  return result("CRM", "Zoho CRM", {
    query: value,
    matches
  });
}

async function customLookup(value) {
  const template = process.env.CUSTOM_API_URL;

  if (!template) {
    return result(
      "CUSTOM API",
      "Custom API",
      {
        configured: false,
        note:
          "Set CUSTOM_API_URL to enable your own API."
      },
      "not_configured"
    );
  }

  const url = template.replace(
    "{message}",
    encodeURIComponent(value)
  );

  const headers = {};

  if (process.env.CUSTOM_API_KEY) {
    headers[
      process.env.CUSTOM_API_HEADER || "Authorization"
    ] = process.env.CUSTOM_API_KEY;
  }

  const r = await request(url, { headers });

  return result(
    "CUSTOM API",
    "Custom API",
    {
      http_status: r.status,
      response: r.data
    },
    r.ok ? "success" : "error"
  );
}

async function handler(req, res) {
  if (req.method !== "GET") {
    res.setHeader("Allow", "GET");
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });
  }

  if (!auth.authenticated(req)) {
    return res.status(401).json({
      success: false,
      error: "Login required"
    });
  }

  const value = clean(req.query?.value);
  let type = clean(req.query?.type).toLowerCase();

  if (!value) {
    return res.status(400).json({
      success: false,
      error: "Enter a value"
    });
  }

  if (!type || type === "auto") {
    if (isEmail(value)) type = "email";
    else if (isIP(value)) type = "ip";
    else if (isPIN(value)) type = "pin";
    else if (isIFSC(value)) type = "ifsc";
    else if (isUPI(value)) type = "upi";
    else if (isURL(value)) type = "url";
    else if (isPhone(value)) type = "mobile";
    else type = "company";
  }

  const results = [];

  async function add(fn) {
    try {
      results.push(await fn());
    } catch (e) {
      results.push(
        result(
          "ERROR",
          "TXG",
          { message: e.message },
          "error"
        )
      );
    }
  }

  if (type === "mobile") {
    await add(() => mobileLookup(value));
    await add(() => crmLookup(value));
  }

  else if (type === "email") {
    await add(() => emailLookup(value));
    await add(() => domainLookup(value.split("@")[1]));
    await add(() => crmLookup(value));
  }

  else if (type === "ip") {
    await add(() => ipLookup(value));
  }

  else if (type === "pin") {
    await add(() => pinLookup(value));
  }

  else if (type === "ifsc") {
    await add(() => ifscLookup(value));
  }

  else if (type === "upi") {
    await add(() => upiLookup(value));
  }

  else if (type === "url" || type === "domain") {
    await add(() => domainLookup(value));
    await add(() => crmLookup(getHost(value) || value));
  }

  else if (type === "vehicle") {
    await add(() => vehicleLookup(value));
  }

  else if (type === "company") {
    await add(() => companyLookup(value));
    await add(() => crmLookup(value));
  }

  else if (type === "crm") {
    await add(() => crmLookup(value));
  }

  else if (type === "custom") {
    await add(() => customLookup(value));
  }

  else {
    await add(() => companyLookup(value));
  }

  return res.status(200).json({
    success: true,
    query: value,
    type,
    result_count: Math.min(results.length, MAX_RESULTS),
    results: results.slice(0, MAX_RESULTS)
  });
}

module.exports = handler;
