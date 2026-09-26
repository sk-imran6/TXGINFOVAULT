const dns = require("dns").promises;
const { parsePhoneNumberFromString } = require("libphonenumber-js");
const { authenticated } = require("./auth");

function clean(value) {
  return String(value || "").trim();
}

async function fetchJSON(url, options = {}) {
  const controller = new AbortController();

  const timeout = setTimeout(() => {
    controller.abort();
  }, 12000);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        "User-Agent": "TXG-Information-Center/1.0",
        Accept: "application/json"
      }
    });

    const text = await response.text();

    let data;

    try {
      data = JSON.parse(text);
    } catch {
      data = {
        raw: text
      };
    }

    return {
      status: response.status,
      ok: response.ok,
      data
    };
  } finally {
    clearTimeout(timeout);
  }
}

function lookupMobile(value) {
  const phone = parsePhoneNumberFromString(value);

  if (!phone) {
    return {
      valid: false,
      message: "Invalid or unsupported phone number"
    };
  }

  return {
    valid: phone.isValid(),
    possible: phone.isPossible(),
    country: phone.country || null,
    countryCallingCode: `+${phone.countryCallingCode}`,
    nationalNumber: phone.nationalNumber,
    internationalFormat: phone.formatInternational(),
    nationalFormat: phone.formatNational(),
    uri: phone.getURI(),
    numberType: phone.getType() || null
  };
}

async function lookupPIN(value) {
  const pin = clean(value);

  if (!/^\d{6}$/.test(pin)) {
    return {
      valid: false,
      message: "PIN code must contain 6 digits"
    };
  }

  const result = await fetchJSON(
    `https://api.postalpincode.in/pincode/${encodeURIComponent(pin)}`
  );

  const data = result.data;

  if (!Array.isArray(data) || !data[0]) {
    return {
      valid: false,
      message: "No result"
    };
  }

  const first = data[0];

  return {
    pin,
    status: first.Status || null,
    message: first.Message || null,
    postOffices: first.PostOffice || []
  };
}

async function lookupIFSC(value) {
  const ifsc = clean(value).toUpperCase();

  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test(ifsc)) {
    return {
      valid: false,
      message: "Invalid IFSC format"
    };
  }

  const result = await fetchJSON(
    `https://ifsc.razorpay.com/${encodeURIComponent(ifsc)}`
  );

  if (!result.ok) {
    return {
      valid: false,
      message: "IFSC not found"
    };
  }

  return result.data;
}

async function lookupIP(value) {
  let ip = clean(value);

  if (!ip) {
    try {
      const result = await fetchJSON("https://api.ipify.org?format=json");
      ip = result.data.ip;
    } catch {
      return {
        valid: false,
        message: "Unable to detect public IP"
      };
    }
  }

  const result = await fetchJSON(
    `https://ipwho.is/${encodeURIComponent(ip)}`
  );

  return result.data;
}

async function getDomainRDAP(hostname) {
  const domain = hostname.toLowerCase().replace(/^www\./, "");

  const suffix = domain.split(".").slice(-2).join(".");

  const rdapServers = {
    "com": "https://rdap.verisign.com/com/v1/domain/",
    "net": "https://rdap.verisign.com/net/v1/domain/",
    "org": "https://rdap.publicinterestregistry.org/rdap/domain/",
    "info": "https://rdap.identitydigital.services/rdap/domain/",
    "biz": "https://rdap.identitydigital.services/rdap/domain/",
    "io": "https://rdap.identitydigital.services/rdap/domain/"
  };

  const tld = domain.split(".").pop();

  let endpoint = rdapServers[tld];

  if (!endpoint) {
    endpoint = `https://rdap.org/domain/${encodeURIComponent(domain)}`;
  } else {
    endpoint += encodeURIComponent(domain);
  }

  try {
    const result = await fetchJSON(endpoint);

    if (!result.ok || !result.data) {
      return null;
    }

    const data = result.data;

    let created = null;
    let expires = null;

    for (const event of data.events || []) {
      if (event.eventAction === "registration") {
        created = event.eventDate;
      }

      if (event.eventAction === "expiration") {
        expires = event.eventDate;
      }
    }

    let registrar = null;

    for (const entity of data.entities || []) {
      if (entity.roles && entity.roles.includes("registrar")) {
        registrar =
          entity.vcardArray &&
          entity.vcardArray[1] &&
          entity.vcardArray[1].find(
            item => item[0] === "fn"
          );

        registrar = registrar ? registrar[3] : null;
      }
    }

    let ageDays = null;

    if (created) {
      ageDays = Math.floor(
        (Date.now() - new Date(created).getTime()) /
          86400000
      );
    }

    return {
      domain,
      created,
      ageDays,
      expires,
      registrar,
      status: data.status || [],
      nameservers: (data.nameservers || []).map(
        item => item.ldhName
      )
    };
  } catch {
    return null;
  }
}

async function lookupURL(value) {
  let parsed;

  try {
    parsed = new URL(value);
  } catch {
    throw new Error("Invalid URL");
  }

  if (!/^https?:$/.test(parsed.protocol)) {
    throw new Error("Only HTTP/HTTPS URLs are supported");
  }

  const domainInfo = await getDomainRDAP(parsed.hostname);

  let website = {
    reachable: false,
    status: null,
    finalUrl: null,
    https: parsed.protocol === "https:",
    title: null,
    contentType: null
  };

  try {
    const response = await fetch(parsed.toString(), {
      method: "GET",
      redirect: "follow",
      signal: AbortSignal.timeout(12000),
      headers: {
        "User-Agent": "TXG-Information-Center/1.0"
      }
    });

    const text = await response.text();

    const titleMatch = text.match(
      /<title[^>]*>([\s\S]*?)<\/title>/i
    );

    website = {
      reachable: true,
      status: response.status,
      finalUrl: response.url,
      https: response.url.startsWith("https://"),
      title: titleMatch
        ? titleMatch[1].replace(/\s+/g, " ").trim()
        : null,
      contentType:
        response.headers.get("content-type") || null
    };
  } catch {
    website.reachable = false;
  }

  let dnsInfo = null;

  try {
    const records = await dns.lookup(parsed.hostname, {
      all: true
    });

    dnsInfo = records;
  } catch {
    dnsInfo = null;
  }

  return {
    input: value,
    protocol: parsed.protocol.replace(":", ""),
    hostname: parsed.hostname,
    port: parsed.port || null,
    path: parsed.pathname,
    query: parsed.search || null,
    domain: domainInfo,
    website,
    dns: dnsInfo
  };
}

function lookupUPI(value) {
  const upi = clean(value);

  const valid = /^[A-Za-z0-9._-]{2,256}@[A-Za-z0-9.-]{2,64}$/.test(
    upi
  );

  return {
    upi,
    valid,
    handle: valid ? upi.split("@").slice(1).join("@") : null,
    message: valid
      ? "UPI ID format is valid"
      : "Invalid UPI ID format",
    note:
      "Format validation does not prove account ownership or beneficiary identity."
  };
}

async function handler(req, res) {
  try {
    if (!authenticated(req)) {
      return res.status(401).json({
        ok: false,
        error: "Unauthorized"
      });
    }

    if (req.method !== "GET") {
      res.setHeader("Allow", "GET");

      return res.status(405).json({
        ok: false,
        error: "Method not allowed"
      });
    }

    const type = clean(req.query.type).toLowerCase();
    const value = clean(req.query.value);

    if (!type) {
      return res.status(400).json({
        ok: false,
        error: "Lookup type is required"
      });
    }

    if (!value && type !== "ip") {
      return res.status(400).json({
        ok: false,
        error: "Lookup value is required"
      });
    }

    let result;

    if (type === "mobile") {
      result = lookupMobile(value);
    } else if (type === "pin") {
      result = await lookupPIN(value);
    } else if (type === "ifsc") {
      result = await lookupIFSC(value);
    } else if (type === "ip") {
      result = await lookupIP(value);
    } else if (type === "url") {
      result = await lookupURL(value);
    } else if (type === "upi") {
      result = lookupUPI(value);
    } else {
      return res.status(400).json({
        ok: false,
        error: "Unknown lookup type"
      });
    }

    return res.status(200).json({
      ok: true,
      type,
      result
    });
  } catch (error) {
    console.error("LOOKUP ERROR:", error);

    return res.status(500).json({
      ok: false,
      error: error.message || "Lookup failed"
    });
  }
}

module.exports = handler;
