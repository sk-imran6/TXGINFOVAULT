const send = (res, status, data) => {
  return res.status(status).json(data);
};

const clean = (value) => String(value ?? "").trim();

const getRequestValue = (req) => {
  const url = new URL(
    req.url,
    `https://${req.headers.host || "localhost"}`
  );

  return clean(
    url.searchParams.get("value") ||
    url.searchParams.get("query") ||
    url.searchParams.get("q") ||
    url.searchParams.get("input") ||
    url.searchParams.get("message")
  );
};

const getRequestType = (req) => {
  const url = new URL(
    req.url,
    `https://${req.headers.host || "localhost"}`
  );

  return clean(url.searchParams.get("type")).toLowerCase();
};

const fetchJSON = async (url, options = {}) => {
  const controller = new AbortController();

  const timer = setTimeout(() => {
    controller.abort();
  }, 15000);

  try {
    const response = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        Accept: "application/json",
        ...(options.headers || {})
      }
    });

    const text = await response.text();

    let data;

    try {
      data = text ? JSON.parse(text) : {};
    } catch {
      data = {
        raw: text
      };
    }

    if (!response.ok) {
      throw new Error(
        data?.error ||
        data?.message ||
        `HTTP ${response.status}`
      );
    }

    return data;

  } finally {
    clearTimeout(timer);
  }
};

const detectType = (value) => {
  const v = clean(value);

  if (/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v)) {
    return "email";
  }

  if (/^\d{6}$/.test(v)) {
    return "pin";
  }

  if (/^[A-Z]{4}0[A-Z0-9]{6}$/i.test(v)) {
    return "ifsc";
  }

  if (/^\d{10}$/.test(v)) {
    return "mobile";
  }

  if (
    /^(https?:\/\/)?([a-z0-9-]+\.)+[a-z]{2,}(\/.*)?$/i.test(v)
  ) {
    return "url";
  }

  if (
    /^(?:\d{1,3}\.){3}\d{1,3}$/.test(v) ||
    (v.includes(":") && /^[0-9a-f:]+$/i.test(v))
  ) {
    return "ip";
  }

  if (/^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+$/.test(v)) {
    return "upi";
  }

  return "auto";
};

const dnsLookup = async (hostname, type) => {
  try {
    const url =
      `https://dns.google/resolve?name=${encodeURIComponent(hostname)}` +
      `&type=${encodeURIComponent(type)}`;

    const data = await fetchJSON(url);

    return {
      type,
      answers: data.Answer || []
    };

  } catch {
    return {
      type,
      answers: []
    };
  }
};

const lookupMobile = (value) => {
  const digits = value.replace(/\D/g, "");

  const valid =
    digits.length === 10;

  return [{
    input: value,
    normalized: valid
      ? `+91${digits}`
      : value,
    valid,
    country: valid
      ? "India"
      : null,
    country_calling_code: valid
      ? "+91"
      : null,
    number_type: valid
      ? "mobile"
      : "invalid"
  }];
};

const lookupEmail = async (value) => {
  const match = value.match(
    /^([^@\s]+)@([^@\s]+)$/
  );

  if (!match) {
    return [{
      input: value,
      valid: false,
      message: "Invalid email format"
    }];
  }

  const local = match[1];
  const domain = match[2].toLowerCase();

  const dns = {};

  for (const type of [
    "MX",
    "A",
    "AAAA",
    "NS",
    "TXT",
    "CNAME"
  ]) {
    dns[type] = await dnsLookup(
      domain,
      type
    );
  }

  return [{
    input: value,
    valid: true,
    normalized: `${local}@${domain}`,
    local_part: local,
    domain,
    tld: domain.includes(".")
      ? domain.split(".").pop()
      : "",
    dns
  }];
};

const lookupIP = async (value) => {
  const template =
    process.env.IP_API_URL ||
    "https://ipwho.is/{ip}";

  const url = template.replace(
    "{ip}",
    encodeURIComponent(value)
  );

  const data = await fetchJSON(url);

  return [data];
};

const lookupPIN = async (value) => {
  const template =
    process.env.PIN_API_URL ||
    "https://api.postalpincode.in/pincode/{pin}";

  const url = template.replace(
    "{pin}",
    encodeURIComponent(value)
  );

  const data = await fetchJSON(url);

  return Array.isArray(data)
    ? data
    : [data];
};

const lookupIFSC = async (value) => {
  const template =
    process.env.IFSC_API_URL ||
    "https://ifsc.razorpay.com/{ifsc}";

  const url = template.replace(
    "{ifsc}",
    encodeURIComponent(value)
  );

  const data = await fetchJSON(url);

  return [data];
};

const lookupUPI = (value) => {
  const valid =
    /^[a-zA-Z0-9._-]+@[a-zA-Z0-9._-]+$/.test(value);

  return [{
    input: value,
    valid,
    type: "UPI",
    handle: valid
      ? value.split("@")[1]
      : null
  }];
};

const lookupURL = async (value) => {
  let target = value;

  if (!/^https?:\/\//i.test(target)) {
    target = `https://${target}`;
  }

  const parsed = new URL(target);
  const hostname = parsed.hostname;

  const dns = {};

  for (const type of [
    "A",
    "AAAA",
    "MX",
    "NS",
    "TXT",
    "CNAME"
  ]) {
    dns[type] = await dnsLookup(
      hostname,
      type
    );
  }

  let rdap = null;

  try {
    rdap = await fetchJSON(
      `https://rdap.org/domain/${encodeURIComponent(hostname)}`
    );
  } catch {
    rdap = null;
  }

  return [{
    url: target,
    protocol: parsed.protocol,
    hostname,
    pathname: parsed.pathname,
    search: parsed.search,
    dns,
    rdap
  }];
};

const lookupVehicle = async (value) => {
  const apiURL =
    clean(process.env.VEHICLE_API_URL);

  if (!apiURL) {
    return [{
      input: value,
      status: "not_configured",
      message:
        "Vehicle API is not configured yet."
    }];
  }

  const url = apiURL.replace(
    "{vehicle}",
    encodeURIComponent(value)
  );

  const headers = {};

  const key =
    clean(process.env.VEHICLE_API_KEY);

  const headerName =
    clean(process.env.VEHICLE_API_HEADER) ||
    "Authorization";

  if (key) {
    headers[headerName] =
      headerName.toLowerCase() ===
      "authorization"
        ? `Bearer ${key}`
        : key;
  }

  const data = await fetchJSON(url, {
    headers
  });

  return Array.isArray(data)
    ? data
    : [data];
};

const lookupCompany = async (value) => {
  const apiURL =
    clean(process.env.COMPANY_API_URL);

  if (!apiURL) {
    return [{
      input: value,
      status: "not_configured",
      message:
        "Company API is not configured yet."
    }];
  }

  const url = apiURL.replace(
    "{value}",
    encodeURIComponent(value)
  );

  const headers = {};

  const key =
    clean(process.env.COMPANY_API_KEY);

  const headerName =
    clean(process.env.COMPANY_API_HEADER) ||
    "Authorization";

  if (key) {
    headers[headerName] =
      headerName.toLowerCase() ===
      "authorization"
        ? `Bearer ${key}`
        : key;
  }

  const data = await fetchJSON(url, {
    headers
  });

  return Array.isArray(data)
    ? data
    : [data];
};

const lookupCRM = async (value) => {
  const apiURL =
    clean(process.env.CRM_API_URL);

  if (!apiURL) {
    return [{
      input: value,
      status: "not_configured",
      message:
        "CRM API is not configured yet."
    }];
  }

  const url = apiURL.replace(
    "{value}",
    encodeURIComponent(value)
  );

  const headers = {};

  const key =
    clean(process.env.CRM_API_KEY);

  const headerName =
    clean(process.env.CRM_API_HEADER) ||
    "Authorization";

  if (key) {
    headers[headerName] =
      headerName.toLowerCase() ===
      "authorization"
        ? `Bearer ${key}`
        : key;
  }

  const data = await fetchJSON(url, {
    headers
  });

  return Array.isArray(data)
    ? data
    : [data];
};

const lookupCustomAPI = async (value) => {
  return [{
    input: value,
    status: "use_custom_api_manager",
    message:
      "Use the Custom API section to run your saved API."
  }];
};

module.exports = async function handler(req, res) {
  try {
    if (
      req.method !== "GET" &&
      req.method !== "POST"
    ) {
      return send(res, 405, {
        success: false,
        error:
          "GET or POST method required"
      });
    }

    let value = "";
    let requestedType = "";

    if (req.method === "GET") {

      value = getRequestValue(req);
      requestedType = getRequestType(req);

    } else {

      let body = req.body || {};

      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch {
          body = {};
        }
      }

      value = clean(
        body.value ||
        body.query ||
        body.q ||
        body.input ||
        body.message
      );

      requestedType =
        clean(body.type).toLowerCase();
    }

    /*
      IMPORTANT:

      Old frontend was sending:

      /api/lookup?value=XXXX

      New frontend may send:

      /api/lookup?query=XXXX
      /api/lookup?q=XXXX
      /api/lookup?input=XXXX

      All are supported now.
    */

    if (!value) {
      return send(res, 400, {
        success: false,
        error: "Value is required"
      });
    }

    const type =
      requestedType &&
      requestedType !== "auto"
        ? requestedType
        : detectType(value);

    let results = [];

    switch (type) {

      case "mobile":
      case "phone":
      case "number":
        results =
          lookupMobile(value);
        break;

      case "email":
        results =
          await lookupEmail(value);
        break;

      case "ip":
        results =
          await lookupIP(value);
        break;

      case "url":
      case "domain":
        results =
          await lookupURL(value);
        break;

      case "pin":
      case "pincode":
      case "postal":
        results =
          await lookupPIN(value);
        break;

      case "ifsc":
        results =
          await lookupIFSC(value);
        break;

      case "upi":
        results =
          lookupUPI(value);
        break;

      case "vehicle":
      case "car":
      case "rc":
        results =
          await lookupVehicle(value);
        break;

      case "company":
      case "business":
        results =
          await lookupCompany(value);
        break;

      case "crm":
        results =
          await lookupCRM(value);
        break;

      case "custom":
      case "customapi":
        results =
          await lookupCustomAPI(value);
        break;

      default:
        results = [{
          input: value,
          detected_type:
            detectType(value),
          message:
            "No specific lookup type detected."
        }];
    }

    return send(res, 200, {
      success: true,
      query: value,
      type,
      result_count:
        Array.isArray(results)
          ? results.length
          : 1,
      results
    });

  } catch (error) {

    console.error(
      "LOOKUP ERROR:",
      error
    );

    return send(res, 500, {
      success: false,
      error:
        error?.message ||
        "Lookup failed"
    });
  }
};
