const {
  parsePhoneNumberFromString
} = require("libphonenumber-js");

const PASSWORD = "TXG@Admin#2026!Secure";

function auth(req, res) {
  const key = req.headers["x-txg-key"];

  if (key !== PASSWORD) {
    res.status(401).json({
      ok: false,
      error: "Unauthorized"
    });
    return false;
  }

  return true;
}

function maskName(value) {
  if (!value) return "Not available";

  return String(value)
    .trim()
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
  return maskName(value);
}

function maskNumber(value) {
  value = String(value);

  if (value.length <= 4) {
    return "*".repeat(value.length);
  }

  return (
    value.slice(0, 2) +
    "*".repeat(value.length - 4) +
    value.slice(-2)
  );
}

async function mobile(value) {
  const phone =
    parsePhoneNumberFromString(
      String(value),
      "IN"
    );

  if (!phone) {
    return {
      valid: false,
      error: "Invalid number"
    };
  }

  return {
    valid: phone.isValid(),
    number: phone.number,
    country: phone.country || "Unknown",
    countryCode: phone.countryCallingCode,
    nationalFormat: phone.formatNational(),
    internationalFormat:
      phone.formatInternational(),
    type:
      phone.getType?.() || "Unknown",

    ownerName: "Not available",
    address: "Not available",
    location: "Not available"
  };
}

function upi(value) {
  const input =
    String(value)
      .trim()
      .toLowerCase();

  const match =
    input.match(
      /^([a-z0-9._-]{2,})@([a-z0-9.-]{2,})$/
    );

  if (!match) {
    return {
      valid: false,
      error: "Invalid UPI ID"
    };
  }

  const local = match[1];
  const handle = match[2];

  return {
    valid: true,
    upi: input,
    handle,

    visibleNumber:
      /^\d{8,15}$/.test(local)
        ? maskNumber(local)
        : "Not present",

    ownerName: "Not available",
    linkedMobile: "Not available",
    address: "Not available"
  };
}

async function ifsc(value) {
  const code =
    String(value)
      .trim()
      .toUpperCase();

  if (!/^[A-Z]{4}0[A-Z0-9]{6}$/.test(code)) {
    return {
      valid: false,
      error: "Invalid IFSC"
    };
  }

  const r = await fetch(
    `https://ifsc.razorpay.com/${code}`
  );

  if (!r.ok) {
    return {
      valid: false,
      error: "IFSC not found"
    };
  }

  const d = await r.json();

  return {
    valid: true,
    bank: d.BANK,
    branch: d.BRANCH,
    address: d.ADDRESS,
    city: d.CITY,
    district: d.DISTRICT,
    state: d.STATE,
    ifsc: d.IFSC
  };
}

async function pin(value) {
  const code = String(value).trim();

  if (!/^\d{6}$/.test(code)) {
    return {
      valid: false,
      error: "Invalid PIN"
    };
  }

  const r = await fetch(
    `https://api.postalpincode.in/pincode/${code}`
  );

  const d = await r.json();

  if (
    !d[0] ||
    d[0].Status !== "Success"
  ) {
    return {
      valid: false,
      error: "PIN not found"
    };
  }

  return {
    valid: true,
    pin: code,
    offices: d[0].PostOffice || []
  };
}

async function email(value) {
  const input =
    String(value).trim().toLowerCase();

  const match =
    input.match(
      /^[^\s@]+@([^\s@]+\.[^\s@]+)$/
    );

  if (!match) {
    return {
      valid: false,
      error: "Invalid email"
    };
  }

  const domain = match[1];

  return {
    valid: true,
    email: input,
    domain
  };
}

async function ip(value) {
  const input = String(value).trim();

  const r = await fetch(
    `https://ipwho.is/${encodeURIComponent(input)}`
  );

  if (!r.ok) {
    return {
      valid: false,
      error: "IP lookup failed"
    };
  }

  const d = await r.json();

  return {
    valid: d.success,
    ip: d.ip,
    country: d.country,
    region: d.region,
    city: d.city,
    latitude: d.latitude,
    longitude: d.longitude,
    isp: d.connection?.isp,
    organization: d.connection?.org,
    asn: d.connection?.asn,
    note:
      "IP location is approximate."
  };
}

module.exports = async function(req, res) {
  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  if (!auth(req, res)) return;

  if (req.method !== "POST") {
    return res.status(405).json({
      ok: false,
      error: "POST required"
    });
  }

  try {
    const {
      type,
      value
    } = req.body || {};

    let data;

    if (type === "mobile") {
      data = await mobile(value);
    }

    else if (type === "upi") {
      data = upi(value);
    }

    else if (type === "ifsc") {
      data = await ifsc(value);
    }

    else if (type === "pin") {
      data = await pin(value);
    }

    else if (type === "email") {
      data = await email(value);
    }

    else if (type === "ip") {
      data = await ip(value);
    }

    else {
      return res.status(400).json({
        ok: false,
        error: "Unknown lookup type"
      });
    }

    return res.json({
      ok: true,
      type,
      data
    });

  } catch (e) {
    return res.status(500).json({
      ok: false,
      error: "Lookup failed"
    });
  }
};
