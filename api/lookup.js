const dns = require("dns").promises;
const {
  parsePhoneNumberFromString
} = require("libphonenumber-js");

function json(res, status, data) {
  res.setHeader(
    "Cache-Control",
    "no-store"
  );

  res.setHeader(
    "X-Content-Type-Options",
    "nosniff"
  );

  return res.status(status).json(data);
}

function clean(value) {
  return String(value || "").trim();
}

function validPin(pin) {
  return /^[1-9][0-9]{5}$/.test(pin);
}

function validIfsc(ifsc) {
  return /^[A-Z]{4}0[A-Z0-9]{6}$/.test(
    ifsc.toUpperCase()
  );
}

function validUpi(upi) {
  return /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9.-]{2,64}$/.test(
    upi
  );
}

function mask(value) {
  const s = String(value || "");

  if (s.length <= 2) return s;

  if (s.length <= 4) {
    return s[0] + "***" + s[s.length - 1];
  }

  return (
    s.slice(0, 2) +
    "***" +
    s.slice(-1)
  );
}

module.exports = async (req, res) => {
  if (req.method !== "POST") {
    return json(res, 405, {
      ok: false,
      message: "POST required"
    });
  }

  try {
    const type = clean(req.body?.type);
    const value = clean(req.body?.value);

    if (!type || !value) {
      return json(res, 400, {
        ok: false,
        message: "Type and value required"
      });
    }

    // ==========================
    // MOBILE
    // ==========================

    if (type === "mobile") {
      const phone =
        parsePhoneNumberFromString(
          value,
          "IN"
        );

      if (!phone) {
        return json(res, 200, {
          ok: false,
          type: "mobile",
          valid: false,
          message:
            "Invalid phone number"
        });
      }

      return json(res, 200, {
        ok: true,
        type: "mobile",
        valid: phone.isValid(),
        possible: phone.isPossible(),
        country:
          phone.country || null,
        callingCode:
          "+" + phone.countryCallingCode,
        nationalNumber:
          phone.nationalNumber,
        international:
          phone.formatInternational(),
        e164:
          phone.number,
        type:
          phone.getType() || "UNKNOWN"
      });
    }

    // ==========================
    // PIN
    // ==========================

    if (type === "pin") {
      if (!validPin(value)) {
        return json(res, 400, {
          ok: false,
          message: "Invalid PIN"
        });
      }

      const response = await fetch(
        `https://api.pincodeapi.in/api/v1/pincode/${value}`
      );

      const raw =
        await response.text();

      let data = raw;

      try {
        data = JSON.parse(raw);
      } catch (_) {}

      return json(res, 200, {
        ok: response.ok,
        type: "pin",
        input: value,
        response: data
      });
    }

    // ==========================
    // IFSC
    // ==========================

    if (type === "ifsc") {
      const ifsc =
        value.toUpperCase();

      if (!validIfsc(ifsc)) {
        return json(res, 400, {
          ok: false,
          message: "Invalid IFSC"
        });
      }

      const response = await fetch(
        `https://ifsc.razorpay.com/${encodeURIComponent(ifsc)}`
      );

      const raw =
        await response.text();

      let data = raw;

      try {
        data = JSON.parse(raw);
      } catch (_) {}

      return json(res, 200, {
        ok: response.ok,
        type: "ifsc",
        input: ifsc,
        response: data
      });
    }

    // ==========================
    // IP
    // ==========================

    if (type === "ip") {
      const response = await fetch(
        `https://ipwho.is/${encodeURIComponent(value)}`
      );

      const data =
        await response.json();

      return json(res, 200, {
        ok: response.ok,
        type: "ip",
        response: data
      });
    }

    // ==========================
    // URL
    // ==========================

    if (type === "url") {
      let parsed;

      try {
        parsed = new URL(value);
      } catch (_) {
        return json(res, 400, {
          ok: false,
          message: "Invalid URL"
        });
      }

      if (
        parsed.protocol !== "http:" &&
        parsed.protocol !== "https:"
      ) {
        return json(res, 400, {
          ok: false,
          message:
            "Only HTTP/HTTPS URLs are supported"
        });
      }

      let addresses = [];

      try {
        addresses =
          await dns.lookup(
            parsed.hostname,
            { all: true }
          );
      } catch (_) {}

      return json(res, 200, {
        ok: true,
        type: "url",
        protocol:
          parsed.protocol,
        hostname:
          parsed.hostname,
        port:
          parsed.port ||
          (parsed.protocol === "https:"
            ? "443"
            : "80"),
        pathname:
          parsed.pathname,
        search:
          parsed.search,
        hash:
          parsed.hash,
        resolvedAddresses:
          addresses.map(
            x => x.address
          )
      });
    }

    // ==========================
    // UPI
    // ==========================

    if (type === "upi") {
      if (!validUpi(value)) {
        return json(res, 200, {
          ok: false,
          type: "upi",
          valid: false,
          message:
            "Invalid UPI ID format"
        });
      }

      const parts = value.split("@");

      const result = {
        ok: true,
        type: "upi",
        valid: true,
        upiId: value,
        handle: "@" + parts[1],
        userPart: parts[0],
        verification:
          "Format validation only"
      };

      /*
       * Optional authorized provider.
       * Configure UPI_VALIDATE_URL and UPI_API_KEY
       * only if you have an authorized provider.
       */

      if (
        process.env.UPI_VALIDATE_URL &&
        process.env.UPI_API_KEY
      ) {
        try {
          const endpoint =
            process.env.UPI_VALIDATE_URL;

          const response = await fetch(
            endpoint,
            {
              method: "POST",
              headers: {
                "Content-Type":
                  "application/json",
                "Authorization":
                  "Bearer " +
                  process.env.UPI_API_KEY
              },
              body: JSON.stringify({
                vpa: value
              })
            }
          );

          const raw =
            await response.text();

          let providerData = raw;

          try {
            providerData =
              JSON.parse(raw);
          } catch (_) {}

          result.provider =
            providerData;
        } catch (error) {
          result.providerError =
            error.message;
        }
      }

      return json(res, 200, result);
    }

    return json(res, 400, {
      ok: false,
      message: "Unknown lookup type"
    });

  } catch (error) {
    console.error(error);

    return json(res, 500, {
      ok: false,
      message: error.message
    });
  }
};
