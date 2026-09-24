import crypto from "crypto";

const PASSWORD = process.env.ADMIN_PASSWORD;
const SESSION_SECRET = process.env.SESSION_SECRET;

function base64url(input) {
  return Buffer.from(input)
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function sign(data) {
  return base64url(
    crypto
      .createHmac("sha256", SESSION_SECRET)
      .update(data)
      .digest()
  );
}

export default async function handler(req, res) {
  res.setHeader("Cache-Control", "no-store");

  if (req.method !== "POST") {
    return res.status(405).json({
      success: false,
      error: "POST only"
    });
  }

  if (!PASSWORD || !SESSION_SECRET) {
    return res.status(500).json({
      success: false,
      error: "Server security variables are not configured"
    });
  }

  const password = String(req.body?.password || "");

  if (!password || password.length > 200) {
    return res.status(400).json({
      success: false,
      error: "Invalid password"
    });
  }

  const supplied = crypto
    .createHash("sha256")
    .update(password)
    .digest("hex");

  const expected = crypto
    .createHash("sha256")
    .update(PASSWORD)
    .digest("hex");

  const a = Buffer.from(supplied);
  const b = Buffer.from(expected);

  if (
    a.length !== b.length ||
    !crypto.timingSafeEqual(a, b)
  ) {
    return res.status(401).json({
      success: false,
      error: "Wrong password"
    });
  }

  const exp = Date.now() + 60 * 60 * 1000;

  const payload = JSON.stringify({
    iat: Date.now(),
    exp
  });

  const encoded = base64url(payload);
  const signature = sign(encoded);

  return res.status(200).json({
    success: true,
    token: encoded + "." + signature,
    expiresAt: exp
  });
}
