// api/custom-apis.js

const crypto = require("crypto");
const { neon } = require("@neondatabase/serverless");

const COOKIE_NAME = "txg_admin_session";

const FALLBACK_SECRET =
  "TXG-INFORMATION-AUTH-2026-CHANGE-ME";

const SESSION_HOURS = 12;


// ==========================================
// AUTH SECRET
// ==========================================

function getSecret() {
  return (
    process.env.AUTH_SECRET ||
    FALLBACK_SECRET
  );
}


// ==========================================
// GET COOKIE
// ==========================================

function getCookie(req, name) {
  const cookieHeader =
    req.headers.cookie || "";

  for (const item of cookieHeader.split(";")) {

    const index = item.indexOf("=");

    if (index === -1) continue;

    const key =
      item.slice(0, index).trim();

    const value =
      item.slice(index + 1).trim();

    if (key === name) {

      try {
        return decodeURIComponent(value);
      } catch {
        return value;
      }

    }
  }

  return null;
}


// ==========================================
// VERIFY SESSION
// ==========================================

function verifySession(token) {

  if (!token) {
    return false;
  }

  const parts = token.split(".");

  if (parts.length !== 2) {
    return false;
  }

  const timestamp =
    Number(parts[0]);

  const signature =
    parts[1];

  if (!Number.isFinite(timestamp)) {
    return false;
  }

  const age =
    Date.now() - timestamp;

  if (
    age < 0 ||
    age >
      SESSION_HOURS *
      60 *
      60 *
      1000
  ) {
    return false;
  }

  const expected =
    crypto
      .createHmac(
        "sha256",
        getSecret()
      )
      .update(
        String(timestamp)
      )
      .digest("hex");

  if (
    signature.length !==
    expected.length
  ) {
    return false;
  }

  try {

    return crypto.timingSafeEqual(
      Buffer.from(
        signature,
        "utf8"
      ),
      Buffer.from(
        expected,
        "utf8"
      )
    );

  } catch {

    return false;

  }
}


// ==========================================
// AUTH CHECK
// ==========================================

function isAuthenticated(req) {

  const token =
    getCookie(
      req,
      COOKIE_NAME
    );

  return verifySession(token);
}


// ==========================================
// CLEAN INPUT
// ==========================================

function clean(
  value,
  max = 500
) {

  if (
    typeof value !==
    "string"
  ) {
    return "";
  }

  return value
    .trim()
    .replace(/[<>]/g, "")
    .slice(0, max);
}


// ==========================================
// GENERATE ID
// ==========================================

function makeId() {

  return (
    Date.now()
      .toString(36) +
    "-" +
    crypto
      .randomBytes(5)
      .toString("hex")
  );
}


// ==========================================
// RESPONSE
// ==========================================

function send(
  res,
  status,
  data
) {

  return res
    .status(status)
    .json(data);
}


// ==========================================
// DATABASE
// ==========================================

async function getDatabase() {

  /*
    Supports:

    DATABASE_URL
    POSTGRES_URL
    STORAGE_DATABASE_URL
    STORAGE_POSTGRES_URL
  */

  const databaseUrl =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.STORAGE_DATABASE_URL ||
    process.env.STORAGE_POSTGRES_URL;

  if (!databaseUrl) {

    throw new Error(
      "Database connection is not configured. Check the Neon environment variable in Vercel."
    );

  }

  const sql =
    neon(databaseUrl);


  // ========================================
  // CREATE TABLE
  // ========================================

  await sql`
    CREATE TABLE IF NOT EXISTS custom_apis (

      id TEXT PRIMARY KEY,

      name TEXT NOT NULL,

      url TEXT NOT NULL,

      method TEXT NOT NULL
        DEFAULT 'GET',

      description TEXT
        DEFAULT '',

      category TEXT
        DEFAULT 'Custom API',

      created_at TIMESTAMPTZ
        NOT NULL
        DEFAULT NOW()

    )
  `;

  return sql;
}


// ==========================================
// MAIN HANDLER
// ==========================================

module.exports =
  async function handler(
    req,
    res
  ) {

    res.setHeader(
      "Cache-Control",
      "no-store, no-cache, must-revalidate"
    );

    res.setHeader(
      "X-Content-Type-Options",
      "nosniff"
    );


    // ======================================
    // LOGIN CHECK
    // ======================================

    if (
      !isAuthenticated(req)
    ) {

      return send(
        res,
        401,
        {
          ok: false,
          error: "Unauthorized"
        }
      );

    }


    try {

      const sql =
        await getDatabase();


      // ====================================
      // GET SAVED APIs
      // ====================================

      if (
        req.method === "GET"
      ) {

        const rows =
          await sql`

            SELECT

              id,

              name,

              url,

              method,

              description,

              category,

              created_at
                AS "createdAt"

            FROM custom_apis

            ORDER BY
              created_at DESC

          `;


        return send(
          res,
          200,
          {
            ok: true,
            apis: rows
          }
        );

      }


      // ====================================
      // ADD API
      // ====================================

      if (
        req.method === "POST"
      ) {

        const body =
          req.body &&
          typeof req.body ===
            "object"
            ? req.body
            : {};


        const name =
          clean(
            body.name,
            80
          );


        const url =
          clean(
            body.url,
            2000
          );


        const method =
          clean(
            body.method ||
              "GET",
            10
          ).toUpperCase();


        const description =
          clean(
            body.description ||
              "",
            300
          );


        const category =
          clean(
            body.category ||
              "Custom API",
            50
          );


        // ==================================
        // NAME
        // ==================================

        if (!name) {

          return send(
            res,
            400,
            {
              ok: false,
              error:
                "API name is required."
            }
          );

        }


        // ==================================
        // URL
        // ==================================

        if (!url) {

          return send(
            res,
            400,
            {
              ok: false,
              error:
                "API URL is required."
            }
          );

        }


        // ==================================
        // VALIDATE URL
        // ==================================

        let parsedUrl;

        try {

          parsedUrl =
            new URL(url);

        } catch {

          return send(
            res,
            400,
            {
              ok: false,
              error:
                "Invalid API URL."
            }
          );

        }


        if (
          parsedUrl.protocol !==
            "https:" &&
          parsedUrl.protocol !==
            "http:"
        ) {

          return send(
            res,
            400,
            {
              ok: false,
              error:
                "Only HTTP/HTTPS URLs are allowed."
            }
          );

        }


        // ==================================
        // METHOD
        // ==================================

        const allowedMethods = [

          "GET",

          "POST",

          "PUT",

          "PATCH",

          "DELETE"

        ];


        if (
          !allowedMethods.includes(
            method
          )
        ) {

          return send(
            res,
            400,
            {
              ok: false,
              error:
                "Invalid HTTP method."
            }
          );

        }


        // ==================================
        // CREATE ID
        // ==================================

        const id =
          makeId();


        // ==================================
        // INSERT
        // ==================================

        const rows =
          await sql`

            INSERT INTO custom_apis (

              id,

              name,

              url,

              method,

              description,

              category

            )

            VALUES (

              ${id},

              ${name},

              ${url},

              ${method},

              ${description},

              ${category}

            )

            RETURNING

              id,

              name,

              url,

              method,

              description,

              category,

              created_at
                AS "createdAt"

          `;


        return send(
          res,
          201,
          {
            ok: true,
            api: rows[0]
          }
        );

      }


      // ====================================
      // REMOVE API
      // ====================================

      if (
        req.method === "DELETE"
      ) {

        let id =
          req.query?.id ||
          req.body?.id;


        id =
          clean(
            id,
            150
          );


        if (!id) {

          return send(
            res,
            400,
            {
              ok: false,
              error:
                "API ID is required."
            }
          );

        }


        const rows =
          await sql`

            DELETE FROM custom_apis

            WHERE id = ${id}

            RETURNING id

          `;


        if (
          !rows.length
        ) {

          return send(
            res,
            404,
            {
              ok: false,
              error:
                "API not found."
            }
          );

        }


        return send(
          res,
          200,
          {
            ok: true,
            removed: id
          }
        );

      }


      // ====================================
      // INVALID METHOD
      // ====================================

      res.setHeader(
        "Allow",
        "GET, POST, DELETE"
      );


      return send(
        res,
        405,
        {
          ok: false,
          error:
            "Method not allowed."
        }
      );


    } catch (error) {

      console.error(
        "CUSTOM API DATABASE ERROR:",
        error
      );


      return send(
        res,
        500,
        {
          ok: false,
          error:
            error?.message ||
            "Database error."
        }
      );

    }

  };
