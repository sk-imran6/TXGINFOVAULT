// api/custom-apis.js

const { neon } = require("@neondatabase/serverless");


// ==========================================
// DATABASE
// ==========================================

function getDatabase() {

  const url =
    process.env.DATABASE_URL ||
    process.env.POSTGRES_URL ||
    process.env.STORAGE_DATABASE_URL ||
    process.env.STORAGE_POSTGRES_URL;

  if (!url) {
    throw new Error(
      "DATABASE_URL is not configured"
    );
  }

  return neon(url);
}


// ==========================================
// RESPONSE
// ==========================================

function send(res, status, data) {

  return res
    .status(status)
    .setHeader(
      "Content-Type",
      "application/json"
    )
    .json(data);

}


// ==========================================
// READ BODY
// ==========================================

function readBody(req) {

  if (
    req.body &&
    typeof req.body === "object"
  ) {

    return req.body;

  }

  try {

    return JSON.parse(
      req.body || "{}"
    );

  } catch {

    return {};

  }

}


// ==========================================
// CREATE TABLE
// ==========================================

async function createTable(sql) {

  await sql`

    CREATE TABLE IF NOT EXISTS custom_apis (

      id SERIAL PRIMARY KEY,

      name TEXT NOT NULL,

      url TEXT NOT NULL,

      method TEXT NOT NULL
        DEFAULT 'GET',

      description TEXT
        DEFAULT '',

      category TEXT
        DEFAULT 'Custom API',

      created_at TIMESTAMPTZ
        DEFAULT NOW()

    )

  `;

}


// ==========================================
// MAIN HANDLER
// ==========================================

module.exports = async function handler(
  req,
  res
) {

  try {

    const sql =
      getDatabase();


    await createTable(sql);


    // ======================================
    // GET — LIST SAVED APIs
    // ======================================

    if (req.method === "GET") {

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

          FROM custom_apis

          ORDER BY id DESC

        `;


      return send(
        res,
        200,
        {

          success: true,

          count:
            rows.length,

          apis:
            rows

        }
      );

    }


    // ======================================
    // POST — ADD CUSTOM API
    // ======================================

    if (req.method === "POST") {

      const body =
        readBody(req);


      const name =
        String(
          body.name || ""
        ).trim();


      const url =
        String(
          body.url || ""
        ).trim();


      const method =
        String(
          body.method || "GET"
        )
        .trim()
        .toUpperCase();


      const description =
        String(
          body.description || ""
        ).trim();


      const category =
        String(
          body.category ||
          "Custom API"
        ).trim();


      // ------------------------------------
      // NAME CHECK
      // ------------------------------------

      if (!name) {

        return send(
          res,
          400,
          {

            success: false,

            error:
              "API name is required"

          }
        );

      }


      // ------------------------------------
      // URL CHECK
      // ------------------------------------

      if (!url) {

        return send(
          res,
          400,
          {

            success: false,

            error:
              "API URL is required"

          }
        );

      }


      let parsedURL;


      try {

        parsedURL =
          new URL(url);

      } catch {

        return send(
          res,
          400,
          {

            success: false,

            error:
              "Invalid API URL"

          }
        );

      }


      // ------------------------------------
      // HTTPS ONLY
      // ------------------------------------

      if (
        parsedURL.protocol !==
        "https:"
      ) {

        return send(
          res,
          400,
          {

            success: false,

            error:
              "Only HTTPS API URLs are allowed"

          }
        );

      }


      // ------------------------------------
      // METHOD CHECK
      // ------------------------------------

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

            success: false,

            error:
              "Invalid HTTP method"

          }
        );

      }


      // ------------------------------------
      // INSERT
      // ------------------------------------

      const inserted =
        await sql`

          INSERT INTO custom_apis (

            name,

            url,

            method,

            description,

            category

          )

          VALUES (

            ${name},

            ${url},

            ${method},

            ${description},

            ${category}

          )

          RETURNING *

        `;


      return send(
        res,
        201,
        {

          success: true,

          message:
            "Custom API added successfully",

          api:
            inserted[0]

        }
      );

    }


    // ======================================
    // DELETE — REMOVE SAVED API
    // ======================================

    if (req.method === "DELETE") {

      const id =
        Number(
          req.query?.id
        );


      if (
        !Number.isInteger(id) ||
        id <= 0
      ) {

        return send(
          res,
          400,
          {

            success: false,

            error:
              "Valid API ID is required"

          }
        );

      }


      const deleted =
        await sql`

          DELETE FROM custom_apis

          WHERE id = ${id}

          RETURNING id

        `;


      if (!deleted.length) {

        return send(
          res,
          404,
          {

            success: false,

            error:
              "Custom API not found"

          }
        );

      }


      return send(
        res,
        200,
        {

          success: true,

          message:
            "Custom API deleted",

          deleted_id:
            id

        }
      );

    }


    // ======================================
    // OTHER METHODS
    // ======================================

    return send(
      res,
      405,
      {

        success: false,

        error:
          "Method not allowed"

      }
    );


  } catch (error) {

    console.error(
      "Custom API error:",
      error
    );


    return send(
      res,
      500,
      {

        success: false,

        error:
          error.message ||
          "Database/API error"

      }
    );

  }

};
