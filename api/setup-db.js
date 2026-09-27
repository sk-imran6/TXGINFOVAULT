// api/setup-db.js

const { neon } = require("@neondatabase/serverless");

module.exports = async function handler(req, res) {

  try {

    if (req.method !== "GET") {
      return res.status(405).json({
        success: false,
        error: "GET method required"
      });
    }

    const databaseUrl =
      process.env.DATABASE_URL ||
      process.env.POSTGRES_URL ||
      process.env.STORAGE_DATABASE_URL ||
      process.env.STORAGE_POSTGRES_URL;

    if (!databaseUrl) {
      return res.status(500).json({
        success: false,
        error: "DATABASE_URL is not configured"
      });
    }

    const sql = neon(databaseUrl);


    // ==========================================
    // CREATE TABLE IF NOT EXISTS
    // ==========================================

    await sql`
      CREATE TABLE IF NOT EXISTS custom_apis (
        id INTEGER NOT NULL PRIMARY KEY,
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        method VARCHAR(10) NOT NULL DEFAULT 'GET',
        description TEXT DEFAULT '',
        category TEXT DEFAULT 'Custom',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;


    // ==========================================
    // CREATE ID SEQUENCE
    // ==========================================

    await sql`
      CREATE SEQUENCE IF NOT EXISTS custom_apis_id_seq
      AS INTEGER
      START WITH 1
      INCREMENT BY 1
    `;


    // ==========================================
    // SYNC SEQUENCE WITH EXISTING DATA
    // ==========================================

    await sql`
      SELECT setval(
        'custom_apis_id_seq',
        COALESCE(
          (SELECT MAX(id) FROM custom_apis),
          0
        )
      )
    `;


    // ==========================================
    // SET AUTO ID
    // ==========================================

    await sql`
      ALTER TABLE custom_apis
      ALTER COLUMN id
      SET DEFAULT nextval('custom_apis_id_seq')
    `;


    // ==========================================
    // OWN SEQUENCE
    // ==========================================

    await sql`
      ALTER SEQUENCE custom_apis_id_seq
      OWNED BY custom_apis.id
    `;


    // ==========================================
    // INDEX
    // ==========================================

    await sql`
      CREATE INDEX IF NOT EXISTS
      custom_apis_created_at_idx
      ON custom_apis(created_at DESC)
    `;


    // ==========================================
    // TEST
    // ==========================================

    const test = await sql`
      SELECT
        NOW() AS server_time,
        COUNT(*) AS total_apis
      FROM custom_apis
    `;


    return res.status(200).json({

      success: true,

      message:
        "Neon database setup completed successfully",

      table:
        "custom_apis",

      total_apis:
        Number(test[0]?.total_apis || 0),

      server_time:
        test[0]?.server_time || null

    });

  } catch (error) {

    console.error(
      "Database setup error:",
      error
    );

    return res.status(500).json({

      success: false,

      error:
        error.message ||
        "Database setup failed"

    });

  }

};
