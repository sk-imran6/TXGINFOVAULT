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

    await sql`
      CREATE TABLE IF NOT EXISTS custom_apis (
        id TEXT PRIMARY KEY DEFAULT (gen_random_uuid()::text),
        name TEXT NOT NULL,
        url TEXT NOT NULL,
        method VARCHAR(10) NOT NULL DEFAULT 'GET',
        description TEXT DEFAULT '',
        category TEXT DEFAULT 'Custom',
        created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
      )
    `;

    await sql`
      ALTER TABLE custom_apis
      ALTER COLUMN id
      SET DEFAULT (gen_random_uuid()::text)
    `;

    await sql`
      ALTER TABLE custom_apis
      ALTER COLUMN created_at
      SET DEFAULT NOW()
    `;

    await sql`
      CREATE INDEX IF NOT EXISTS custom_apis_created_at_idx
      ON custom_apis(created_at DESC)
    `;

    const result = await sql`
      SELECT COUNT(*) AS total
      FROM custom_apis
    `;

    return res.status(200).json({
      success: true,
      message: "Database setup completed successfully",
      table: "custom_apis",
      id_type: "UUID/Text",
      total_apis: Number(result[0]?.total || 0)
    });

  } catch (error) {
    console.error("setup-db:", error);

    return res.status(500).json({
      success: false,
      error: error.message || "Database setup failed"
    });
  }
};
