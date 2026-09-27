const { neon } = require("@neondatabase/serverless");

module.exports = async function handler(req, res) {
  try {
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

    if (req.method === "GET") {
      const rows = await sql`
        SELECT id, name, url, method, description, category, created_at
        FROM custom_apis
        ORDER BY created_at DESC
      `;

      return res.status(200).json({
        success: true,
        apis: rows
      });
    }

    if (req.method === "POST") {
      let body = req.body || {};

      if (typeof body === "string") {
        body = JSON.parse(body);
      }

      const name = String(body.name || "").trim();
      const url = String(body.url || "").trim();
      const method = String(body.method || "GET").trim().toUpperCase();
      const description = String(body.description || "").trim();
      const category = String(body.category || "Custom").trim();

      if (!name || !url) {
        return res.status(400).json({
          success: false,
          error: "Name and URL are required"
        });
      }

      let parsed;

      try {
        parsed = new URL(url);
      } catch {
        return res.status(400).json({
          success: false,
          error: "Invalid API URL"
        });
      }

      if (parsed.protocol !== "https:") {
        return res.status(400).json({
          success: false,
          error: "Only HTTPS URLs are allowed"
        });
      }

      const methods = ["GET", "POST", "PUT", "PATCH", "DELETE"];

      if (!methods.includes(method)) {
        return res.status(400).json({
          success: false,
          error: "Invalid HTTP method"
        });
      }

      const result = await sql`
        INSERT INTO custom_apis
          (name, url, method, description, category)
        VALUES
          (${name}, ${url}, ${method}, ${description}, ${category})
        RETURNING *
      `;

      return res.status(201).json({
        success: true,
        api: result[0]
      });
    }

    if (req.method === "DELETE") {
      const id = String(req.query?.id || "").trim();

      if (!id || id === "[object Object]") {
        return res.status(400).json({
          success: false,
          error: "Valid API ID is required"
        });
      }

      const result = await sql`
        DELETE FROM custom_apis
        WHERE id = ${id}
        RETURNING id, name
      `;

      if (!result.length) {
        return res.status(404).json({
          success: false,
          error: "API not found"
        });
      }

      return res.status(200).json({
        success: true,
        deleted: result[0]
      });
    }

    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });

  } catch (error) {
    console.error(error);

    return res.status(500).json({
      success: false,
      error: error.message || "Server error"
    });
  }
};

async function deleteCustomApi(id) {
  const apiId =
    typeof id === "object"
      ? String(id.id || "")
      : String(id || "");

  if (!apiId || apiId === "[object Object]") {
    alert("Valid API ID is required");
    return;
  }

  if (!confirm("Delete this API?")) return;

  try {
    const response = await fetch(
      "/api/custom-apis?id=" + encodeURIComponent(apiId),
      {
        method: "DELETE"
      }
    );

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(data.error || "Delete failed");
    }

    await loadSavedApis();

  } catch (error) {
    alert(error.message || "Delete failed");
  }
}

<button
  type="button"
  onclick="deleteCustomApi(${JSON.stringify(api.id)})">
  Delete
</button>
```0
