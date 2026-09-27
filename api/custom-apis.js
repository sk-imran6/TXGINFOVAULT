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

    // =========================
    // CREATE TABLE
    // =========================
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

    // Keep existing UUID/text IDs
    await sql`
      ALTER TABLE custom_apis
      ALTER COLUMN id SET DEFAULT (gen_random_uuid()::text)
    `;

    // =========================
    // GET - LIST APIs
    // =========================
    if (req.method === "GET") {
      const rows = await sql`
        SELECT
          id,
          name,
          url,
          method,
          description,
          category,
          created_at
        FROM custom_apis
        ORDER BY created_at DESC
      `;

      return res.status(200).json({
        success: true,
        apis: rows,
        total: rows.length
      });
    }

    // =========================
    // POST - ADD API
    // =========================
    if (req.method === "POST") {
      let body = req.body;

      if (typeof body === "string") {
        try {
          body = JSON.parse(body);
        } catch (e) {
          return res.status(400).json({
            success: false,
            error: "Invalid JSON body"
          });
        }
      }

      body = body || {};

      const name = String(body.name || "").trim();
      const url = String(body.url || "").trim();
      const method = String(body.method || "GET")
        .trim()
        .toUpperCase();

      const description = String(
        body.description || ""
      ).trim();

      const category = String(
        body.category || "Custom"
      ).trim();

      if (!name) {
        return res.status(400).json({
          success: false,
          error: "API name is required"
        });
      }

      if (!url) {
        return res.status(400).json({
          success: false,
          error: "API URL is required"
        });
      }

      // URL validation
      let parsedUrl;

      try {
        parsedUrl = new URL(url);
      } catch (e) {
        return res.status(400).json({
          success: false,
          error: "Invalid API URL"
        });
      }

      // Only HTTPS
      if (parsedUrl.protocol !== "https:") {
        return res.status(400).json({
          success: false,
          error: "Only HTTPS API URLs are allowed"
        });
      }

      const allowedMethods = [
        "GET",
        "POST",
        "PUT",
        "PATCH",
        "DELETE"
      ];

      if (!allowedMethods.includes(method)) {
        return res.status(400).json({
          success: false,
          error: "Unsupported HTTP method"
        });
      }

      // =========================
      // INSERT
      // Let PostgreSQL generate TEXT/UUID ID
      // =========================
      const inserted = await sql`
        INSERT INTO custom_apis
        (
          name,
          url,
          method,
          description,
          category
        )
        VALUES
        (
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
      `;

      return res.status(201).json({
        success: true,
        message: "Custom API added successfully",
        api: inserted[0]
      });
    }

    // =========================
    // DELETE - DELETE API
    // =========================
    if (req.method === "DELETE") {
      const id = String(
        req.query?.id || ""
      ).trim();

      if (!id) {
        return res.status(400).json({
          success: false,
          error: "Valid API ID is required"
        });
      }

      const deleted = await sql`
        DELETE FROM custom_apis
        WHERE id = ${id}
        RETURNING
          id,
          name,
          url,
          method
      `;

      if (!deleted.length) {
        return res.status(404).json({
          success: false,
          error: "API not found"
        });
      }

      return res.status(200).json({
        success: true,
        message: "API deleted successfully",
        deleted: deleted[0]
      });
    }

    // =========================
    // METHOD NOT ALLOWED
    // =========================
    return res.status(405).json({
      success: false,
      error: "Method not allowed"
    });

  } catch (error) {
    console.error("custom-apis error:", error);

    return res.status(500).json({
      success: false,
      error: error.message || "Server error"
    });
  }
};

Frontend delete function

"index.html"-এ পুরোনো "deleteCustomApi()" থাকলে পুরোটা replace করে এটা দাও:

:::writing{variant="standard" id="74106" title="index.html — Delete Function"}

async function deleteCustomApi(id) {
  const apiId = String(id || "").trim();

  if (!apiId) {
    alert("Valid API ID is required");
    return;
  }

  const confirmed = confirm(
    "Are you sure you want to delete this API?"
  );

  if (!confirmed) {
    return;
  }

  try {
    const response = await fetch(
      "/api/custom-apis?id=" +
      encodeURIComponent(apiId),
      {
        method: "DELETE"
      }
    );

    const data = await response.json();

    if (!response.ok || !data.success) {
      throw new Error(
        data.error || "Failed to delete API"
      );
    }

    alert("API deleted successfully");

    await loadSavedApis();

  } catch (error) {
    console.error("Delete API error:", error);

    alert(
      error.message ||
      "Failed to delete API"
    );
  }
}

আরেকটা গুরুত্বপূর্ণ জিনিস: Delete button তৈরি করার সময় ID-টা অবশ্যই string হিসেবে পাঠাবে:

<button
  type="button"
  onclick="deleteCustomApi(${JSON.stringify(api.id)})">
  Delete
</button>

এতে "mujub0uf-513841a331"-এর মতো text/UUID ID-ও ঠিকমতো delete হবে।

Deploy করার পর: Vercel redeploy → Custom API section refresh → পুরোনো API-র Delete চাপো। "Valid API ID is required" আর আসার কথা নয়।
