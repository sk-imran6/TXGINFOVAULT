const { createClient } = require("redis");
const { authenticated } = require("./auth");

const REDIS_KEY = "txg:custom_apis";

let redisClient = null;
let connecting = null;

async function getRedis() {
  if (!process.env.REDIS_URL) {
    throw new Error("Redis is not connected");
  }

  if (redisClient && redisClient.isReady) {
    return redisClient;
  }

  if (connecting) {
    return connecting;
  }

  redisClient = createClient({
    url: process.env.REDIS_URL
  });

  redisClient.on("error", err => {
    console.error("Redis error:", err);
  });

  connecting = redisClient.connect()
    .then(() => {
      connecting = null;
      return redisClient;
    })
    .catch(error => {
      connecting = null;
      redisClient = null;
      throw error;
    });

  return connecting;
}

async function getApis() {
  const redis = await getRedis();

  const value = await redis.get(REDIS_KEY);

  if (!value) {
    return [];
  }

  try {
    const data = JSON.parse(value);

    return Array.isArray(data)
      ? data
      : [];
  } catch {
    return [];
  }
}

async function saveApis(apis) {
  const redis = await getRedis();

  await redis.set(
    REDIS_KEY,
    JSON.stringify(apis)
  );
}

function clean(value, max) {
  return String(value || "")
    .trim()
    .slice(0, max);
}

module.exports = async function handler(req, res) {

  if (!authenticated(req)) {
    return res.status(401).json({
      ok: false,
      error: "Authentication required"
    });
  }

  try {

    // =========================
    // GET ALL CUSTOM APIS
    // =========================

    if (req.method === "GET") {

      const apis = await getApis();

      return res.status(200).json({
        ok: true,
        apis
      });
    }


    // =========================
    // ADD CUSTOM API
    // =========================

    if (req.method === "POST") {

      const body = req.body || {};

      const name = clean(
        body.name,
        80
      );

      const url = clean(
        body.url,
        1000
      );

      if (!name) {
        return res.status(400).json({
          ok: false,
          error: "API name is required"
        });
      }

      if (!url) {
        return res.status(400).json({
          ok: false,
          error: "API URL is required"
        });
      }

      if (!/^https?:\/\//i.test(url)) {
        return res.status(400).json({
          ok: false,
          error:
            "API URL must start with http:// or https://"
        });
      }

      const apis = await getApis();

      const api = {
        id:
          Date.now().toString(36) +
          Math.random()
            .toString(36)
            .slice(2, 8),

        name,
        url,

        createdAt:
          new Date().toISOString()
      };

      apis.push(api);

      await saveApis(apis);

      return res.status(200).json({
        ok: true,
        api,
        apis
      });
    }


    // =========================
    // DELETE CUSTOM API
    // =========================

    if (req.method === "DELETE") {

      const body = req.body || {};

      const id = clean(
        body.id,
        200
      );

      if (!id) {
        return res.status(400).json({
          ok: false,
          error: "API ID is required"
        });
      }

      const apis = await getApis();

      const newApis = apis.filter(
        api => api.id !== id
      );

      if (newApis.length === apis.length) {
        return res.status(404).json({
          ok: false,
          error: "API not found"
        });
      }

      await saveApis(newApis);

      return res.status(200).json({
        ok: true,
        apis: newApis
      });
    }


    return res.status(405).json({
      ok: false,
      error: "Method not allowed"
    });

  } catch (error) {

    console.error(
      "Custom API storage error:",
      error
    );

    return res.status(500).json({
      ok: false,
      error:
        error.message ||
        "Custom API storage failed"
    });
  }
};
