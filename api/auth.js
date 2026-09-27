const crypto = require("crypto");

const COOKIE_NAME = "txg_admin_session";
const SESSION_HOURS = 12;

const FALLBACK_PASSWORD = "TXG@Admin#2026!Secure";
const FALLBACK_SECRET = "TXG-INFORMATION-AUTH-2026-CHANGE-ME";


function getPassword() {
  return (
    process.env.ADMIN_PASSWORD ||
    FALLBACK_PASSWORD
  );
}


function getSecret() {
  return (
    process.env.AUTH_SECRET ||
    FALLBACK_SECRET
  );
}


function sign(value) {
  return crypto
    .createHmac(
      "sha256",
      getSecret()
    )
    .update(value)
    .digest("hex");
}


function createSession() {

  const expires =
    Date.now() +
    SESSION_HOURS * 60 * 60 * 1000;

  const data =
    String(expires);

  const signature =
    sign(data);

  return data + "." + signature;
}


function verifySession(token) {

  if (!token) {
    return false;
  }

  const parts =
    String(token).split(".");

  if (parts.length !== 2) {
    return false;
  }

  const expires =
    Number(parts[0]);

  const signature =
    parts[1];

  if (
    !Number.isFinite(expires) ||
    expires < Date.now()
  ) {
    return false;
  }

  const expected =
    sign(String(expires));

  if (
    signature.length !==
    expected.length
  ) {
    return false;
  }

  try {

    return crypto.timingSafeEqual(
      Buffer.from(signature),
      Buffer.from(expected)
    );

  } catch (_) {

    return false;

  }
}


function getCookie(req) {

  /*
   * Vercel provides req.cookies.
   */

  if (
    req.cookies &&
    typeof req.cookies === "object"
  ) {

    return (
      req.cookies[COOKIE_NAME] ||
      null
    );

  }


  /*
   * Fallback manual cookie parser.
   */

  const header =
    req.headers &&
    req.headers.cookie;

  if (!header) {
    return null;
  }


  const cookies =
    header.split(";");


  for (
    const item of cookies
  ) {

    const parts =
      item.trim().split("=");

    const name =
      parts.shift();

    const value =
      parts.join("=");


    if (
      name === COOKIE_NAME
    ) {

      return decodeURIComponent(
        value
      );

    }

  }


  return null;
}


function isAuthenticated(req) {

  return verifySession(
    getCookie(req)
  );

}


function setSessionCookie(
  res,
  token
) {

  const maxAge =
    SESSION_HOURS * 60 * 60;


  res.setHeader(
    "Set-Cookie",
    [
      COOKIE_NAME +
        "=" +
        encodeURIComponent(token),

      "Path=/",

      "Max-Age=" +
        maxAge,

      "HttpOnly",

      "Secure",

      "SameSite=Lax"
    ].join("; ")
  );

}


function clearSessionCookie(res) {

  res.setHeader(
    "Set-Cookie",
    [
      COOKIE_NAME +
        "=deleted",

      "Path=/",

      "Max-Age=0",

      "HttpOnly",

      "Secure",

      "SameSite=Lax"
    ].join("; ")
  );

}


function readBody(req) {

  if (
    req.body &&
    typeof req.body === "object"
  ) {

    return req.body;

  }


  return {};
}


async function handler(req, res) {

  try {

    /*
     * GET
     * Check current login.
     */

    if (
      req.method === "GET"
    ) {

      const authenticated =
        isAuthenticated(req);


      return res.status(200).json({
        success: true,
        authenticated:
          authenticated,
        loggedIn:
          authenticated
      });

    }


    /*
     * POST
     */

    if (
      req.method !== "POST"
    ) {

      res.setHeader(
        "Allow",
        "GET, POST"
      );

      return res
        .status(405)
        .json({
          success: false,
          error:
            "Method not allowed."
        });

    }


    const body =
      readBody(req);


    const action =
      String(
        body.action || ""
      ).toLowerCase();


    /*
     * LOGIN
     */

    if (
      action === "login" ||
      !action
    ) {

      const password =
        String(
          body.password || ""
        );


      if (!password) {

        return res
          .status(400)
          .json({
            success: false,
            error:
              "Password is required."
          });

      }


      if (
        password !==
        getPassword()
      ) {

        return res
          .status(401)
          .json({
            success: false,
            authenticated:
              false,
            error:
              "Invalid password."
          });

      }


      const token =
        createSession();


      setSessionCookie(
        res,
        token
      );


      return res
        .status(200)
        .json({
          success: true,
          authenticated:
            true,
          loggedIn:
            true
        });

    }


    /*
     * LOGOUT
     */

    if (
      action === "logout"
    ) {

      clearSessionCookie(res);


      return res
        .status(200)
        .json({
          success: true,
          authenticated:
            false,
          loggedIn:
            false
        });

    }


    /*
     * CHECK
     */

    if (
      action === "check"
    ) {

      const authenticated =
        isAuthenticated(req);


      return res
        .status(200)
        .json({
          success: true,
          authenticated:
            authenticated,
          loggedIn:
            authenticated
        });

    }


    return res
      .status(400)
      .json({
        success: false,
        error:
          "Unknown action."
      });


  } catch (error) {

    console.error(
      "AUTH ERROR:",
      error
    );


    return res
      .status(500)
      .json({
        success: false,
        error:
          "Authentication server error."
      });

  }

}


module.exports = handler;


/*
 * IMPORTANT:
 * lookup.js and custom-proxy.js
 * can use this function.
 */

module.exports.authenticated =
  isAuthenticated;
