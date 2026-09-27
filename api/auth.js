const crypto = require("crypto");

/* =========================================================
   TXG INFORMATION — AUTH CONFIG
========================================================= */

const COOKIE_NAME = "txg_admin_session";

const SESSION_HOURS = 12;

const DEFAULT_PASSWORD =
    "TXG@Admin#2026!Secure";


/* =========================================================
   SECRET
========================================================= */

function getSecret() {

    return (
        process.env.AUTH_SECRET ||
        "TXG-INFORMATION-CHANGE-AUTH-SECRET-2026"
    );

}


/* =========================================================
   HASH
========================================================= */

function hash(value) {

    return crypto
        .createHmac(
            "sha256",
            getSecret()
        )
        .update(String(value))
        .digest("hex");

}


/* =========================================================
   SESSION TOKEN
========================================================= */

function createSession() {

    const expires =
        Date.now() +
        SESSION_HOURS *
        60 *
        60 *
        1000;

    const payload =
        String(expires);

    const signature =
        hash(payload);

    return `${payload}.${signature}`;

}


/* =========================================================
   VERIFY SESSION
========================================================= */

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
        hash(String(expires));

    try {

        return crypto.timingSafeEqual(
            Buffer.from(signature),
            Buffer.from(expected)
        );

    } catch {

        return false;

    }

}


/* =========================================================
   READ COOKIE
========================================================= */

function getCookie(req, name) {

    if (
        req &&
        req.cookies &&
        typeof req.cookies === "object"
    ) {

        return req.cookies[name] || null;

    }


    const header =
        req?.headers?.cookie || "";

    const cookies =
        header.split(";");


    for (const item of cookies) {

        const index =
            item.indexOf("=");

        if (index === -1) {
            continue;
        }

        const key =
            item.slice(0, index).trim();

        const value =
            item.slice(index + 1).trim();


        if (key === name) {
            return decodeURIComponent(value);
        }

    }


    return null;

}


/* =========================================================
   AUTHENTICATED
========================================================= */

function authenticated(req) {

    const token =
        getCookie(
            req,
            COOKIE_NAME
        );

    return verifySession(token);

}


/* =========================================================
   SET SESSION COOKIE
========================================================= */

function setSessionCookie(res) {

    const token =
        createSession();


    const maxAge =
        SESSION_HOURS *
        60 *
        60;


    res.setHeader(
        "Set-Cookie",
        [
            `${COOKIE_NAME}=${encodeURIComponent(token)}`,
            `Max-Age=${maxAge}`,
            "Path=/",
            "HttpOnly",
            "Secure",
            "SameSite=Lax"
        ].join("; ")
    );

}


/* =========================================================
   CLEAR SESSION
========================================================= */

function clearSessionCookie(res) {

    res.setHeader(
        "Set-Cookie",
        [
            `${COOKIE_NAME}=`,
            "Max-Age=0",
            "Path=/",
            "HttpOnly",
            "Secure",
            "SameSite=Lax"
        ].join("; ")
    );

}


/* =========================================================
   PASSWORD
========================================================= */

function getPassword() {

    return (
        process.env.ADMIN_PASSWORD ||
        DEFAULT_PASSWORD
    );

}


/* =========================================================
   LOGIN CHECK
========================================================= */

function checkPassword(password) {

    const supplied =
        hash(password || "");

    const correct =
        hash(getPassword());


    try {

        return crypto.timingSafeEqual(
            Buffer.from(supplied),
            Buffer.from(correct)
        );

    } catch {

        return false;

    }

}


/* =========================================================
   VERCEL HANDLER
========================================================= */

async function handler(req, res) {

    if (req.method === "GET") {

        return res.status(200).json({
            success: true,
            authenticated:
                authenticated(req)
        });

    }


    if (req.method !== "POST") {

        return res.status(405).json({
            success: false,
            message: "Method not allowed"
        });

    }


    const body =
        req.body || {};


    const action =
        String(body.action || "")
            .toLowerCase();


    /* ---------------------------------------------
       LOGIN
    --------------------------------------------- */

    if (action === "login") {

        const password =
            String(body.password || "");


        if (!checkPassword(password)) {

            return res.status(401).json({
                success: false,
                message: "Invalid password"
            });

        }


        setSessionCookie(res);


        return res.status(200).json({
            success: true,
            authenticated: true,
            message: "Login successful"
        });

    }


    /* ---------------------------------------------
       LOGOUT
    --------------------------------------------- */

    if (action === "logout") {

        clearSessionCookie(res);


        return res.status(200).json({
            success: true,
            authenticated: false,
            message: "Logged out"
        });

    }


    /* ---------------------------------------------
       CHECK
    --------------------------------------------- */

    if (action === "check") {

        return res.status(200).json({
            success: true,
            authenticated:
                authenticated(req)
        });

    }


    return res.status(400).json({
        success: false,
        message: "Unknown authentication action"
    });

}


/* =========================================================
   EXPORTS
========================================================= */

handler.authenticated =
    authenticated;

handler.setSessionCookie =
    setSessionCookie;

handler.clearSessionCookie =
    clearSessionCookie;

handler.checkPassword =
    checkPassword;

module.exports = handler;
