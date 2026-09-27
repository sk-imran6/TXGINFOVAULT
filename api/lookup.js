const auth = require("./auth");

const DEFAULT_TIMEOUT = 12000;
const MAX_RESULTS_PER_SOURCE = 20;

/* =========================================================
   BASIC HELPERS
========================================================= */

function text(value) {
    if (value === null || value === undefined) return "";
    return String(value).trim();
}

function unique(values) {
    return [...new Set(
        values
            .map(text)
            .filter(Boolean)
    )];
}

function safeJson(value) {
    try {
        return JSON.stringify(value, null, 2);
    } catch {
        return String(value);
    }
}

function cleanObject(obj) {
    if (!obj || typeof obj !== "object") return obj;

    if (Array.isArray(obj)) {
        return obj.slice(0, MAX_RESULTS_PER_SOURCE).map(cleanObject);
    }

    const out = {};

    for (const [key, value] of Object.entries(obj)) {

        if (
            value === undefined ||
            value === null ||
            value === ""
        ) {
            continue;
        }

        if (typeof value === "object") {
            out[key] = cleanObject(value);
        } else {
            out[key] = value;
        }
    }

    return out;
}


/* =========================================================
   FETCH
========================================================= */

async function fetchSafe(url, options = {}, timeout = DEFAULT_TIMEOUT) {

    const controller = new AbortController();

    const timer = setTimeout(
        () => controller.abort(),
        timeout
    );

    try {

        const response = await fetch(url, {
            ...options,
            signal: controller.signal,
            redirect: "follow",
            headers: {
                "User-Agent": "TXG-Information/1.0",
                ...(options.headers || {})
            }
        });

        const contentType =
            response.headers.get("content-type") || "";

        let data;

        if (contentType.includes("application/json")) {
            data = await response.json();
        } else {
            data = await response.text();
        }

        return {
            ok: response.ok,
            status: response.status,
            data
        };

    } catch (error) {

        return {
            ok: false,
            status: 0,
            error: error.name === "AbortError"
                ? "Request timeout"
                : error.message
        };

    } finally {
        clearTimeout(timer);
    }
}


/* =========================================================
   RESULT BLOCK
========================================================= */

function result(name, source, data, extra = {}) {

    return {
        name,
        source,
        status: extra.status || "success",
        data: cleanObject(data)
    };
}


/* =========================================================
   INPUT DETECTION
========================================================= */

function looksLikeEmail(value) {
    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/i.test(value);
}

function looksLikePhone(value) {
    const digits = value.replace(/[^\d+]/g, "");
    return /^\+?\d{8,15}$/.test(digits);
}

function looksLikeIP(value) {

    const ipv4 =
        /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;

    const ipv6 = /^[0-9a-f:]+$/i;

    return ipv4.test(value) ||
        (value.includes(":") && ipv6.test(value));
}

function looksLikeURL(value) {
    return /^https?:\/\//i.test(value) ||
        /^[a-z0-9.-]+\.[a-z]{2,}$/i.test(value);
}

function normalizePhone(value) {

    let v = text(value);

    v = v.replace(/[^\d+]/g, "");

    if (
        v.startsWith("00") &&
        !v.startsWith("000")
    ) {
        v = "+" + v.slice(2);
    }

    return v;
}


/* =========================================================
   CRM CONFIG
========================================================= */

function crmConfigured() {

    return Boolean(
        process.env.ZOHO_ACCESS_TOKEN
    );
}

function crmBase() {

    return (
        process.env.ZOHO_API_BASE ||
        "https://www.zohoapis.in/crm/v8"
    ).replace(/\/+$/, "");
}


/* =========================================================
   CRM SEARCH
========================================================= */

async function searchCRMModule(
    module,
    mode,
    value
) {

    if (!crmConfigured()) {
        return {
            configured: false,
            data: []
        };
    }

    const encoded = encodeURIComponent(value);

    let parameter = "";

    if (mode === "phone") {
        parameter = `phone=${encoded}`;
    }

    else if (mode === "email") {
        parameter = `email=${encoded}`;
    }

    else {
        parameter = `word=${encoded}`;
    }

    const url =
        `${crmBase()}/${encodeURIComponent(module)}/search?${parameter}`;

    const response = await fetchSafe(url, {
        headers: {
            Authorization:
                `Zoho-oauthtoken ${process.env.ZOHO_ACCESS_TOKEN}`,
            Accept: "application/json"
        }
    });

    if (!response.ok) {

        return {
            configured: true,
            data: [],
            error:
                response.data?.message ||
                response.error ||
                `CRM HTTP ${response.status}`
        };
    }

    const rows =
        Array.isArray(response.data?.data)
            ? response.data.data
            : [];

    return {
        configured: true,
        data: rows.slice(
            0,
            MAX_RESULTS_PER_SOURCE
        )
    };
}


/* =========================================================
   SEARCH ALL AUTHORIZED CRM MODULES
========================================================= */

async function searchCRM(
    mode,
    value
) {

    if (!crmConfigured()) {

        return result(
            "CRM",
            "Zoho CRM",
            {
                configured: false,
                message:
                    "CRM connection is not configured."
            },
            {
                status: "not_configured"
            }
        );
    }


    const modules = [
        "Contacts",
        "Leads",
        "Accounts",
        "Deals"
    ];


    const all = [];

    for (const module of modules) {

        const found =
            await searchCRMModule(
                module,
                mode,
                value
            );

        if (
            found.data &&
            found.data.length
        ) {

            all.push({
                module,
                records: found.data
            });

        }

    }


    if (!all.length) {

        return result(
            "CRM",
            "Zoho CRM",
            {
                searched: value,
                matches: [],
                message: "No matching CRM record found."
            }
        );

    }


    return result(
        "CRM",
        "Zoho CRM",
        {
            searched: value,
            matches: all
        }
    );
}


/* =========================================================
   CRM RELATED VALUE EXTRACTION
========================================================= */

function extractCRMValues(records) {

    const emails = [];
    const phones = [];
    const companies = [];
    const domains = [];

    function walk(value, key = "") {

        if (
            value === null ||
            value === undefined
        ) {
            return;
        }

        if (typeof value === "string") {

            const v = value.trim();

            if (!v) return;


            if (
                key.toLowerCase().includes("email") &&
                looksLikeEmail(v)
            ) {
                emails.push(v);
            }


            if (
                key.toLowerCase().includes("phone") ||
                key.toLowerCase().includes("mobile")
            ) {

                if (looksLikePhone(v)) {
                    phones.push(v);
                }

            }


            if (
                key.toLowerCase().includes("company") ||
                key.toLowerCase().includes("account")
            ) {

                if (
                    v.length > 1 &&
                    v.length < 150
                ) {
                    companies.push(v);
                }

            }


            if (
                key.toLowerCase().includes("website") ||
                key.toLowerCase().includes("domain")
            ) {

                let domain = v
                    .replace(/^https?:\/\//i, "")
                    .split("/")[0];

                if (
                    domain.includes(".") &&
                    !domain.includes(" ")
                ) {
                    domains.push(domain);
                }

            }

            return;
        }


        if (Array.isArray(value)) {

            for (const item of value) {
                walk(item, key);
            }

            return;
        }


        if (typeof value === "object") {

            for (
                const [childKey, childValue]
                of Object.entries(value)
            ) {

                walk(
                    childValue,
                    childKey
                );

            }

        }

    }


    walk(records);


    return {
        emails: unique(emails),
        phones: unique(phones),
        companies: unique(companies),
        domains: unique(domains)
    };
}


/* =========================================================
   EMAIL INFORMATION
========================================================= */

async function emailInfo(email) {

    const domain =
        email.split("@")[1]?.toLowerCase() || "";

    const local =
        email.split("@")[0] || "";

    const disposableDomains = [
        "mailinator.com",
        "10minutemail.com",
        "guerrillamail.com",
        "tempmail.com",
        "yopmail.com"
    ];

    const freeDomains = [
        "gmail.com",
        "outlook.com",
        "hotmail.com",
        "yahoo.com",
        "icloud.com",
        "proton.me",
        "protonmail.com"
    ];


    return result(
        "Email",
        "Email Analysis",
        {
            email,
            normalized: email.toLowerCase(),
            local_part: local,
            domain,
            free_provider:
                freeDomains.includes(domain),
            disposable:
                disposableDomains.includes(domain)
        }
    );
}


/* =========================================================
   PHONE INFORMATION
========================================================= */

function phoneInfo(phone) {

    const normalized =
        normalizePhone(phone);

    let country = "Unknown";
    let callingCode = null;

    if (
        normalized.startsWith("+91")
    ) {
        country = "India";
        callingCode = "+91";
    }

    else if (
        normalized.startsWith("+1")
    ) {
        country = "United States / Canada";
        callingCode = "+1";
    }

    else if (
        normalized.startsWith("+44")
    ) {
        country = "United Kingdom";
        callingCode = "+44";
    }

    else if (
        normalized.startsWith("+971")
    ) {
        country = "United Arab Emirates";
        callingCode = "+971";
    }


    return result(
        "Mobile",
        "Number Analysis",
        {
            input: phone,
            normalized,
            country,
            calling_code: callingCode,
            valid_format:
                looksLikePhone(normalized),
            carrier:
                "Not available without a carrier data provider"
        }
    );
}


/* =========================================================
   IP INFORMATION
========================================================= */

async function ipInfo(ip) {

    const response =
        await fetchSafe(
            `https://ipwho.is/${encodeURIComponent(ip)}`
        );


    if (!response.ok) {

        return result(
            "IP",
            "IP Geolocation",
            {
                ip,
                error:
                    response.error ||
                    "IP lookup unavailable"
            },
            {
                status: "error"
            }
        );

    }


    const data = response.data || {};


    return result(
        "IP",
        "IP Geolocation",
        {
            ip,
            success: data.success,
            type: data.type,
            country: data.country,
            country_code: data.country_code,
            region: data.region,
            city: data.city,
            latitude: data.latitude,
            longitude: data.longitude,
            timezone: data.timezone,
            isp: data.connection?.isp,
            organization: data.connection?.org,
            asn: data.connection?.asn,
            reverse_dns: data.reverse_dns
        }
    );
}


/* =========================================================
   PIN INFORMATION
========================================================= */

async function pinInfo(pin) {

    const response =
        await fetchSafe(
            `https://api.postalpincode.in/pincode/${encodeURIComponent(pin)}`
        );


    if (!response.ok) {

        return result(
            "PIN",
            "India Post PIN Lookup",
            {
                pin,
                error:
                    response.error ||
                    "PIN lookup unavailable"
            },
            {
                status: "error"
            }
        );

    }


    const data =
        Array.isArray(response.data)
            ? response.data[0]
            : response.data;


    return result(
        "PIN",
        "India Post PIN Lookup",
        {
            pin,
            status: data?.Status,
            message: data?.Message,
            post_offices:
                data?.PostOffice || []
        }
    );
}


/* =========================================================
   IFSC INFORMATION
========================================================= */

async function ifscInfo(ifsc) {

    const code =
        text(ifsc).toUpperCase();


    const response =
        await fetchSafe(
            `https://ifsc.razorpay.com/${encodeURIComponent(code)}`
        );


    if (!response.ok) {

        return result(
            "IFSC",
            "IFSC Lookup",
            {
                ifsc: code,
                error:
                    response.error ||
                    "IFSC lookup unavailable"
            },
            {
                status: "error"
            }
        );

    }


    return result(
        "IFSC",
        "IFSC Lookup",
        response.data
    );
}


/* =========================================================
   UPI
========================================================= */

function upiInfo(value) {

    const valid =
        /^[a-zA-Z0-9._-]{2,256}@[a-zA-Z0-9._-]{2,64}$/
            .test(value);


    return result(
        "UPI",
        "UPI Format Analysis",
        {
            upi_id: value,
            valid_format: valid,
            verification:
                "Not performed. Authorized UPI verification provider required."
        }
    );
}


/* =========================================================
   COMPANY
========================================================= */

function companyInfo(value) {

    return result(
        "Company",
        "Company Information",
        {
            search: value,
            message:
                "Public company data requires a configured company-data provider.",
            provider:
                "Not configured"
        },
        {
            status: "not_configured"
        }
    );
}


/* =========================================================
   VEHICLE
========================================================= */

function vehicleInfo(value) {

    return result(
        "Vehicle",
        "Vehicle Information",
        {
            registration_number:
                value.toUpperCase(),
            message:
                "Vehicle details require an authorized vehicle-data provider.",
            provider:
                "Not configured"
        },
        {
            status: "not_configured"
        }
    );
}


/* =========================================================
   URL
========================================================= */

async function urlInfo(value) {

    let url = value;

    if (!/^https?:\/\//i.test(url)) {
        url = "https://" + url;
    }


    let parsed;

    try {
        parsed = new URL(url);
    } catch {

        return result(
            "URL",
            "URL Analysis",
            {
                input: value,
                valid: false
            },
            {
                status: "error"
            }
        );

    }


    const response =
        await fetchSafe(url, {
            method: "GET"
        });


    const headers = {};


    if (response) {
        headers.status = response.status;
    }


    return result(
        "URL",
        "URL Analysis",
        {
            input: value,
            normalized_url: parsed.href,
            protocol: parsed.protocol,
            hostname: parsed.hostname,
            pathname: parsed.pathname,
            port: parsed.port || null,
            https:
                parsed.protocol === "https:",
            http_status:
                response.status || null,
            reachable:
                response.ok
        }
    );
}


/* =========================================================
   CUSTOM API
========================================================= */

async function customInfo(value) {

    if (!process.env.CUSTOM_LOOKUP_API_URL) {

        return result(
            "Custom API",
            "Custom API",
            {
                value,
                message:
                    "CUSTOM_LOOKUP_API_URL is not configured."
            },
            {
                status: "not_configured"
            }
        );

    }


    let url =
        process.env.CUSTOM_LOOKUP_API_URL
            .replace(
                /\{message\}/g,
                encodeURIComponent(value)
            );


    const response =
        await fetchSafe(url, {
            headers: {
                Accept:
                    "application/json,text/plain,*/*",
                ...(process.env.CUSTOM_LOOKUP_API_KEY
                    ? {
                        Authorization:
                            `Bearer ${process.env.CUSTOM_LOOKUP_API_KEY}`
                    }
                    : {})
            }
        });


    if (!response.ok) {

        return result(
            "Custom API",
            "Custom API",
            {
                value,
                error:
                    response.error ||
                    `HTTP ${response.status}`
            },
            {
                status: "error"
            }
        );

    }


    return result(
        "Custom API",
        "Custom API",
        response.data
    );
}


/* =========================================================
   CONNECTED LOOKUP ENGINE
========================================================= */

async function connectedLookup(
    type,
    value
) {

    const results = [];

    const related = {
        emails: [],
        phones: [],
        companies: [],
        domains: []
    };


    /* ---------------------------------------------
       PRIMARY SEARCH
    --------------------------------------------- */

    if (type === "mobile") {

        results.push(
            phoneInfo(value)
        );

        if (crmConfigured()) {

            const crm =
                await searchCRM(
                    "phone",
                    normalizePhone(value)
                );

            results.push(crm);


            if (
                crm.data &&
                crm.data.matches
            ) {

                const extracted =
                    extractCRMValues(
                        crm.data.matches
                    );

                related.emails.push(
                    ...extracted.emails
                );

                related.phones.push(
                    ...extracted.phones
                );

                related.companies.push(
                    ...extracted.companies
                );

                related.domains.push(
                    ...extracted.domains
                );

            }

        }

    }


    else if (type === "email") {

        results.push(
            await emailInfo(value)
        );


        if (crmConfigured()) {

            const crm =
                await searchCRM(
                    "email",
                    value
                );

            results.push(crm);


            if (
                crm.data &&
                crm.data.matches
            ) {

                const extracted =
                    extractCRMValues(
                        crm.data.matches
                    );

                related.emails.push(
                    ...extracted.emails
                );

                related.phones.push(
                    ...extracted.phones
                );

                related.companies.push(
                    ...extracted.companies
                );

                related.domains.push(
                    ...extracted.domains
                );

            }

        }

    }


    else if (type === "ip") {

        results.push(
            await ipInfo(value)
        );

    }


    else if (type === "pin") {

        results.push(
            await pinInfo(value)
        );

    }


    else if (type === "ifsc") {

        results.push(
            await ifscInfo(value)
        );

    }


    else if (type === "upi") {

        results.push(
            upiInfo(value)
        );

    }


    else if (type === "vehicle") {

        results.push(
            vehicleInfo(value)
        );

    }


    else if (type === "url") {

        results.push(
            await urlInfo(value)
        );

    }


    else if (type === "company") {

        results.push(
            companyInfo(value)
        );


        if (crmConfigured()) {

            const crm =
                await searchCRM(
                    "word",
                    value
                );

            results.push(crm);

        }

    }


    else if (type === "crm") {

        const crm =
            await searchCRM(
                "word",
                value
            );

        results.push(crm);


        if (
            crm.data &&
            crm.data.matches
        ) {

            const extracted =
                extractCRMValues(
                    crm.data.matches
                );

            related.emails.push(
                ...extracted.emails
            );

            related.phones.push(
                ...extracted.phones
            );

            related.companies.push(
                ...extracted.companies
            );

            related.domains.push(
                ...extracted.domains
            );

        }

    }


    else if (type === "custom") {

        results.push(
            await customInfo(value)
        );

    }


    else {

        results.push(
            result(
                "Lookup",
                "TXG",
                {
                    value,
                    message:
                        "Unknown lookup type."
                },
                {
                    status: "error"
                }
            )
        );

    }


    /* ---------------------------------------------
       CONNECTED EMAIL SEARCH
    --------------------------------------------- */

    const connectedEmails =
        unique(related.emails);


    for (
        const email of connectedEmails.slice(0, 5)
    ) {

        const exists =
            results.some(
                item =>
                    item.name === "Email" &&
                    item.data?.email === email
            );

        if (!exists) {

            results.push(
                await emailInfo(email)
            );

        }


        if (crmConfigured()) {

            const crm =
                await searchCRM(
                    "email",
                    email
                );

            if (
                crm.data?.matches?.length
            ) {

                results.push(
                    result(
                        "CRM",
                        "Zoho CRM",
                        {
                            connected_from: email,
                            searched: email,
                            matches:
                                crm.data.matches
                        }
                    )
                );

            }

        }

    }


    /* ---------------------------------------------
       CONNECTED COMPANY SEARCH
    --------------------------------------------- */

    const connectedCompanies =
        unique(related.companies);


    for (
        const company of connectedCompanies.slice(0, 5)
    ) {

        results.push(
            companyInfo(company)
        );


        if (crmConfigured()) {

            const crm =
                await searchCRM(
                    "word",
                    company
                );

            if (
                crm.data?.matches?.length
            ) {

                results.push(
                    result(
                        "CRM",
                        "Zoho CRM",
                        {
                            connected_from: company,
                            searched: company,
                            matches:
                                crm.data.matches
                        }
                    )
                );

            }

        }

    }


    /* ---------------------------------------------
       CONNECTED PHONE SEARCH
    --------------------------------------------- */

    const connectedPhones =
        unique(related.phones);


    for (
        const phone of connectedPhones.slice(0, 5)
    ) {

        if (
            normalizePhone(phone) !==
            normalizePhone(value)
        ) {

            results.push(
                phoneInfo(phone)
            );

        }

    }


    /* ---------------------------------------------
       CONNECTED DOMAIN SEARCH
    --------------------------------------------- */

    const connectedDomains =
        unique(related.domains);


    for (
        const domain of connectedDomains.slice(0, 5)
    ) {

        results.push(
            await urlInfo(domain)
        );

    }


    return {
        success: true,
        query: value,
        type,
        connected: true,
        result_count: results.length,
        results
    };
}


/* =========================================================
   VERCEL HANDLER
========================================================= */

module.exports = async function handler(
    req,
    res
) {

    try {

        if (
            typeof auth.authenticated === "function" &&
            !auth.authenticated(req)
        ) {

            return res.status(401).json({
                success: false,
                message: "Unauthorized"
            });

        }


        if (req.method !== "GET") {

            return res.status(405).json({
                success: false,
                message: "Method not allowed"
            });

        }


        const type =
            text(req.query?.type).toLowerCase();

        const value =
            text(req.query?.value);


        if (!type || !value) {

            return res.status(400).json({
                success: false,
                message:
                    "type and value are required"
            });

        }


        const data =
            await connectedLookup(
                type,
                value
            );


        res.setHeader(
            "Cache-Control",
            "no-store, max-age=0"
        );


        return res.status(200).json(data);


    } catch (error) {

        console.error(
            "TXG LOOKUP ERROR:",
            error
        );


        return res.status(500).json({
            success: false,
            message:
                "Lookup engine error",
            error:
                process.env.NODE_ENV === "development"
                    ? error.message
                    : undefined
        });

    }

};
