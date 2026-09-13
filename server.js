const express = require("express");
const axios = require("axios");
const https = require("https");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const { DatabaseSync } = require("node:sqlite");

require("dotenv").config();

const app = express();

const PORT = Number(process.env.PORT || 80);
const SITE_ID = process.env.UNIFI_SITE_ID;
const ADMIN_MAC = process.env.ADMIN_MAC.toLowerCase();

app.use(express.json());


// ======================================================
// DATABASE
// ======================================================

const dataDirectory = path.join(__dirname, "data");

fs.mkdirSync(dataDirectory, {
    recursive: true
});

const db = new DatabaseSync(
    path.join(dataDirectory, "portal.db")
);

db.exec(`
    CREATE TABLE IF NOT EXISTS vouchers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,

        code TEXT NOT NULL UNIQUE,

        full_name TEXT NOT NULL,

        expires_at TEXT NOT NULL,

        created_at TEXT NOT NULL,

        used_at TEXT,

        used_by_mac TEXT,

        redeeming_at TEXT
    );
`);


// ======================================================
// UNIFI API
// ======================================================

const unifi = axios.create({

    baseURL: process.env.UNIFI_BASE_URL,

    timeout: 10000,

    headers: {
        "X-API-KEY": process.env.UNIFI_API_KEY,
        "Accept": "application/json"
    },

    httpsAgent: new https.Agent({
        rejectUnauthorized:
            process.env.UNIFI_VERIFY_TLS === "true"
    })

});


// ======================================================
// UTILITY FUNCTIONS
// ======================================================

function normalizeIP(ip) {

    if (!ip) {
        return "";
    }

    if (ip.startsWith("::ffff:")) {
        return ip.substring(7);
    }

    return ip;
}


function getRequestIP(req) {

    return normalizeIP(
        req.socket.remoteAddress
    );
}


function normalizeMAC(mac) {

    return String(mac || "")
        .trim()
        .toLowerCase();
}


function normalizeVoucherCode(code) {

    let raw = String(code || "")
        .toUpperCase()
        .replace(/[^A-Z0-9]/g, "")
        .slice(0, 8);

    if (raw.length !== 8) {
        return null;
    }

    return (
        raw.substring(0, 4) +
        "-" +
        raw.substring(4)
    );
}


function getResponseData(response) {

    if (Array.isArray(response.data)) {
        return response.data;
    }

    return response.data?.data || [];
}


// ======================================================
// FIND UNIFI CLIENT
// ======================================================

async function getClientByIP(ip) {

    const response = await unifi.get(
        `/sites/${SITE_ID}/clients`,
        {
            params: {
                limit: 10,
                filter:
                    `ipAddress.eq('${ip}')`
            }
        }
    );

    const clients =
        getResponseData(response);

    return clients.find(
        client => client.ipAddress === ip
    ) || null;
}


async function getClientByMAC(mac) {

    const response = await unifi.get(
        `/sites/${SITE_ID}/clients`,
        {
            params: {
                limit: 10,
                filter:
                    `macAddress.eq('${mac}')`
            }
        }
    );

    const clients =
        getResponseData(response);

    return clients.find(
        client =>
            normalizeMAC(client.macAddress) === mac
    ) || null;
}


// ======================================================
// ADMIN AUTHENTICATION
// ======================================================

async function requireAdminMAC(
    req,
    res,
    next
) {

    try {

        const ip =
            getRequestIP(req);

        console.log(
            `Admin request from ${ip}`
        );

        const client =
            await getClientByIP(ip);

        if (!client) {

            console.log(
                `Admin denied: no UniFi client found for ${ip}`
            );

            return res
                .status(403)
                .send("403 - Access Denied");
        }

        const mac =
            normalizeMAC(
                client.macAddress
            );

        console.log(
            `Admin request MAC: ${mac}`
        );

        if (mac !== ADMIN_MAC) {

            console.log(
                `Admin denied for ${mac}`
            );

            return res
                .status(403)
                .send("403 - Access Denied");
        }

        console.log(
            "Admin MAC authorized."
        );

        next();

    }

    catch (error) {

        console.error(
            "Admin verification error:",
            error.response?.data ||
            error.message
        );

        res
            .status(500)
            .send(
                "Unable to verify administrator device."
            );
    }
}


// ======================================================
// VOUCHER GENERATOR
// ======================================================

// Removed I, O, 0, and 1 because they're easy to confuse.

const VOUCHER_CHARACTERS =
    "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";


function randomCharacter() {

    return VOUCHER_CHARACTERS[
        crypto.randomInt(
            0,
            VOUCHER_CHARACTERS.length
        )
    ];
}


function generateVoucherCode() {

    let first = "";
    let second = "";

    for (let i = 0; i < 4; i++) {
        first += randomCharacter();
    }

    for (let i = 0; i < 4; i++) {
        second += randomCharacter();
    }

    return `${first}-${second}`;
}


function generateUniqueVoucherCode() {

    while (true) {

        const code =
            generateVoucherCode();

        const existing =
            db.prepare(`
                SELECT id
                FROM vouchers
                WHERE code = ?
            `).get(code);

        if (!existing) {
            return code;
        }
    }
}


// ======================================================
// UNIFI PORTAL REDIRECT
// ======================================================

// UniFi will normally request:
//
// /guest/s/default/?id=MAC&ssid=Guest&url=...
//
// You said you want the actual portal on "/",
// so send that request to "/" while keeping the
// UniFi query parameters.

app.get(
    [
        "/guest/s/:site",
        "/guest/s/:site/"
    ],

    (req, res) => {

        const params =
            new URLSearchParams();

        for (
            const [key, value]
            of Object.entries(req.query)
        ) {

            if (Array.isArray(value)) {

                for (const item of value) {
                    params.append(
                        key,
                        String(item)
                    );
                }

            } else if (value !== undefined) {

                params.set(
                    key,
                    String(value)
                );
            }
        }

        const query =
            params.toString();

        res.redirect(
            "/" +
            (query ? `?${query}` : "")
        );
    }
);


// ======================================================
// ADMIN PAGE
// ======================================================

app.get(
    "/admin",
    requireAdminMAC,

    (req, res) => {

        res.sendFile(
            path.join(
                __dirname,
                "private",
                "admin.html"
            )
        );
    }
);


// ======================================================
// ADMIN - GET VOUCHERS
// ======================================================

app.get(
    "/api/admin/vouchers",
    requireAdminMAC,

    (req, res) => {

        const vouchers =
            db.prepare(`
                SELECT
                    id,
                    code,
                    full_name,
                    expires_at,
                    created_at,
                    used_at,
                    used_by_mac

                FROM vouchers

                ORDER BY id DESC
            `).all();

        res.json(vouchers);
    }
);


// ======================================================
// ADMIN - CREATE VOUCHER
// ======================================================

app.post(
    "/api/admin/vouchers",
    requireAdminMAC,

    (req, res) => {

        const fullName =
            String(
                req.body.fullName || ""
            ).trim();

        const expiration =
            new Date(
                req.body.expiresAt
            );

        if (
            fullName.length < 2 ||
            fullName.length > 100
        ) {

            return res.status(400).json({
                error:
                    "Enter a valid full name."
            });
        }

        if (
            Number.isNaN(
                expiration.getTime()
            )
        ) {

            return res.status(400).json({
                error:
                    "Invalid expiration date."
            });
        }

        if (
            expiration.getTime()
            <= Date.now()
        ) {

            return res.status(400).json({
                error:
                    "Expiration must be in the future."
            });
        }

        const code =
            generateUniqueVoucherCode();

        const now =
            new Date().toISOString();

        const expiresAt =
            expiration.toISOString();

        db.prepare(`
            INSERT INTO vouchers (
                code,
                full_name,
                expires_at,
                created_at
            )

            VALUES (?, ?, ?, ?)
        `).run(
            code,
            fullName,
            expiresAt,
            now
        );

        console.log(
            `Voucher created: ${code} for ${fullName}`
        );

        res.json({
            success: true,
            code,
            fullName,
            expiresAt
        });
    }
);


// ======================================================
// REDEEM VOUCHER
// ======================================================

app.post(
    "/api/redeem",

    async (req, res) => {

        const code =
            normalizeVoucherCode(
                req.body.code
            );

        const mac =
            normalizeMAC(
                req.body.mac
            );

        const returnUrl =
            req.body.returnUrl;

        if (!code) {

            return res.status(400).json({
                error:
                    "Enter a valid voucher code."
            });
        }

        const macRegex =
            /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

        if (!macRegex.test(mac)) {

            return res.status(400).json({
                error:
                    "Unable to identify this device."
            });
        }


        // --------------------------------------
        // FIND VOUCHER
        // --------------------------------------

        const voucher =
            db.prepare(`
                SELECT *
                FROM vouchers
                WHERE code = ?
            `).get(code);


        if (!voucher) {

            return res.status(401).json({
                error:
                    "Invalid voucher code."
            });
        }


        if (voucher.used_at) {

            return res.status(401).json({
                error:
                    "This voucher has already been used."
            });
        }


        const expiration =
            new Date(
                voucher.expires_at
            );

        if (
            expiration.getTime()
            <= Date.now()
        ) {

            return res.status(401).json({
                error:
                    "This voucher has expired."
            });
        }


        // --------------------------------------
        // CLAIM VOUCHER
        //
        // Prevent two devices from redeeming the
        // same voucher simultaneously.
        // --------------------------------------

        const now =
            new Date();

        const staleClaim =
            new Date(
                Date.now() -
                5 * 60 * 1000
            );

        const claim =
            db.prepare(`
                UPDATE vouchers

                SET redeeming_at = ?

                WHERE code = ?

                AND used_at IS NULL

                AND expires_at > ?

                AND (
                    redeeming_at IS NULL
                    OR redeeming_at < ?
                )
            `).run(
                now.toISOString(),
                code,
                now.toISOString(),
                staleClaim.toISOString()
            );


        if (Number(claim.changes) !== 1) {

            return res.status(409).json({
                error:
                    "This voucher is already being redeemed."
            });
        }


        try {

            // --------------------------------------
            // FIND CLIENT IN UNIFI
            // --------------------------------------

            const client =
                await getClientByMAC(mac);

            if (!client) {

                throw new Error(
                    "Guest device was not found in UniFi."
                );
            }


            // --------------------------------------
            // VERIFY THE REQUEST REALLY CAME
            // FROM THAT CLIENT
            // --------------------------------------

            const requestIP =
                getRequestIP(req);

            if (
                client.ipAddress &&
                client.ipAddress !== requestIP
            ) {

                throw new Error(
                    "Guest device identity could not be verified."
                );
            }


            // --------------------------------------
            // DETERMINE ACCESS TIME
            // --------------------------------------

            const remainingMs =
                expiration.getTime()
                - Date.now();

            const remainingMinutes =
                Math.max(
                    1,
                    Math.ceil(
                        remainingMs /
                        60000
                    )
                );


            console.log(
                `Authorizing ${mac} for ${remainingMinutes} minutes`
            );


            // --------------------------------------
            // AUTHORIZE WITH UNIFI
            // --------------------------------------

            await unifi.post(
                `/sites/${SITE_ID}/clients/${client.id}/actions`,
                {
                    action:
                        "AUTHORIZE_GUEST_ACCESS",

                    timeLimitMinutes:
                        remainingMinutes
                }
            );


            // --------------------------------------
            // MARK VOUCHER USED
            // --------------------------------------

            const usedAt =
                new Date().toISOString();

            db.prepare(`
                UPDATE vouchers

                SET
                    used_at = ?,
                    used_by_mac = ?,
                    redeeming_at = NULL

                WHERE code = ?
            `).run(
                usedAt,
                mac,
                code
            );


            // --------------------------------------
            // SAFE REDIRECT
            // --------------------------------------

            let safeRedirect = null;

            if (returnUrl) {

                try {

                    const parsed =
                        new URL(returnUrl);

                    if (
                        parsed.protocol === "http:" ||
                        parsed.protocol === "https:"
                    ) {

                        safeRedirect =
                            parsed.toString();
                    }

                } catch {
                    // Ignore invalid URLs
                }
            }


            console.log(
                `${voucher.full_name} redeemed ${code}`
            );


            res.json({
                success: true,

                fullName:
                    voucher.full_name,

                expiresAt:
                    voucher.expires_at,

                redirect:
                    safeRedirect
            });

        }

        catch (error) {

            // Release the voucher if UniFi authorization
            // failed so the guest can try again.

            db.prepare(`
                UPDATE vouchers

                SET redeeming_at = NULL

                WHERE code = ?
                AND used_at IS NULL
            `).run(code);


            console.error(
                "Voucher authorization error:",
                error.response?.data ||
                error.message
            );


            res.status(500).json({
                error:
                    error.message ||
                    "Unable to authorize this device."
            });
        }
    }
);


// ======================================================
// PUBLIC PORTAL
// ======================================================

app.use(
    express.static(
        path.join(
            __dirname,
            "public"
        )
    )
);


// ======================================================
// START SERVER
// ======================================================

app.listen(
    PORT,
    "0.0.0.0",

    () => {

        console.log("");
        console.log(
            "======================================"
        );

        console.log(
            " UniFi Voucher Portal"
        );

        console.log(
            "======================================"
        );

        console.log(
            `Portal: http://192.168.2.192:${PORT}/`
        );

        console.log(
            `Admin:  http://192.168.2.192:${PORT}/admin`
        );

        console.log("");
    }
);