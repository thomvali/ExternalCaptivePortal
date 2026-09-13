const express = require('express');
const axios = require('axios');
const https = require('https');
const path = require('path');
require('dotenv').config();

const app = express();

const PORT = process.env.PORT || 3000;
const SITE_ID = process.env.UNIFI_SITE_ID;

if (!process.env.UNIFI_BASE_URL || !process.env.UNIFI_API_KEY || !SITE_ID) {
    console.error("Missing UniFi configuration in .env");
    process.exit(1);
}

app.use(express.json());
app.use(express.static(path.join(__dirname, "public")));

const unifi = axios.create({
    baseURL: process.env.UNIFI_BASE_URL,
    timeout: 10000,

    headers: {
        "X-API-KEY": process.env.UNIFI_API_KEY,
        Accept: "application/json",
    },

    httpsAgent: new https.Agent({
        rejectUnauthorized: process.env.UNIFI_VERIFY_TLS === "true",
    }),
});

// UniFi will normally send guests to a URL resembling:
// /guest/s/default?ap=...&id=CLIENT_MAC&url=...&ssid=guest-ssid

app.get('/guest/s/:site/', (req, res) => {
    res.sendFile(path.join(__dirname, "public", "index.html"));
});

app.post('/authorize', async (req, res) => {
    try {
        const { mac, returnUrl } = req.body;

        if (!mac) {
            return res.status(400).json({
                error: 'Client MAC address was not provided.'
            });
        }

        const normalizedMac = mac.toLowerCase();

        const macRegex = /^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i;

        if (!macRegex.test(normalizedMac)) {
            return res.status(400).json({
                error: "Invalid MAC address.",
            });
        }

        console.log(`Looking up client ${normalizedMac}`);

        // Find UniFi ClientId using the clients mac address

        const clientResponse = await unifi.get(`/sites/${SITE_ID}/clients`, {
            params: {
                filter: `macAddress.eq('${normalizedMac}')`,
            }
        });

        const clients = clientResponse.data.data || [];

        if (clients.length === 0) {
            console.log(`Client not found.`)

            return res.status(404).json({
                error: `Guest device could not be found in UniFi.`
            });
        }

        const client = clients[0];

        console.log(`Client ID: ${client.id}`)
        console.log(`Authorizing ${client.macAddress}`)

        // Authorize the guest

        await unifi.post(`/sites/${SITE_ID}/clients/${client.id}/actions`, {
            action: "AUTHORIZE_GUEST_ACCESS",

            // 8 hours
            timeLimitMinutes: 480,
        });

        console.log(`Guest authorized`);

        // validate the original url before redirecting

        let safeRedirect = null;

        if (returnUrl) {
            try {
                const parsed = new URL(returnUrl);

                if (parsed.protocol === "http:" || parsed.protocol === "https:") {
                    safeRedirect = returnUrl;
                }
            } catch {
                // invalid redirect; ignore it
            }
        }

        res.json({
            success: true,
            redirect: safeRedirect
        });
    } catch (error) {
        console.error(`Authorization error:`, error.response?.data || error.message);

        res.status(500).json({
            error: `Unable to authorize guest device`
        });
    }
});

app.get('/health', (req, res) => {
    res.json({
        status: 'ok'
    });
});

app.listen(PORT, "0.0.0.0", () => {
    console.log("")
    console.log(`UniFi External Guest Portal`)
    console.log("")

    console.log(`Listening on port ${PORT}`)
    console.log(`http://localhost:${PORT}`)
    console.log("")
})