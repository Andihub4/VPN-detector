const express = require("express");

const app = express();
const PORT = 3000;

// -----------------------------
// SIMPLE CACHE (production-lite)
// -----------------------------
const cache = new Map();
const CACHE_TTL = 1000 * 60 * 10; // 10 min

// -----------------------------
// GET CLIENT IP
// -----------------------------
function getClientIP(req) {
    let ip =
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress ||
        "";

    ip = ip.split(",")[0].trim();
    ip = ip.replace("::ffff:", "");

    // FIX: localhost handling
    if (ip === "127.0.0.1" || ip === "::1" || !ip) {
        ip = "8.8.8.8"; // fallback test IP
    }

    return ip;
}

// -----------------------------
// FETCH IP INFO (FREE API)
// -----------------------------
async function getIPInfo(ip) {
    const cached = cache.get(ip);
    if (cached && Date.now() - cached.time < CACHE_TTL) {
        return cached.data;
    }

    const res = await fetch(`http://ip-api.com/json/${ip}?fields=status,country,city,isp,org,as,proxy,hosting,query`);
    const data = await res.json();

    if (data.status !== "success") {
        return null;
    }

    cache.set(ip, {
        time: Date.now(),
        data
    });

    return data;
}

// -----------------------------
// RISK ENGINE (VPN DETECTION)
// -----------------------------
function calculateRisk(data) {
    let score = 0;
    let reasons = [];

    const isp = (data.isp || "").toLowerCase();
    const org = (data.org || "").toLowerCase();
    const asn = (data.as || "").toLowerCase();

    // 1. Hosting / Datacenter detection
    const hostingKeywords = [
        "amazon",
        "aws",
        "google",
        "cloud",
        "azure",
        "microsoft",
        "digitalocean",
        "vultr",
        "linode",
        "hosting"
    ];

    if (
        hostingKeywords.some(k =>
            isp.includes(k) ||
            org.includes(k) ||
            asn.includes(k)
        )
    ) {
        score += 40;
        reasons.push("Datacenter / hosting IP detected");
    }

    // 2. IP flagged as proxy (ip-api free field)
    if (data.proxy) {
        score += 50;
        reasons.push("Proxy detected by IP database");
    }

    // 3. Hosting flag (ip-api feature)
    if (data.hosting) {
        score += 35;
        reasons.push("Hosting provider IP");
    }

    // 4. Suspicious ASN patterns
    if (data.as && data.as.length < 8) {
        score += 10;
        reasons.push("Unusual ASN format");
    }

    // Clamp score
    if (score > 100) score = 100;

    let level = "LOW";

    if (score >= 30) level = "MEDIUM";
    if (score >= 60) level = "HIGH";
    if (score >= 85) level = "CRITICAL";

    return {
        score,
        level,
        reasons
    };
}

// -----------------------------
// MAIN API ROUTE
// -----------------------------
app.get("/check", async (req, res) => {
    try {
        const ip = getClientIP(req);

        const data = await getIPInfo(ip);

        if (!data) {
            return res.status(500).json({
                error: "IP lookup failed",
                ip
            });
        }

        const risk = calculateRisk(data);

        res.json({
            ip: data.query,
            country: data.country,
            city: data.city,
            isp: data.isp,
            org: data.org,
            asn: data.as,
            proxy: data.proxy,
            hosting: data.hosting,
            risk
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({
            error: "Server error",
            message: err.message
        });
    }
});

// -----------------------------
// HEALTH CHECK
// -----------------------------
app.get("/", (req, res) => {
    res.send("VPN / Proxy Detector API running 🚀");
});

// -----------------------------
app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});
