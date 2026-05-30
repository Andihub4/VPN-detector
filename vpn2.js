const express = require("express");
const app = express();
const PORT = 3000;

// ---------------------
// CACHE (simple production style)
// ---------------------
const cache = new Map();
const CACHE_TTL = 1000 * 60 * 10;

// ---------------------
// IP PROVIDERS (FREE)
// ---------------------
const PROVIDERS = [
    (ip) => fetch(`http://ip-api.com/json/${ip}?fields=status,country,isp,org,as,proxy,hosting,query`)
        .then(r => r.json()),

    (ip) => fetch(`https://ipwho.is/${ip}`)
        .then(r => r.json())
];

// ---------------------
// GET CLIENT IP
// ---------------------
function getIP(req) {
    let ip =
        req.headers["x-forwarded-for"] ||
        req.socket.remoteAddress ||
        "";

    ip = ip.split(",")[0].trim().replace("::ffff:", "");

    if (!ip || ip === "::1") ip = "8.8.8.8"; // fallback safe test

    return ip;
}

// ---------------------
// MULTI SOURCE FETCH
// ---------------------
async function getIPIntelligence(ip) {
    const cached = cache.get(ip);
    if (cached && Date.now() - cached.time < CACHE_TTL) {
        return cached.data;
    }

    const results = [];

    for (const provider of PROVIDERS) {
        try {
            const data = await provider(ip);

            if (data && (data.status === "success" || data.success !== false)) {
                results.push(data);
            }
        } catch (e) {}
    }

    if (results.length === 0) return null;

    cache.set(ip, { time: Date.now(), data: results });

    return results;
}

// ---------------------
// ASN INTELLIGENCE LAYER
// ---------------------
function analyzeASN(asnString = "") {
    const asn = asnString.toLowerCase();

    let score = 0;
    let reasons = [];

    const vpnHeavyASNs = [
        "digitalocean",
        "aws",
        "amazon",
        "google",
        "azure",
        "vultr",
        "linode",
        "ovh",
        "hetzner"
    ];

    if (vpnHeavyASNs.some(k => asn.includes(k))) {
        score += 35;
        reasons.push("ASN belongs to common hosting infrastructure");
    }

    return { score, reasons };
}

// ---------------------
// CONSENSUS RISK ENGINE
// ---------------------
function calculateRisk(sources) {
    let score = 0;
    let reasons = [];

    let vpnVotes = 0;
    let proxyVotes = 0;
    let hostingVotes = 0;

    let asnScore = 0;

    const primary = sources[0];

    const isp = (primary.isp || "").toLowerCase();
    const org = (primary.org || "").toLowerCase();
    const asn = primary.as || "";

    // ---------------------
    // Vote-based consensus
    // ---------------------
    for (const s of sources) {
        if (s.proxy === true) proxyVotes++;
        if (s.hosting === true) hostingVotes++;
        if (s.security?.vpn === true) vpnVotes++;
    }

    if (vpnVotes >= 1) {
        score += 55;
        reasons.push("VPN detected by at least one provider");
    }

    if (proxyVotes >= 1) {
        score += 45;
        reasons.push("Proxy detected by consensus");
    }

    if (hostingVotes >= 2) {
        score += 30;
        reasons.push("Multiple sources confirm hosting/datacenter IP");
    }

    // ---------------------
    // ASN intelligence
    // ---------------------
    const asnResult = analyzeASN(asn);
    asnScore += asnResult.score;
    reasons.push(...asnResult.reasons);

    score += asnScore;

    // ---------------------
    // ISP heuristics (light weight only)
    // ---------------------
    const riskyKeywords = ["vpn", "proxy", "hosting", "server"];

    if (riskyKeywords.some(k => isp.includes(k) || org.includes(k))) {
        score += 20;
        reasons.push("ISP/org contains suspicious keywords");
    }

    // ---------------------
    // Final normalization
    // ---------------------
    if (score > 100) score = 100;

    let level = "LOW";

    if (score >= 30) level = "MEDIUM";
    if (score >= 60) level = "HIGH";
    if (score >= 85) level = "CRITICAL";

    return {
        score,
        level,
        vpnVotes,
        proxyVotes,
        hostingVotes,
        reasons
    };
}


app.get("/", (req, res) => {
    res.json({
        status: "ok",
        message: "VPN Detector API is running 🚀",
        time: new Date().toISOString()
    });
});

// ---------------------
// MAIN API
// ---------------------
app.get("/check", async (req, res) => {
    try {
        const ip = getIP(req);

        const sources = await getIPIntelligence(ip);

        if (!sources) {
            return res.status(500).json({
                error: "IP intelligence failed"
            });
        }

        const risk = calculateRisk(sources);

        const primary = sources[0];

        res.json({
            ip: primary.query || ip,
            country: primary.country,
            isp: primary.isp,
            org: primary.org,
            asn: primary.as,
            sources: sources.length,
            risk
        });

    } catch (err) {
        res.status(500).json({
            error: "Server error",
            message: err.message
        });
    }
});

// ---------------------
app.listen(PORT, () => {
    console.log(`V3 Intelligence Engine running on http://localhost:${PORT}`);
});
