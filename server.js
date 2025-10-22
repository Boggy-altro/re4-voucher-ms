import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 10000;

/**
 * Healthcheck
 */
app.get("/", (_req, res) => res.send("OK"));

/**
 * Shopify Webhook (orders/paid)
 * Phase 2: verify HMAC, then 200 OK (no metafield creation yet)
 *
 * Important: use express.raw so we can compute the HMAC on the exact raw body.
 * Do NOT put a global express.json() before this route.
 */
app.post(
  "/webhook",
  express.raw({ type: "application/json" }),
  (req, res) => {
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET || "";
    const hmacHeader = req.get("x-shopify-hmac-sha256") || "";
    const topic = req.get("x-shopify-topic") || "unknown";
    const shop = req.get("x-shopify-shop-domain") || "unknown";
    const rawBody = req.body; // Buffer (because of express.raw)

    if (!secret || !hmacHeader || !rawBody) {
      console.warn("Webhook missing secret/header/body", {
        hasSecret: !!secret,
        hasHeader: !!hmacHeader,
        hasBody: !!rawBody,
      });
      return res.status(401).send("unauthorized");
    }

    // Compute HMAC on the raw bytes (no encoding/decoding changes)
    const digest = crypto
      .createHmac("sha256", secret)
      .update(rawBody)
      .digest("base64");

    // Constant-time comparison
    let verified = false;
    try {
      const a = Buffer.from(digest, "utf8");
      const b = Buffer.from(hmacHeader, "utf8");
      if (a.length === b.length) verified = crypto.timingSafeEqual(a, b);
    } catch {
      verified = false;
    }

    if (!verified) {
      console.warn("❌ Webhook HMAC verification FAILED", { shop, topic });
      return res.status(401).send("unauthorized");
    }

    // (Optional) parse after verification — safe to read payload now
    let payload = {};
    try {
      payload = JSON.parse(rawBody.toString("utf8"));
    } catch (e) {
      console.warn("JSON parse error after verification:", e?.message);
    }

    console.log("✅ Webhook verified", {
      shop,
      topic,
      order_id: payload?.id,
    });

    // Phase 2 requirement: just acknowledge success.
    return res.status(200).send("ok");
  }
);

// If you need JSON on other routes, add it AFTER the webhook route:
app.use(express.json());

app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
