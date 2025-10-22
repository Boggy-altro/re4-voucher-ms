import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 10000;

// Simple health check
app.get("/", (_req, res) => res.send("OK"));

// Webhook handler (Shopify orders/paid)
app.post(
  "/webhooks/shopify/orders-paid",
  express.raw({ type: "application/json" }),
  (req, res) => {
    // 1️⃣ Get environment secret + header
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET || "";
    const header = req.get("x-shopify-hmac-sha256") || "";

    // 2️⃣ Compute HMAC on raw body bytes
    const computed = crypto
      .createHmac("sha256", secret)
      .update(req.body)
      .digest(); // Buffer

    // 3️⃣ Decode Shopify's header from base64 and compare bytes
    const received = Buffer.from(header, "base64");
    const ok =
      received.length === computed.length &&
      crypto.timingSafeEqual(received, computed);

    if (!ok) {
      console.warn("❌ HMAC mismatch");
      return res.status(401).send("unauthorized");
    }

    // 4️⃣ Parse JSON payload (after verification)
    let payload = {};
    try {
      payload = JSON.parse(req.body.toString("utf8"));
    } catch (e) {
      console.warn("JSON parse error", e.message);
    }

    // 5️⃣ Log and acknowledge
    console.log("✅ Webhook verified", {
      shop: req.get("x-shopify-shop-domain"),
      topic: req.get("x-shopify-topic"),
      order_id: payload?.id,
    });

    return res.status(200).send("ok");
  }
);

// JSON parser for other routes (AFTER webhook)
app.use(express.json());

// Start server
app.listen(PORT, () => {
  console.log(`RE4 Voucher MS listening on port ${PORT}`);
});
