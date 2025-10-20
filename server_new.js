import express from "express";
import crypto from "crypto";
import axios from "axios";
import getRawBody from "raw-body";

const app = express();
const PORT = process.env.PORT || 10000;

// Health check
app.get("/healthz", (_req, res) => res.status(200).send("ok"));

// Shopify Orders Paid webhook
app.post("/webhooks/shopify/orders-paid", async (req, res) => {
  try {
    // --- diagnostics
    console.log(
      "> RE4 webhook hit",
      new Date().toISOString(),
      "topic=",
      req.header("X-Shopify-Topic"),
      "hmac-present=",
      !!req.header("X-Shopify-Hmac-Sha256")
    );

    // Read raw body (required for HMAC)
    const rawBody = await getRawBody(req);

    // Build HMAC using secret in the right encoding (hex OR utf8)
    const incomingHmac = req.header("X-Shopify-Hmac-Sha256");
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET || "";
    let secretBuf;
    if (/^[0-9a-fA-F]{64,}$/.test(secret)) {
      // long hex from Notifications page
      secretBuf = Buffer.from(secret, "hex");
    } else {
      // whsec_... or any non-hex secret
      secretBuf = Buffer.from(secret, "utf8");
    }
    const digest = crypto.createHmac("sha256", secretBuf).update(rawBody).digest("base64");

    if (
      !incomingHmac ||
      !crypto.timingSafeEqual(Buffer.from(incomingHmac, "utf8"), Buffer.from(digest, "utf8"))
    ) {
      console.error("> HMAC mismatch");
      return res.status(401).send("HMAC validation failed");
    }

    // Parse JSON and get order id
    const body = JSON.parse(rawBody.toString("utf8"));
    const orderId = body?.id;
    if (!orderId) {
      console.error("> No order id in payload");
      return res.status(400).send("No order id");
    }
    console.log("> Valid webhook for order", orderId);

    // Generate a placeholder code (replace with real allocator later)
    const code = `TEST-RE4-${String(orderId).slice(-6)}`;
    console.log("> Generated code:", code);

    // Write metafield to the order
    const store = process.env.SHOPIFY_STORE_DOMAIN; // e.g. fdiwym-ci.myshopify.com
    const adminToken = process.env.SHOPIFY_ADMIN_TOKEN; // shpat_...
    const ns = process.env.METAFIELD_NAMESPACE || "custom";
    const key = process.env.METAFIELD_KEY || "bookeo_code";

    const url = `https://${store}/admin/api/2025-10/orders/${orderId}/metafields.json`;
    const payload = {
      metafield: {
        namespace: ns,
        key: key,
        type: "single_line_text_field",
        value: code,
      },
    };

    const r = await axios.post(url, payload, {
      headers: {
        "Content-Type": "application/json",
        "X-Shopify-Access-Token": adminToken,
      },
      validateStatus: () => true,
    });

    if (r.status >= 200 && r.status < 300) {
      console.log("> Metafield written OK", r.status);
      return res.status(200).send("Webhook processed successfully");
    } else {
      console.error("> Shopify write failed", r.status, r.data);
      // Still return 200 so Shopify doesn’t spam retries while we debug
      return res.status(200).send("Received; write failed");
    }
  } catch (err) {
    console.error("> Webhook error:", err?.message || err);
    return res.status(500).send("Server error");
  }
});

// Fallback
app.use((_req, res) => res.status(404).send("Not found"));

app.listen(PORT, () => console.log(`> RE4 Voucher MS listening on port ${PORT}`));
