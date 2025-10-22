import express from "express";
import crypto from "crypto";

const app = express();
const PORT = process.env.PORT || 10000;

app.get("/", (_req, res) => res.send("OK"));

// Shared verifier + handler
const verifyAndAck = (req, res) => {
  const secret = process.env.SHOPIFY_WEBHOOK_SECRET || "";
  const hmacHeader = req.get("x-shopify-hmac-sha256") || "";
  const topic = req.get("x-shopify-topic") || "unknown";
  const shop = req.get("x-shopify-shop-domain") || "unknown";
  const rawBody = req.body; // Buffer (express.raw)

  if (!secret || !hmacHeader || !rawBody) {
    console.warn("Webhook missing secret/header/body", {
      hasSecret: !!secret, hasHeader: !!hmacHeader, hasBody: !!rawBody,
    });
    return res.status(401).send("unauthorized");
  }

  const digest = crypto.createHmac("sha256", secret).update(rawBody).digest("base64");

  let verified = false;
  try {
    const a = Buffer.from(digest, "utf8");
    const b = Buffer.from(hmacHeader, "utf8");
    if (a.length === b.length) verified = crypto.timingSafeEqual(a, b);
  } catch { verified = false; }

  if (!verified) {
    console.warn("❌ Webhook HMAC verification FAILED", { shop, topic });
    return res.status(401).send("unauthorized");
  }

  let payload = {};
  try { payload = JSON.parse(rawBody.toString("utf8")); } catch {}

  console.log("✅ Webhook verified", { shop, topic, order_id: payload?.id });
  return res.status(200).send("ok");
};

// Keep original route (if anything is still pointing here)
app.post("/webhook", express.raw({ type: "application/json" }), verifyAndAck);

// Add YOUR Shopify route
app.post(
  "/webhooks/shopify/orders-paid",
  express.raw({ type: "application/json" }),
  verifyAndAck
);

// JSON parser can come after webhook routes for other endpoints
app.use(express.json());

app.listen(PORT, () => {
  console.log(`Server listening on ${PORT}`);
});
