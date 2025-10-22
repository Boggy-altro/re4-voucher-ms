const secret = process.env.SHOPIFY_WEBHOOK_SECRET || "";
const header = req.get("x-shopify-hmac-sha256") || "";

const computed = crypto.createHmac("sha256", secret).update(req.body).digest(); // Buffer
const received = Buffer.from(header, "base64");

const ok =
  received.length === computed.length &&
  crypto.timingSafeEqual(received, computed);

if (!ok) return res.status(401).send("unauthorized");
