// server.cjs — CommonJS, no ESM, clean rebuild
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || "";
const DATABASE_URL = process.env.DATABASE_URL || "";

let pool = null;
if (DATABASE_URL) {
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  pool.connect()
    .then(() => console.log("✅ Connected to Postgres"))
    .catch(err => console.error("❌ Postgres connection error:", err.message));
} else {
  console.log("ℹ️ No DATABASE_URL set; skipping DB connect.");
}

app.use('/webhooks/shopify', bodyParser.raw({ type: '*/*' }));

function verifyShopifyHmac(req) {
  const hmac = req.get('x-shopify-hmac-sha256');
  if (!hmac || !SHOPIFY_WEBHOOK_SECRET) return false;
  const digest = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.body)
    .digest('base64');
  try {
    return crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(digest));
  } catch {
    return false;
  }
}

app.post('/webhooks/shopify/orders-paid', async (req, res) => {
  if (!verifyShopifyHmac(req)) {
    console.error('❌ Invalid Shopify HMAC');
    return res.status(401).send('Invalid signature');
  }

  let payload = {};
  try {
    payload = JSON.parse(req.body.toString('utf8'));
  } catch (e) {
    console.error('❌ JSON parse error:', e.message);
    return res.status(400).send('Bad Request');
  }

  console.log('✅ Webhook verified', { topic: 'orders/paid', id: payload?.id });

  try {
    if (pool) await pool.query('select 1;');
  } catch (e) {
    console.error('DB error:', e.message);
  }

  return res.status(200).send('ok');
});

app.get('/', (_req, res) => res.send('OK'));

app.listen(PORT, () => {
  console.log(`🚀 Server listening on ${PORT}`);
});
