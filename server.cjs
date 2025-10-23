// server.cjs — hardened webhook server (CommonJS)
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Env ----
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || "";
const DATABASE_URL = process.env.DATABASE_URL || "";
const SHOPIFY_SHOP = process.env.SHOPIFY_SHOP || "unknown_shop";

// ---- DB ----
let pool = null;
async function initDb() {
  if (!DATABASE_URL) {
    console.log("ℹ️ No DATABASE_URL set; skipping DB connect.");
    return;
  }
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false },
  });
  await pool.connect();
  console.log("✅ Connected to Postgres");

  await pool.query(`
    create table if not exists orders_paid_events (
      id bigserial primary key,
      shop text not null,
      order_id text,
      received_at timestamptz not null default now(),
      payload jsonb not null
    );
  `);
  await pool.query(`create index if not exists idx_orders_paid_events_order_id on orders_paid_events(order_id);`);
  await pool.query(`create index if not exists idx_orders_paid_events_received_at on orders_paid_events(received_at);`);
  console.log("✅ DB ready (table: orders_paid_events)");
}

// ---- Normal JSON for non-webhook routes ----
app.use(express.json());

// ---- Strict method/content guard for the webhook path ----
app.all('/webhooks/shopify/orders-paid', (req, res, next) => {
  if (req.method !== 'POST') {
    res.set('Allow', 'POST');
    return res.status(405).send('Method Not Allowed'); // prevents browser GETs from causing errors
  }
  // Content-Type must be JSON; Shopify sends 'application/json'
  const ct = (req.headers['content-type'] || '').split(';')[0].trim().toLowerCase();
  if (ct !== 'application/json') {
    return res.status(415).send('Unsupported Media Type');
  }
  return next();
});

// ---- Use RAW body ONLY for this one route (prevents parsing issues) ----
app.post(
  '/webhooks/shopify/orders-paid',
  bodyParser.raw({ type: 'application/json' }),
  async (req, res) => {
    const hmac = req.get('x-shopify-hmac-sha256');
    if (!hmac || !SHOPIFY_WEBHOOK_SECRET) {
      console.error('❌ Missing HMAC or secret');
      return res.status(401).send('Invalid signature');
    }

    // Compute HMAC on raw body
    const digest = crypto
      .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
      .update(req.body) // Buffer
      .digest('base64');

    let safeEqual = false;
    try {
      safeEqual = crypto.timingSafeEqual(Buffer.from(hmac), Buffer.from(digest));
    } catch (_) {
      // If lengths differ, timingSafeEqual throws; treat as invalid
      safeEqual = false;
    }
    if (!safeEqual) {
      console.error('❌ Invalid Shopify HMAC');
      return res.status(401).send('Invalid signature');
    }

    // Parse AFTER verification
    let payload = {};
    try {
      payload = JSON.parse(req.body.toString('utf8'));
    } catch (e) {
      console.error('❌ JSON parse error:', e.message);
      return res.status(400).send('Bad Request');
    }

    const orderId = String(payload?.id ?? payload?.order_id ?? '');

    console.log('✅ Webhook verified', { topic: 'orders/paid', id: orderId });

    // Best-effort DB insert (non-blocking for Shopify)
    try {
      if (pool) {
        await pool.query(
          'insert into orders_paid_events (shop, order_id, payload) values ($1, $2, $3)',
          [SHOPIFY_SHOP, orderId, payload]
        );
      }
    } catch (e) {
      console.error('DB insert error:', e.message);
      // continue; we still ACK to Shopify
    }

    return res.status(200).send('ok');
  }
);

// ---- Health endpoints ----
app.get('/', (_req, res) => res.send('OK'));
app.get('/health', (_req, res) => {
  res.json({ ok: true, db: !!pool, time: new Date().toISOString() });
});

// ---- Global error handler (keeps logs clean) ----
app.use((err, _req, res, _next) => {
  console.error('Unhandled error:', err && err.stack ? err.stack : err);
  res.status(500).send('error');
});

// ---- Start ----
(async () => {
  try {
    await initDb();
    app.listen(PORT, () => {
      console.log(`🚀 Server listening on ${PORT}`);
      if (!SHOPIFY_WEBHOOK_SECRET) {
        console.warn('⚠️ SHOPIFY_WEBHOOK_SECRET is empty — webhook verification will fail.');
      }
    });
  } catch (err) {
    console.error('❌ Fatal startup error:', err);
    process.exit(1);
  }
})();

// ---- Graceful shutdown ----
process.on('SIGTERM', async () => {
  try {
    if (pool) await pool.end();
  } finally {
    process.exit(0);
  }
});

