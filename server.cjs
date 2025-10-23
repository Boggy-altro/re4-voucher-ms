// server.cjs — production-ready, CommonJS
const express = require('express');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const { Pool } = require('pg');

const app = express();
const PORT = process.env.PORT || 3000;

// ---- Env ----
const SHOPIFY_WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET || "";
const DATABASE_URL = process.env.DATABASE_URL || "";

// ---- DB ----
let pool = null;
async function initDb() {
  if (!DATABASE_URL) {
    console.log("ℹ️ No DATABASE_URL set; skipping DB connect.");
    return;
  }
  pool = new Pool({
    connectionString: DATABASE_URL,
    ssl: { rejectUnauthorized: false }
  });
  await pool.connect();
  console.log("✅ Connected to Postgres");

  // Create table if it doesn't exist (idempotent)
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

// ---- Middleware order ----
// JSON for normal routes
app.use(express.json());

// RAW for Shopify webhooks (MUST be before any JSON parser on this path)
app.use('/webhooks/shopify', bodyParser.raw({ type: '*/*' }));

function verifyShopifyHmac(req) {
  const hmac = req.get('x-shopify-hmac-sha256');
  if (!hmac || !SHOPIFY_WEBHOOK_SECRET) return false;
  const digest = crypto
    .createHmac('sha256', SHOPIFY_WEBHOOK_SECRET)
    .update(req.body) // Buffer
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

  const orderId = String(payload?.id || payload?.order_id || '');
  const shop = process.env.SHOPIFY_SHOP || 'unknown_shop';

  console.log('✅ Webhook verified', { topic: 'orders/paid', id: orderId });

  // Best effort DB write (non-blocking for Shopify)
  try {
    if (pool) {
      await pool.query(
        'insert into orders_paid_events (shop, order_id, payload) values ($1, $2, $3)',
        [shop, orderId, payload]
      );
    }
  } catch (e) {
    console.error('DB insert error:', e.message);
  }

  // Always ACK quickly so Shopify doesn't retry
  return res.status(200).send('ok');
});

// Health: simple and JSON
app.get('/', (_req, res) => res.send('OK'));
app.get('/health', (_req, res) => {
  res.json({
    ok: true,
    db: !!pool,
    time: new Date().toISOString()
  });
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
