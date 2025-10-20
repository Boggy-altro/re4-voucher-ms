import express from 'express';
import crypto from 'crypto';
import getRawBody from 'raw-body';
import axios from 'axios';

const app = express();
const PORT = process.env.PORT || 3000;

// ENV from Render
const STORE_DOMAIN   = process.env.SHOPIFY_STORE_DOMAIN;      // e.g. fdiwym-ci.myshopify.com
const ADMIN_TOKEN    = process.env.SHOPIFY_ADMIN_TOKEN;       // shpat_...
const WEBHOOK_SECRET = process.env.SHOPIFY_WEBHOOK_SECRET;    // whsec_... OR long hex from Notifications
const META_NS        = process.env.METAFIELD_NAMESPACE || 'custom';
const META_KEY       = process.env.METAFIELD_KEY || 'bookeo_code';

// health check
app.get('/healthz', (_req, res) => res.type('text').send('ok'));

// orders paid webhook (raw body for HMAC)
app.post('/webhooks/shopify/orders-paid', async (req, res) => {
  try {
    const raw = await getRawBody(req);
    const hmacHeader = req.header('X-Shopify-Hmac-Sha256') || req.header('X-Shopify-Hmac-SHA256');

    // Shopify Notifications may show a HEX secret; support both hex and utf8
    let secretBuf;
    if (/^[0-9a-fA-F]{64,}$/.test(WEBHOOK_SECRET || '')) {
      secretBuf = Buffer.from(WEBHOOK_SECRET, 'hex');
    } else {
      secretBuf = Buffer.from(WEBHOOK_SECRET || '', 'utf8');
    }

    const digest = crypto.createHmac('sha256', secretBuf).update(raw).digest('base64');
    if (!hmacHeader || !crypto.timingSafeEqual(Buffer.from(hmacHeader, 'utf8'), Buffer.from(digest, 'utf8'))) {
      return res.status(401).send('HMAC validation failed');
    }

    const data = JSON.parse(raw.toString('utf8'));
    const orderId = data?.id;
    if (!orderId) return res.status(400).send('No order id');

    // placeholder allocator – swap to your real pool later
    const code = `TEST-RE4-${String(orderId).slice(-6)}`;

    // write metafield on the order
    const url = `https://${STORE_DOMAIN}/admin/api/2025-10/orders/${orderId}/metafields.json`;
    const body = {
      metafield: {
        namespace: META_NS,
        key: META_KEY,
        type: "single_line_text_field",
        value: code
      }
    };

    await axios.post(url, body, {
      headers: {
        'X-Shopify-Access-Token': ADMIN_TOKEN,
        'Content-Type': 'application/json'
      }
    });

    return res.status(200).json({ status: 'ok', set: body.metafield });
  } catch (err) {
    console.error('Webhook error:', err?.response?.status, err?.response?.data || err.message);
    return res.status(500).send('Server error');
  }
});

// 404
app.use((_req, res) => res.status(404).send('Not found'));

app.listen(PORT, () => console.log('RE4 Voucher MS listening on port', PORT));
