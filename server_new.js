const express = require('express');
const crypto = require('crypto');

const app = express();

// Capture raw body for Shopify HMAC check
app.use(express.json({
  verify: (req, _res, buf) => { req.rawBody = buf; }
}));

app.get('/healthz', (_req, res) => res.status(200).send('ok'));

console.log('[BOOT] SHOPIFY_WEBHOOK_SECRET length:',
  (process.env.SHOPIFY_WEBHOOK_SECRET || '').trim().length,
  'hex?', /^[0-9a-f]{64}$/i.test((process.env.SHOPIFY_WEBHOOK_SECRET || '').trim())
);

function verifyHmac(req, res, next) {
  try {
    const secret = (process.env.SHOPIFY_WEBHOOK_SECRET || '').trim();
    const header = (req.get('x-shopify-hmac-sha256') || '').trim();
    const body = req.rawBody || Buffer.alloc(0);
    const isHex = /^[0-9a-f]{64}$/i.test(secret);
    const key = isHex ? Buffer.from(secret, 'hex') : Buffer.from(secret, 'utf8');
    const digest = crypto.createHmac('sha256', key).update(body).digest('base64');

    if (crypto.timingSafeEqual(Buffer.from(digest), Buffer.from(header))) {
      console.log('> HMAC verified OK');
      next();
    } else {
      console.log('> HMAC mismatch');
      res.status(401).send('unauthorized');
    }
  } catch (err) {
    console.error('HMAC verify error', err);
    res.status(401).send('unauthorized');
  }
}

app.post('/webhooks/shopify/orders-paid', verifyHmac, (req, res) => {
  console.log('> RE4 webhook hit', new Date().toISOString());
  res.status(200).send('ok');
});

const PORT = process.env.PORT || 10000;
app.listen(PORT, () => console.log(`RE4 Voucher MS listening on port ${PORT}`));
