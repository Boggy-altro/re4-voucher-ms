// server_new.js
const express = require('express');
const crypto = require('crypto');
const bodyParser = require('body-parser');
const axios = require('axios');

const app = express();

// Capture raw body for HMAC validation
app.use(
  bodyParser.json({
    verify: (req, _res, buf) => {
      req.rawBody = buf;
    },
  })
);

app.get('/healthz', (_req, res) => {
  res.status(200).send('ok');
});

function verifyHmac(req, res, next) {
  try {
    const secret = process.env.SHOPIFY_WEBHOOK_SECRET || '';
    const hmacHeader = req.get('x-shopify-hmac-sha256') || '';

    // Calculate digest from raw body
    const digest = crypto
      .createHmac(
        'sha256',
        Buffer.from(
          secret,
          /^[0-9a-f]{64}$/i.test(secret) ? 'hex' : 'utf8'
        )
      )
      .update(req.rawBody)
      .digest('base64');

    const valid =
      hmacHeader &&
      crypto.timingSafeEqual(
        Buffer.from(digest),
        Buffer.from(hmacHeader)
      );

    if (!valid) {
      console.log('> HMAC mismatch');
      return res.status(401).send('unauthorized');
    }

    console.log('> HMAC verified OK');
    next();
  } catch (err) {
    console.error('HMAC verify error', err);
    res.status(401).send('unauthorized');
  }
}

app.post('/webhooks/shopify/orders-paid', verifyHmac, async (req, res) => {
  const order = req.body || {};
  const orderId = order.id;

  console.log('> RE4 webhook hit', new Date().toISOString(), 'topic=orders/paid', 'id=', orderId);

  // TODO: Metafield writing logic will go here
  res.status(200).send('ok');
});

// Start server
const PORT = process.env.PORT || 10000;
app.listen(PORT, () => {
  console.log(`RE4 Voucher MS listening on port ${PORT}`);
});
