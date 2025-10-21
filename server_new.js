function verifyHmac(req, res, next) {
  try {
    const secretRaw = (process.env.SHOPIFY_WEBHOOK_SECRET || '').trim();
    const hmacHeader = req.get('x-shopify-hmac-sha256') || '';

    // Quick debug (safe): lengths and format only
    if (!req._hmacLoggedOnce) {
      console.log('[HMAC] secret length:', secretRaw.length, 'hex?', /^[0-9a-f]{64}$/i.test(secretRaw));
      console.log('[HMAC] header length:', hmacHeader.length, 'rawBody bytes:', (req.rawBody ? req.rawBody.length : 0));
      req._hmacLoggedOnce = true;
    }

    const crypto = require('crypto');
    const body = req.rawBody || Buffer.alloc(0);

    // Compute digests with both interpretations (hex and utf8)
    const digestHex = /^[0-9a-f]{64}$/i.test(secretRaw)
      ? crypto.createHmac('sha256', Buffer.from(secretRaw, 'hex')).update(body).digest('base64')
      : null;

    const digestUtf8 = crypto.createHmac('sha256', secretRaw).update(body).digest('base64');

    const matchHex = digestHex ? crypto.timingSafeEqual(Buffer.from(digestHex), Buffer.from(hmacHeader)) : false;
    const matchUtf8 = crypto.timingSafeEqual(Buffer.from(digestUtf8), Buffer.from(hmacHeader));

    if (!matchHex && !matchUtf8) {
      console.log('> HMAC mismatch');
      return res.status(401).send('unauthorized');
    }

    console.log('> HMAC verified OK', matchHex ? '(hex)' : '(utf8)');
    next();
  } catch (err) {
    console.error('HMAC verify error', err);
    res.status(401).send('unauthorized');
  }
}
