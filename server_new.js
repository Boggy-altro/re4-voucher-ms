function verifyHmac(req, res, next) {
  try {
    const secretRaw = (process.env.SHOPIFY_WEBHOOK_SECRET || '').trim();
    const hmacHeader = (req.get('x-shopify-hmac-sha256') || '').trim();
    const body = req.rawBody || Buffer.alloc(0);
    const crypto = require('crypto');

    const isHex = /^[0-9a-f]{64}$/i.test(secretRaw);
    const keyHex = isHex ? Buffer.from(secretRaw, 'hex') : null;
    const keyUtf = Buffer.from(secretRaw, 'utf8');

    const digestHex = keyHex ? crypto.createHmac('sha256', keyHex).update(body).digest('base64') : null;
    const digestUtf = crypto.createHmac('sha256', keyUtf).update(body).digest('base64');

    const matchHex = digestHex ? crypto.timingSafeEqual(Buffer.from(digestHex), Buffer.from(hmacHeader)) : false;
    const matchUtf = crypto.timingSafeEqual(Buffer.from(digestUtf), Buffer.from(hmacHeader));

    // one-time debug
    if (!req._hmacDebugged) {
      const mask = s => (s ? s.slice(0, 10) + '…' + s.slice(-6) : 'null');
      console.log('[HMAC] header len:', hmacHeader.length, 'body bytes:', body.length, 'isHexSecret:', isHex);
      console.log('[HMAC] ours(hex):', mask(digestHex), ' ours(utf8):', mask(digestUtf), ' header:', mask(hmacHeader));
      req._hmacDebugged = true;
    }

    if (!matchHex && !matchUtf) {
      console.log('> HMAC mismatch'); // 401 by design for bad signatures
      return res.status(401).send('unauthorized');
    }

    console.log('> HMAC verified OK', matchHex ? '(hex)' : '(utf8)');
    next();
  } catch (e) {
    console.error('HMAC verify error', e);
    return res.status(401).send('unauthorized');
  }
}
