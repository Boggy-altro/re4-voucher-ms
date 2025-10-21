// server.js (ESM)
import express from 'express';
import axios from 'axios';
import getRawBody from 'raw-body';

const app = express();

// Use JSON parser only for your own API paths
app.use('/api', express.json());

// Health
app.get('/', (_req, res) => res.status(200).send('OK'));

// Webhook (kept simple; raw body preserved)
app.post('/webhook', async (req, res) => {
  try {
    const raw = await getRawBody(req, { encoding: false });
    // TODO: verify HMAC + do your processing
    res.status(200).send('OK');
  } catch (e) {
    res.status(500).send('Error');
  }
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => console.log(`Server running on ${PORT}`));
