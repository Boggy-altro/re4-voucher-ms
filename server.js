// server.js — minimal ESM app for Render
import express from 'express';

const app = express();

// health check
app.get('/', (_req, res) => {
  res.status(200).send('OK');
});

// webhook stub: always 200 so Shopify succeeds
app.post('/webhook', (_req, res) => {
  res.status(200).send('OK');
});

// Render gives PORT; bind 0.0.0.0
const PORT = process.env.PORT || 3000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server running on ${PORT}`);
});
