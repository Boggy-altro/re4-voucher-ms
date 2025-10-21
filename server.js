// server.js — minimal test server (ESM)
import express from 'express';

const app = express();

app.get('/', (_req, res) => {
  res.status(200).send('HELLO FROM LOCALHOST');
});

const PORT = process.env.PORT || 3000;

// Extra logging to prove it's listening
app.listen(PORT, () => {
  console.log('==== STARTUP ====');
  console.log(`Node version: ${process.version}`);
  console.log(`Listening on http://localhost:${PORT}/`);
});
