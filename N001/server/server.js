import 'dotenv/config';
import express from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import analyzerRoutes from './routes/analyzerRoutes.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const projectRoot = path.resolve(__dirname, '..');
const frontendDist = path.join(projectRoot, 'dist');
const app = express();
const port = Number(process.env.PORT) || 4100;

app.disable('x-powered-by');
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));
app.use(express.json({ limit: '1mb' }));
app.use('/api/analyze', rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 120,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
}));

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', service: 'N001 analyzer' });
});
app.use('/api/analyze', analyzerRoutes);

app.use('/api', (req, res) => res.status(404).json({ error: 'API endpoint not found.' }));

if (fs.existsSync(frontendDist)) {
  app.use(express.static(frontendDist));
  app.get('/{*path}', (req, res) => res.sendFile(path.join(frontendDist, 'index.html')));
}

app.use((error, req, res, next) => {
  if (res.headersSent) return next(error);
  console.error('[server]', error);
  return res.status(error.status || 500).json({ error: error.status ? error.message : 'Analyzer request failed.' });
});

app.listen(port, '127.0.0.1', () => {
  console.log(`N001 analyzer backend: http://127.0.0.1:${port}`);
});
