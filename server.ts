import 'dotenv/config';
import express from 'express';
import path from 'node:path';
import fs from 'node:fs';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';

// Constant-time string comparison to avoid timing leaks
const safeCompare = (input: string, expected: string): boolean => {
  const a = Buffer.from(input, 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) {
    // Still perform dummy comparison to keep timing uniform
    crypto.timingSafeEqual(b, b);
    return false;
  }
  return crypto.timingSafeEqual(a, b);
};

async function startServer() {
  const app = express();
  app.use(express.json({ limit: '1mb' }));

  // Health check
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true, service: 'aurartist' });
  });

  // Server-side Admin Security Code verification (no plaintext PINs in client bundle)
  app.post('/api/admin/verify-pin', (req, res) => {
    const rawCode = typeof req.body?.code === 'string' ? req.body.code.trim() : '';
    const expectedCode = (process.env.ADMIN_SECURITY_CODE || 'TIST').trim();

    if (!rawCode) {
      res.status(400).json({ valid: false, message: 'Security code required.' });
      return;
    }

    const valid = safeCompare(rawCode.toUpperCase(), expectedCode.toUpperCase());
    if (!valid) {
      res.status(401).json({ valid: false, message: 'Invalid Security Code. Please try again.' });
      return;
    }

    res.json({ valid: true });
  });

  // Server-side Master Admin Email + Password login (reads ADMIN_PASSWORD env var, zero hardcoded password)
  app.post('/api/admin-login', (req, res) => {
    const rawEmail = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const rawPassword = typeof req.body?.password === 'string' ? req.body.password : '';

    const expectedEmail = (process.env.MASTER_ADMIN_EMAIL || 'rawat.ravinder53@gmail.com')
      .trim()
      .toLowerCase();
    const expectedPassword = process.env.ADMIN_PASSWORD || process.env.MASTER_ADMIN_PASSWORD || '';

    if (!expectedPassword) {
      res.status(500).json({
        ok: false,
        error: 'ADMIN_PASSWORD environment variable is not configured.',
      });
      return;
    }

    if (!rawEmail || !rawPassword) {
      res.status(401).json({ ok: false, error: 'Wrong Password' });
      return;
    }

    const emailMatch = safeCompare(rawEmail, expectedEmail);
    const passwordMatch = safeCompare(rawPassword, expectedPassword);

    if (!emailMatch || !passwordMatch) {
      res.status(401).json({ ok: false, error: 'Wrong Password' });
      return;
    }

    res.json({ ok: true });
  });

  // Server-side Master Admin Email + Password verification (legacy endpoint)
  app.post('/api/admin/verify-master', (req, res) => {
    const rawEmail = typeof req.body?.email === 'string' ? req.body.email.trim().toLowerCase() : '';
    const rawPassword = typeof req.body?.password === 'string' ? req.body.password : '';

    const expectedEmail = (process.env.MASTER_ADMIN_EMAIL || 'rawat.ravinder53@gmail.com')
      .trim()
      .toLowerCase();
    const expectedPassword = process.env.ADMIN_PASSWORD || process.env.MASTER_ADMIN_PASSWORD || '';

    if (!expectedPassword) {
      res.status(500).json({
        valid: false,
        message: 'ADMIN_PASSWORD environment variable is not configured.',
      });
      return;
    }

    if (!rawEmail || !rawPassword) {
      res.status(400).json({ valid: false, message: 'Email and Password are required.' });
      return;
    }

    const emailMatch = safeCompare(rawEmail, expectedEmail);
    const passwordMatch = safeCompare(rawPassword, expectedPassword);

    if (!emailMatch || !passwordMatch) {
      res.status(401).json({ valid: false, message: 'Wrong Password' });
      return;
    }

    res.json({ valid: true });
  });

  if (!isProduction) {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: {
        middlewareMode: true,
        hmr: process.env.DISABLE_HMR !== 'true',
      },
      appType: 'spa',
    });

    app.use(vite.middlewares);

    app.use('*', async (req, res, next) => {
      if (req.originalUrl.startsWith('/api/')) {
        next();
        return;
      }
      try {
        const indexPath = path.resolve(__dirname, 'index.html');
        let template = fs.readFileSync(indexPath, 'utf-8');
        template = await vite.transformIndexHtml(req.originalUrl, template);
        res.status(200).set({ 'Content-Type': 'text/html' }).end(template);
      } catch (err) {
        next(err);
      }
    });
  } else {
    const distDir = path.resolve(__dirname, 'dist');
    app.use(express.static(distDir, { index: false }));

    app.get('*', (req, res, next) => {
      if (req.originalUrl.startsWith('/api/')) {
        next();
        return;
      }
      res.sendFile(path.join(distDir, 'index.html'));
    });
  }

  app.listen(PORT, '0.0.0.0', () => {
    console.log(`AURARTIST server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start AURARTIST server:', err);
  process.exit(1);
});
