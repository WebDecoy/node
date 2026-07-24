/**
 * Self-hosted captcha example.
 *
 * Serves a page with the @webdecoy/client checkbox widget, mounts the WebDecoy
 * captcha endpoints (PoW + in-process detection + tokens), and verifies the
 * issued token on a protected /login route.
 *
 *   npm run dev   →   http://localhost:3000
 */

import path from 'path';
import express, { type Request, type Response } from 'express';
import { webdecoyCaptcha } from '@webdecoy/express';
import { Captcha } from '@webdecoy/node';

const SECRET = process.env.WEBDECOY_SECRET || 'example-dev-secret-change-me';
const PORT = Number(process.env.PORT) || 3000;

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

// Serve the standalone browser bundle from the @webdecoy/client package.
app.get('/webdecoy.js', (_req: Request, res: Response) => {
  res.sendFile(require.resolve('@webdecoy/client/global'));
});

// Mount GET/POST /__webdecoy/{challenge,verify,score,token/verify}.
app.use(webdecoyCaptcha({ secret: SECRET }));

// Protected route: verify the session token the widget produced.
// (In production, share one Captcha instance/store between the endpoints and
// this check so single-use replay protection spans both.)
const captcha = new Captcha({ secret: SECRET });

app.post('/login', async (req: Request, res: Response) => {
  const token = req.body?.webdecoy_token as string | undefined;
  if (!token) {
    res.status(400).json({ ok: false, error: 'missing token' });
    return;
  }
  const result = await captcha.verifyToken(token, req.ip);
  if (!result.valid) {
    res.status(403).json({ ok: false, error: `captcha failed: ${result.reason}` });
    return;
  }
  res.json({ ok: true, message: 'Logged in', score: result.score });
});

app.listen(PORT, () => {
  console.log(`WebDecoy captcha example running at http://localhost:${PORT}`);
});
