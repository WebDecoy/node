import express from 'express';
import { AddressInfo } from 'node:net';
import { webdecoyCaptcha } from './captcha';

jest.mock('@webdecoy/node', () => ({
  ...jest.requireActual('@webdecoy/node'),
  createCaptchaEndpoints: () => ({
    handle: async () => ({
      status: 200,
      headers: { 'set-cookie': '__Host-wd_cs=fixture; Path=/; Secure; HttpOnly' },
      body: { success: true },
    }),
  }),
}));

it('appends the CAPTCHA receipt to cookies set by the application', async () => {
  const app = express();
  app.use((_req, res, next) => {
    res.setHeader('set-cookie', 'app-session=fixture; Path=/; HttpOnly');
    next();
  });
  app.use(webdecoyCaptcha());
  const server = app.listen(0, '127.0.0.1');
  await new Promise<void>((resolve, reject) => server.once('listening', resolve).once('error', reject));
  try {
    const { port } = server.address() as AddressInfo;
    const response = await fetch(`http://127.0.0.1:${port}/__webdecoy/score`, { method: 'POST' });
    expect(response.status).toBe(200);
    expect(response.headers.getSetCookie()).toEqual([
      'app-session=fixture; Path=/; HttpOnly',
      '__Host-wd_cs=fixture; Path=/; Secure; HttpOnly',
    ]);
  } finally {
    server.close();
  }
});
