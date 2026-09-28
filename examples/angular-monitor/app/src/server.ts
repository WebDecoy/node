import { AngularNodeAppEngine, createNodeRequestHandler, isMainModule, writeResponseToNodeResponse } from '@angular/ssr/node';
import express from 'express';
import { join } from 'node:path';
import { webdecoy } from '@webdecoy/express';
import { tripwire, rateLimit } from '@webdecoy/node';

const app = express();
const angularApp = new AngularNodeAppEngine();
const browserDistFolder = join(import.meta.dirname, '../browser');

// Local loopback server: no forwarding headers are trusted.
app.set('trust proxy', false);
app.get('/health', (_req, res) => res.json({ ok: true }));
// Only actual build assets bypass observation; extension matching alone is unsafe.
app.use(express.static(browserDistFolder, { index: false, redirect: false, maxAge: '1y', dotfiles: 'ignore' }));
app.use(webdecoy({
  mode: 'monitor',
  apiKey: process.env['WEBDECOY_API_KEY'] || undefined,
  honeytoken: false,
  rules: [
    tripwire({ paths: ['/.env', '/wp-config.php'] }),
    rateLimit({ max: 60, window: 60 }),
  ],
}));
app.use((req, _res, next) => {
  const decision = req.webdecoyDecision;
  if (decision) console.log(JSON.stringify({
    event: 'webdecoy-decision',
    route: req.path === '/api/products' ? 'catalog' : req.path === '/' ? 'page' : 'other',
    conclusion: decision.conclusion,
    wouldBlock: !decision.allowed,
    tripwire: decision.deniedBy('tripwire'),
    testTrigger: decision.detection.bot_type === 'test_trigger',
    dashboardConfigured: Boolean(process.env['WEBDECOY_API_KEY']),
    reportingError: decision.error ? true : false,
    rules: decision.results.map(({ rule, state, conclusion }) => ({ rule, state, conclusion })),
  }));
  next();
});
app.get('/api/products', (_req, res) => res.json({ products: [
  { id: 1, name: 'Demo field notebook' }, { id: 2, name: 'Demo canvas bag' },
] }));
// No real sensitive file exists. Monitor mode preserves the application's 404.
app.get(['/.env', '/wp-config.php'], (_req, res) => res.status(404).json({ error: 'not_found' }));
app.use((req, res, next) => {
  angularApp.handle(req).then(response => response ? writeResponseToNodeResponse(response, res) : next()).catch(next);
});
if (isMainModule(import.meta.url)) {
  const port = Number(process.env['PORT'] || 4300);
  app.listen(port, '127.0.0.1', () => console.log(`Monitor demo: http://127.0.0.1:${port}`));
}
export const reqHandler = createNodeRequestHandler(app);
