import express from 'express';
import { webdecoy } from '@webdecoy/express';
import { tripwire } from '@webdecoy/node';

// Local demonstration: expose summaries here so the verdict is visible.
// Keep this information server-side in a production application.
export function createApp(mode: 'monitor' | 'enforce' = 'monitor') {
  const app = express();
  app.disable('x-powered-by');
  app.use(express.json());
  app.get('/health', (_req, res) => res.json({ status: 'ok' }));
  app.use(webdecoy({
    mode,
    rules: [tripwire({ paths: ['/demo-decoy'], includeDefaults: false })],
    skipPaths: ['/health'],
  }));
  function decision(req: express.Request) {
    return {
      conclusion: req.webdecoyDecision?.conclusion,
      tripwire: req.webdecoyDecision?.deniedBy('tripwire') ?? false,
    };
  }
  app.get('/', (req, res) => {
    res.json({ message: 'Ordinary route', decision: decision(req) });
  });
  app.get('/demo-decoy', (req, res) => {
    res.status(404).json({ message: 'Controlled decoy route', decision: decision(req) });
  });
  app.get('/api/data', (req, res) => {
    res.json({ data: { message: 'Example data' }, decision: decision(req) });
  });
  app.post('/api/submit', (req, res) => {
    res.json({ success: true, received: req.body.data, decision: decision(req) });
  });
  return app;
}
