import express from 'express';
import { fileURLToPath } from 'node:url';
import { webdecoy } from '@webdecoy/express';
import { tripwire } from '@webdecoy/node';

// This is a controlled, keyless fixture. Decision details are exposed only so
// visitors can inspect the demo; keep such details server-side in a real app.
function probeRouter(mode) {
  const router = express.Router();
  router.use(webdecoy({
    mode,
    rules: [tripwire({ paths: ['/demo-decoy'], includeDefaults: false })],
  }));
  const reply = (req, res, status) => res.status(status).json({
    mode,
    path: req.path,
    decision: {
      conclusion: req.webdecoyDecision?.conclusion,
      tripwire: req.webdecoyDecision?.deniedBy('tripwire') ?? false,
    },
  });
  router.get('/', (req, res) => reply(req, res, 200));
  router.get('/demo-decoy', (req, res) => reply(req, res, 404));
  return router;
}

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  app.use('/monitor', probeRouter('monitor'));
  // A separate fixture, selected explicitly by the playground visitor.
  app.use('/enforce', probeRouter('enforce'));
  app.use(express.static(fileURLToPath(new URL('./public/', import.meta.url))));
  return app;
}
