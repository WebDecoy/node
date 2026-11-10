# @webdecoy/express

WebDecoy middleware for Express: tripwires, rate limits and other local rules, plus optional server-side bot detection reported to your WebDecoy dashboard. Starts in monitor mode.

[![npm version](https://img.shields.io/npm/v/@webdecoy/express.svg)](https://www.npmjs.com/package/@webdecoy/express)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @webdecoy/express @webdecoy/node
```

`@webdecoy/node` is the core SDK. This package depends on it, but install it directly too: `tripwire()`, `rateLimit()` and the other rules are imported from `@webdecoy/node`, and relying on a transitive dependency for your own imports breaks under strict package managers such as pnpm.

## Quick Start

```typescript
import express from 'express';
import { webdecoy } from '@webdecoy/express';

const app = express();

// Add Web Decoy protection
app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY,
    skipPaths: ['/health'],
  })
);

app.get('/api/data', (req, res) => {
  // req.webdecoy carries the detection (decision, confidence, threat_level, bot_detected)
  console.log('Bot detected:', req.webdecoy?.bot_detected);
  res.json({ data: 'protected' });
});

app.listen(3000);
```

Mount it before your routes.

The SDK does not read `WEBDECOY_API_KEY` by itself: pass it as `apiKey`. Without one, the middleware runs local rules only and nothing reports to your dashboard.

It starts in **monitor** mode: detections are recorded and every request is still served. Watch what it would have blocked, then set `mode: 'enforce'`.

## Local rules (no API key needed)

With no `rules` option the middleware arms `tripwire()` with its built-in scanner-bait paths (`/.env`, `/wp-config.php` and similar). Add your own rules from `@webdecoy/node`:

```typescript
import express from 'express';
import { webdecoy } from '@webdecoy/express';
import { tripwire, rateLimit } from '@webdecoy/node';

const app = express();

app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY, // optional
    rules: [
      tripwire({ paths: ['/admin-backup.zip'] }),
      rateLimit({ max: 100, window: 60 }),
    ],
    skipPaths: ['/health'],
  })
);

app.get('/', (req, res) => {
  // The full typed decision, set in monitor mode too.
  const decision = req.webdecoyDecision;
  if (decision?.deniedBy('tripwire')) console.log('tripwire hit', decision.id);
  res.send('ok');
});
```

`req.webdecoyDecision` has `conclusion` (`'ALLOW'`, `'DENY'`, `'CHALLENGE'` or `'ERROR'`), `allowed`, `results` (every rule and what it concluded) and `deniedBy(rule)`. In monitor mode it is the only place a verdict surfaces. See the [@webdecoy/node README](https://www.npmjs.com/package/@webdecoy/node) for every rule.

## Middleware Options

```typescript
interface WebDecoyMiddlewareOptions {
  // Web Decoy API key. Without it, nothing reports (local rules only).
  apiKey?: string;

  // 'monitor' (default) records and serves; 'enforce' blocks.
  mode?: 'monitor' | 'enforce';

  // Threat score above which a request counts as blocked (default: 80)
  threatScoreThreshold?: number;
  // Per-request override of the same threshold
  threshold?: number;

  // Inject a hidden honeytoken link into HTML responses (default: on with an apiKey)
  honeytoken?: boolean;

  // Local rules from @webdecoy/node, evaluated first.
  // Default: [tripwire()]. Pass [] to opt out.
  rules?: Rule[];

  // How much of X-Forwarded-For to trust: hop count, 'cloudflare', or proxy CIDRs.
  // Unset, Express decides via req.ip and your app's `trust proxy` setting.
  trustProxy?: TrustedProxies;

  // Custom IP extraction. Overrides trustProxy.
  getIP?: (req: Request) => string;

  // Paths to skip protection
  skipPaths?: string[] | RegExp[];

  // Enforce mode: called when the server-side score blocks a request.
  // Call next() to serve it anyway. Rule refusals (tripwire, rateLimit, ...)
  // answer directly: 403 with the rule name, or 429 with Retry-After.
  onBlocked?: (req, res, detection, next, decision) => void;

  // Custom error handler (default: log and allow, fail open)
  onError?: (req: Request, res: Response, error: Error) => void;

  // Capture TLS details from the socket (needs a proxy that exposes them)
  extractTLS?: boolean;

  // API endpoint (default: 'https://in.webdecoy.com')
  apiUrl?: string;

  // Request timeout in milliseconds (default: 5000)
  timeout?: number;

  // Enable debug logging (default: false)
  debug?: boolean;
}
```

## Client IP

By default the middleware uses `req.ip`, which honours your app's `trust proxy` setting. It does not read the leftmost `X-Forwarded-For` value, because the client writes that one itself. Behind a proxy, set `trust proxy` in Express or pass `trustProxy`:

```typescript
app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY,
    trustProxy: 'cloudflare',
  })
);
```

On Railway, use `trustProxy: 'railway'` (or `app.set('trust proxy', 2)`). Railway's edge writes `X-Forwarded-For: <client>, <edge>`, so trusting one hop records Railway's edge as every visitor.

## Custom Block Handler

```typescript
app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY,
    mode: 'enforce',
    onBlocked: (req, res, detection, next) => {
      res.status(403).render('blocked', {
        detectionId: detection.detection_id,
        threatLevel: detection.threat_level,
      });
    },
  })
);
```

## Skip Specific Paths

```typescript
app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY,
    skipPaths: [
      '/health',
      '/metrics',
      /^\/static\/.*/, // Regex pattern
    ],
  })
);
```

## Access Detection Info

The middleware adds detection info to `req.webdecoy`, and the full typed decision to `req.webdecoyDecision`:

```typescript
app.get('/api/data', (req, res) => {
  if (req.webdecoy?.bot_detected) {
    // Extra logging for bot requests
    logger.warn('Bot detected', {
      ip: req.ip,
      detectionId: req.webdecoy.detection_id,
      botType: req.webdecoy.bot_type,
    });
  }

  res.json({ data: 'response' });
});
```

### Detection Info Properties

```typescript
interface WebDecoyDetection {
  decision: 'allow' | 'block' | 'challenge';
  confidence: number; // 0-100 threat score
  threat_level: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  bot_detected: boolean;
  bot_type?: string; // e.g., "curl", "selenium"
  detection_id: string;
  rule_enforced: boolean;
}
```

## TypeScript Support

The package includes TypeScript definitions and augments the Express Request type:

```typescript
import { Request } from 'express';

app.get('/api/data', (req: Request, res) => {
  // req.webdecoy is typed
  const botDetected = req.webdecoy?.bot_detected;
});
```

## Verify the install

With an `apiKey` configured, send one request with the reserved test User-Agent:

```bash
curl -A "WebDecoy-Test/1.0" http://localhost:3000/
```

A detection labeled **Test** appears on the **Detections** page within a few seconds. See [Verify your install](https://docs.webdecoy.com/getting-started/verify-installation/).

## Core SDK

This package uses [@webdecoy/node](https://www.npmjs.com/package/@webdecoy/node) under the hood. For non-Express applications or custom integrations, use the core SDK directly.

## Getting an API Key

1. Sign up at [app.webdecoy.com](https://app.webdecoy.com)
2. Add your site
3. Create an API key on the **API Keys** page

API keys start with `sk_live_` for production or `sk_test_` for testing.

## Documentation

Full documentation: [docs.webdecoy.com/sdk-plugins/express](https://docs.webdecoy.com/sdk-plugins/express/). Install snippets for every stack: [docs.webdecoy.com/installation/install-with-ai](https://docs.webdecoy.com/installation/install-with-ai/).

## License

MIT
