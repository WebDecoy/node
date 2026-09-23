# @webdecoy/express

Web Decoy middleware for Express.js applications - Advanced bot detection with TLS fingerprinting.

[![npm version](https://img.shields.io/npm/v/@webdecoy/express.svg)](https://www.npmjs.com/package/@webdecoy/express)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @webdecoy/express
# or
yarn add @webdecoy/express
```

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
  // Access detection info
  console.log('Bot detected:', req.webdecoy?.bot_detected);
  res.json({ data: 'protected' });
});

app.listen(3000);
```

The SDK does not read `WEBDECOY_API_KEY` by itself: pass it as `apiKey`. Without one, the middleware runs local rules only and nothing reports to your dashboard.

It starts in **monitor** mode: detections are recorded and every request is still served. Watch what it would have blocked, then set `mode: 'enforce'`.

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

  // Local rules such as tripwire() and rate limits, evaluated first
  rules?: Rule[];

  // How much of X-Forwarded-For to trust: hop count, 'cloudflare', or proxy CIDRs.
  // Unset, Express decides via req.ip and your app's `trust proxy` setting.
  trustProxy?: TrustedProxies;

  // Custom IP extraction. Overrides trustProxy.
  getIP?: (req: Request) => string;

  // Paths to skip protection
  skipPaths?: string[] | RegExp[];

  // Called when a request would be blocked. Call next() to serve it anyway.
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

The middleware adds detection info to `req.webdecoy`:

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

## Core SDK

This package uses [@webdecoy/node](https://www.npmjs.com/package/@webdecoy/node) under the hood. For non-Express applications or custom integrations, use the core SDK directly.

## Getting an API Key

1. Sign up at [app.webdecoy.com](https://app.webdecoy.com)
2. Add your site
3. Create an API key on the **API Keys** page

API keys start with `sk_live_` for production or `sk_test_` for testing.

## Documentation

Full documentation: [docs.webdecoy.com/sdk-plugins/express](https://docs.webdecoy.com/sdk-plugins/express/).

## License

MIT
