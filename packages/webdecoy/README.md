# @webdecoy/node

Core Web Decoy SDK for Node.js applications - Advanced bot detection with TLS fingerprinting.

[![npm version](https://img.shields.io/npm/v/@webdecoy/node.svg)](https://www.npmjs.com/package/@webdecoy/node)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @webdecoy/node
# or
yarn add @webdecoy/node
```

## Quick Start

```typescript
import { WebDecoy } from '@webdecoy/node';

const webdecoy = new WebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY,
});

const result = await webdecoy.protect({
  method: 'GET',
  path: '/api/data',
  ip: '203.0.113.42',
  user_agent: req.headers['user-agent'],
  headers: req.headers,
  timestamp: Date.now(),
});

if (!result.allowed) {
  // Block the request
  return res.status(403).json({ error: 'Access denied' });
}
```

## Configuration Options

```typescript
const webdecoy = new WebDecoy({
  // Required: Your API key from the dashboard
  apiKey: 'sk_live_xxxxx',

  // Optional: API endpoint (defaults to production)
  apiUrl: 'https://ingest.webdecoy.com',

  // Optional: Enable TLS fingerprinting (default: true)
  enableTLSFingerprinting: true,

  // Optional: Threat score threshold for blocking (default: 80)
  threatScoreThreshold: 70,

  // Optional: Request timeout in milliseconds (default: 5000)
  timeout: 5000,

  // Optional: Enable debug logging (default: false)
  debug: false,

  // Optional: Reject unauthorized TLS certificates (default: true)
  tlsRejectUnauthorized: true,
});
```

## API Reference

### `WebDecoy`

Main SDK class for bot detection.

#### `protect(metadata: RequestMetadata, options?: ProtectOptions): Promise<ProtectResult>`

Analyze and protect a request.

```typescript
const result = await webdecoy.protect({
  method: 'GET',
  path: '/api/data',
  ip: '203.0.113.42',
  user_agent: 'Mozilla/5.0...',
  headers: { /* request headers */ },
  timestamp: Date.now(),
});
```

**Returns:**
```typescript
interface ProtectResult {
  allowed: boolean;
  detection: {
    decision: 'allow' | 'block' | 'challenge';
    confidence: number; // 0-100 threat score
    threat_level: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    bot_detected: boolean;
    bot_type?: string;
    detection_id: string;
    rule_enforced: boolean;
  };
  error?: string;
}
```

#### `validateConfig(): Promise<{ valid: boolean; error?: string }>`

Validate your API key and configuration.

#### `getConfig(): Readonly<Required<WebDecoyConfig>>`

Get the current configuration.

## Types

All TypeScript types are exported:

```typescript
import type {
  WebDecoyConfig,
  RequestMetadata,
  SDKDetectionResponse,
  ProtectResult,
  ProtectOptions,
  TLSInfo,
  LocalAnalysis,
  SDKDetectionRequest,
} from '@webdecoy/node';
```

## Self-Hosted Captcha & Detection Engine

In addition to the API-backed `protect()` flow above, the SDK ships a fully
**in-process** bot-detection engine and captcha — no remote call required. It
scores ~40 behavioral, environmental, and fingerprint signals collected by the
[`@webdecoy/client`](https://www.npmjs.com/package/@webdecoy/client) browser
widget, verifies a SHA-256 proof-of-work, and issues a signed session token.

```
Browser (@webdecoy/client)            Your server (@webdecoy/node)
  collect signals + solve PoW  ──▶  Captcha.verify()
                                      ├─ verify proof-of-work
                                      ├─ score signals (in-process engine)
                                      └─ issue session token on success
```

### Mounting the endpoints

Use your framework adapter (or `createCaptchaEndpoints` directly). The handler
serves `GET /__webdecoy/challenge`, `POST /__webdecoy/verify`, `POST
/__webdecoy/score`, and `POST /__webdecoy/token/verify`.

```typescript
import express from 'express';
import { webdecoyCaptcha } from '@webdecoy/express';

const app = express();
app.use(express.json());

app.use(
  webdecoyCaptcha({
    secret: process.env.WEBDECOY_SECRET, // required in production
  }),
);
```

Then verify the token your form receives on a protected route:

```typescript
import { Captcha } from '@webdecoy/node';

const captcha = new Captcha({ secret: process.env.WEBDECOY_SECRET });

app.post('/login', (req, res) => {
  const result = captcha.verifyToken(req.body.webdecoy_token, req.ip);
  if (!result.valid) return res.status(403).json({ error: 'captcha failed' });
  // ...proceed
});
```

### Using the engine directly

For full control, score raw signals yourself:

```typescript
import { DetectionEngine } from '@webdecoy/node';

const engine = new DetectionEngine({ requirePoW: false });
const verdict = engine.score(signals, {
  ip,
  siteKey: 'site',
  userAgent,
  headers,
});
// verdict: { success, score, recommendation: 'allow'|'challenge'|'block', categoryScores, detections }
```

> **Note on the scoring model:** the verdict is a confidence-weighted blend
> across categories, so no single signal can cross the block threshold alone —
> a missing proof-of-work on an otherwise-clean request yields `challenge`, not
> `block`. Tune category weights via the `weights` option.

### Security & deployment notes

- **`secret`** signs challenges and tokens. It is **required in production**
  (`NODE_ENV=production`); a missing or default secret throws. Generate one with
  `openssl rand -hex 32`.
- Challenge/token/fingerprint stores are **in-memory** by default. For
  serverless or multi-instance deployments, supply a shared store via the
  `challengeStore` / `tokenStore` options (the `ChallengeStore` / `TokenStore`
  interfaces are the seam for Redis).
- IP reputation (VPN/proxy/Tor, abuse score, geo) is still served by
  `api.webdecoy.com` via the SDK's IP-enrichment client.

## Framework Integrations

For Express.js, use the dedicated middleware package:

```bash
npm install @webdecoy/express
```

See [@webdecoy/express](https://www.npmjs.com/package/@webdecoy/express) for details.

## Getting an API Key

1. Sign up at [app.webdecoy.com](https://app.webdecoy.com)
2. Create a new organization and property
3. Generate an API key in Settings

API keys start with `sk_live_` for production or `sk_test_` for testing.

## Documentation

For full documentation, visit the [GitHub repository](https://github.com/WebDecoy/node-sdk).

## License

MIT
