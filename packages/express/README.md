# @webdecoy/express

Web Decoy middleware for Express.js applications - Advanced bot detection with TLS fingerprinting.

[![npm version](https://badge.fury.io/js/%40webdecoy%2Fexpress.svg)](https://www.npmjs.com/package/@webdecoy/express)
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
    threatScoreThreshold: 70,
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

## Middleware Options

```typescript
interface WebDecoyMiddlewareOptions {
  // Required: Web Decoy API key
  apiKey: string;

  // Optional: API endpoint (default: 'https://api.webdecoy.com')
  apiUrl?: string;

  // Optional: Threat score threshold for blocking (default: 80)
  threatScoreThreshold?: number;

  // Optional: Request timeout in milliseconds (default: 5000)
  timeout?: number;

  // Optional: Enable debug logging (default: false)
  debug?: boolean;

  // Optional: Paths to skip protection
  skipPaths?: string[] | RegExp[];

  // Optional: Custom IP extraction function
  getIP?: (req: Request) => string;

  // Optional: Custom blocked request handler
  onBlocked?: (req: Request, res: Response, detection: any) => void;

  // Optional: Custom error handler
  onError?: (req: Request, res: Response, error: Error) => void;
}
```

## Custom IP Extraction

By default, the middleware checks `X-Forwarded-For`, `X-Real-IP`, and `req.ip`. You can customize this:

```typescript
app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY,
    getIP: (req) => req.headers['cf-connecting-ip'] as string, // Cloudflare
  })
);
```

## Custom Block Handler

```typescript
app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY,
    onBlocked: (req, res, detection) => {
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
2. Create a new organization and property
3. Generate an API key in Settings

API keys start with `sk_live_` for production or `sk_test_` for testing.

## Documentation

For full documentation, visit the [GitHub repository](https://github.com/webdecoy/webdecoy-node).

## License

MIT
