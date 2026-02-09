# @webdecoy/node

Core Web Decoy SDK for Node.js applications - Advanced bot detection with TLS fingerprinting.

[![npm version](https://badge.fury.io/js/%40webdecoy%2Fnode.svg)](https://www.npmjs.com/package/@webdecoy/node)
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
  apiUrl: 'https://api.webdecoy.com',

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

For full documentation, visit the [GitHub repository](https://github.com/webdecoy/webdecoy-node).

## License

MIT
