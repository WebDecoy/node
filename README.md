# Web Decoy Node.js SDK

Advanced bot detection and protection for Node.js applications with TLS fingerprinting.

[![npm version](https://badge.fury.io/js/%40webdecoy%2Fnode.svg)](https://www.npmjs.com/package/@webdecoy/node)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Features

- **Advanced Bot Detection** - Detect automated tools, scrapers, and malicious bots
- **TLS Fingerprinting** - JA3 and JA4 fingerprint analysis for deeper inspection
- **Two-Tier Analysis** - Fast local checks + comprehensive server-side verification
- **Smart Decision Making** - Allow, block, or challenge based on threat level
- **Framework Integrations** - Ready-to-use middleware for Express.js
- **Real-time Analytics** - Track detections in your Web Decoy dashboard
- **Fail-Safe Design** - Fail open to avoid blocking legitimate users

## Packages

| Package | Version | Description |
|---------|---------|-------------|
| [@webdecoy/node](https://www.npmjs.com/package/@webdecoy/node) | [![npm](https://img.shields.io/npm/v/@webdecoy/node.svg)](https://www.npmjs.com/package/@webdecoy/node) | Core SDK for Node.js |
| [@webdecoy/express](https://www.npmjs.com/package/@webdecoy/express) | [![npm](https://img.shields.io/npm/v/@webdecoy/express.svg)](https://www.npmjs.com/package/@webdecoy/express) | Express.js middleware |

## Quick Start

### Installation

```bash
npm install @webdecoy/node
# or
yarn add @webdecoy/node
```

### Basic Usage

```typescript
import { WebDecoy } from '@webdecoy/node';

const webdecoy = new WebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY, // Get from dashboard
});

// Protect a request
const result = await webdecoy.protect({
  method: 'GET',
  path: '/api/data',
  ip: '203.0.113.42',
  user_agent: req.headers['user-agent'],
  headers: req.headers,
  timestamp: Date.now(),
});

if (!result.allowed) {
  return res.status(403).json({ error: 'Access denied' });
}
```

## Framework Integrations

### Express.js

```bash
npm install @webdecoy/express
```

```typescript
import express from 'express';
import { webdecoy } from '@webdecoy/express';

const app = express();

app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY,
    threatScoreThreshold: 70,
    skipPaths: ['/health', '/public'],
  })
);

app.get('/api/data', (req, res) => {
  // Request is protected automatically
  // Access detection info via req.webdecoy
  res.json({
    data: 'protected',
    bot_detected: req.webdecoy?.bot_detected,
  });
});
```

## Configuration

### SDK Options

```typescript
const webdecoy = new WebDecoy({
  // Required: Your API key from the dashboard
  apiKey: 'sk_live_xxxxx',

  // Optional: API endpoint (defaults to production)
  apiUrl: 'https://api.webdecoy.com',

  // Optional: Enable TLS fingerprinting (default: true)
  enableTLSFingerprinting: true,

  // Optional: Threat score threshold for blocking (default: 80)
  // Scores range from 0-100
  threatScoreThreshold: 70,

  // Optional: Request timeout in milliseconds (default: 5000)
  timeout: 5000,

  // Optional: Enable debug logging (default: false)
  debug: true,

  // Optional: Reject unauthorized TLS certificates (default: true)
  // Set to false for development with self-signed certs
  tlsRejectUnauthorized: true,
});
```

## How It Works

Web Decoy uses a two-tier detection system:

### Tier 1: Local Analysis (Fast)

The SDK performs lightweight checks on your server:

- **Suspicious Headers** - Missing or unusual browser headers
- **Datacenter IPs** - Requests from AWS, GCP, Azure, etc.
- **User-Agent Analysis** - Known bot signatures
- **Missing Security Headers** - Absence of `Sec-CH-UA` and similar

### Tier 2: Server-Side Verification (Deep)

When needed, requests are sent to Web Decoy's servers for:

- **TLS Fingerprinting** - JA3/JA4 hash generation and matching
- **Known Bot Database** - Comparison against fingerprints of curl, wget, Selenium, etc.
- **TLS/User-Agent Mismatch** - Detect spoofed browsers
- **IP Reputation** - Check against threat databases
- **GeoIP Intelligence** - Tor, VPN, proxy, hosting provider detection

## Detection Response

Every protected request returns a decision:

```typescript
interface ProtectResult {
  allowed: boolean; // true = allow, false = block
  detection: {
    decision: 'allow' | 'block' | 'challenge';
    confidence: number; // 0-100 threat score
    threat_level: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    bot_detected: boolean;
    bot_type?: string; // e.g., "curl", "selenium"
    detection_id: string; // Unique ID for tracking
    rule_enforced: boolean; // true if response rule triggered
  };
  error?: string; // Present if an error occurred
}
```

## Examples

See the [examples](./examples) directory for complete working examples:

- **[express-basic](./examples/express-basic)** - Basic Express.js integration

## API Reference

### `WebDecoy`

Main SDK class for bot detection.

#### `constructor(config: WebDecoyConfig)`

Create a new Web Decoy instance.

#### `protect(metadata: RequestMetadata, options?: ProtectOptions): Promise<ProtectResult>`

Analyze and protect a request.

**Parameters:**
- `metadata` - Request information (IP, headers, etc.)
- `options` - Optional settings for this request
  - `threshold` - Custom threat score threshold for this request
  - `skipLocalAnalysis` - Skip local analysis and only use server-side detection
  - `metadata` - Additional metadata to include in the detection

**Returns:** Protection result with decision

#### `validateConfig(): Promise<{ valid: boolean; error?: string }>`

Validate your API key and configuration.

#### `getConfig(): Readonly<Required<WebDecoyConfig>>`

Get the current configuration.

### Types

All TypeScript types are exported for your convenience:

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

## Getting an API Key

1. Sign up at [app.webdecoy.com](https://app.webdecoy.com)
2. Create a new organization
3. Create a property for your application
4. Go to Settings to generate an API key

API keys start with `sk_live_` for production or `sk_test_` for testing.

## Security Best Practices

1. **Never commit API keys** - Use environment variables
2. **Use appropriate thresholds** - Start with 70-80 for most applications
3. **Monitor your dashboard** - Review detections regularly
4. **Skip health checks** - Don't protect monitoring endpoints
5. **Fail open** - The SDK fails open by default to avoid blocking legitimate users on errors

## FAQ

**Q: Will this slow down my application?**
A: Local analysis adds <1ms. Server verification typically takes 50-200ms but runs asynchronously for low-risk requests.

**Q: What happens if the Web Decoy service is down?**
A: The SDK fails open by default, allowing requests to continue. You'll see errors in logs but users won't be affected.

**Q: Can I use this behind a CDN or load balancer?**
A: Yes! The Express middleware automatically handles `X-Forwarded-For` and similar headers. Make sure to configure your proxy correctly.

## Support

- **Website**: [webdecoy.com](https://webdecoy.com)
- **Dashboard**: [app.webdecoy.com](https://app.webdecoy.com)
- **Issues**: [GitHub Issues](https://github.com/webdecoy/webdecoy-node/issues)
- **Email**: support@webdecoy.com

## Contributing

Contributions are welcome! Please read our [Contributing Guide](./CONTRIBUTING.md) first.

## License

MIT License - see [LICENSE](./LICENSE) for details.
