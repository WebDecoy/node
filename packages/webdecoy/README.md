# @webdecoy/node

Core Web Decoy SDK for Node.js applications.

## Installation

```bash
npm install @webdecoy/node
```

## Usage

```typescript
import { WebDecoy } from '@webdecoy/node';

const webdecoy = new WebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY,
});

const result = await webdecoy.protect({
  method: 'GET',
  path: '/api/data',
  ip: '203.0.113.42',
  user_agent: 'Mozilla/5.0...',
  headers: { /* request headers */ },
  timestamp: Date.now(),
});

if (!result.allowed) {
  // Block the request
  throw new Error('Access denied');
}
```

## Documentation

See the [main README](../../README.md) for full documentation.

## License

MIT
