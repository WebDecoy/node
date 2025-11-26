# @webdecoy/express

Web Decoy middleware for Express.js applications.

## Installation

```bash
npm install @webdecoy/express
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
  // Web Decoy SDK config
  apiKey: string;
  apiUrl?: string;
  threatScoreThreshold?: number;

  // Middleware-specific options
  skipPaths?: string[] | RegExp[];
  getIP?: (req: Request) => string;
  onBlocked?: (req: Request, res: Response, detection: any) => void;
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
      /^\/static\/.*/,  // Regex pattern
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

## Documentation

See the [main README](../../README.md) for full documentation.

## License

MIT
