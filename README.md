# Stealth-scraper tripwires for Node.js

**Catch scrapers with honeypot paths, not fingerprinting.** Deterministic, zero-false-positive bot detection for Express, Fastify, and Next.js — **no account, no API key, three lines of code.**

Fingerprint- and challenge-based detection loses to purpose-built stealth scrapers ([botasaurus](https://github.com/omkarcloud/botasaurus), undetected-chromedriver, SeleniumBase-UC) that present a genuine browser fingerprint. Tripwires win a different fight: a hidden honeypot path a real user can never reach, so **any request for it is automated by construction** — it detects *intent*, which a better fingerprint can't spoof away.

[![npm version](https://img.shields.io/npm/v/@webdecoy/node.svg)](https://www.npmjs.com/package/@webdecoy/node)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

<!-- TODO: add a short terminal GIF here — a scraper follows the hidden link and gets 403'd.
![A scraper hits a tripwire and gets blocked](docs/tripwire-demo.gif) -->

## Quick start — no API key

```bash
npm install @webdecoy/node
```

```typescript
import { WebDecoy, tripwire, honeytoken } from '@webdecoy/node';

// A hidden decoy link + the secret path it points at.
const trap = honeytoken();

const wd = new WebDecoy({
  rules: [
    // Block any request to the honeytoken path, plus built-in scanner-bait
    // paths (/.env, /.git/config, /wp-config.php, …). Runs locally — no key.
    tripwire({ paths: [trap.path] }),
  ],
});

// Inject the invisible, rel=nofollow decoy link into your HTML. Real users
// never see or follow it; a link-following scraper requests it and is blocked.
html = html.replace('</body>', `${trap.linkHtml}</body>`);
```

That's the whole thing. Runs entirely on your server, in memory, with no account and no outbound calls. With the [framework middleware](#framework-integration-still-no-api-key), a tripwire hit becomes a `403` automatically.

Register your own paths, prefixes, or patterns too:

```typescript
tripwire({
  paths: ['/admin-backup.zip'],
  prefixes: ['/.git/'],
  patterns: [/\/wp-admin\//],
  includeDefaults: true, // built-in scanner-bait paths (default: true)
  action: 'DENY',        // or 'THROTTLE'
  dryRun: false,         // log only, don't block (observe before enforcing)
});
```

## Why tripwires beat fingerprinting

Modern scraping frameworks are built specifically to defeat fingerprint- and challenge-based bot management. They run a real Chrome, strip `navigator.webdriver`, spoof canvas/WebGL/audio, and solve CAPTCHAs. Independent data: residential-proxy scrapers bypass major CDNs 80–99% of the time. Fingerprinting is an arms race you re-run every release.

A tripwire sidesteps the arms race. It doesn't ask *"does this look like a bot?"* — it exploits the one thing automation does that humans don't: **following links and hitting paths a person can never see.**

- **Deterministic.** A hit isn't a probability; it's a request for a path that only exists to trap automation.
- **Zero-false-positive by design.** The decoy link is invisible and `rel=nofollow`; the default bait paths (`/.env`, `/.git/config`, `/wp-config.php`, …) are never requested by real traffic. (See [false positives](#what-counts-as-a-false-positive) for the honest edge cases.)
- **Unspoofable.** It catches *intent*, not a fingerprint — so a stealthier browser doesn't help the scraper.
- **Instant.** Evaluated locally before any scoring, model, or network call.

## Framework integration (still no API key)

Tripwires (and the other [local rules](#more-local-rules)) are enforced automatically by the middleware — a hit returns `403`, no extra code.

### Express

```bash
npm install @webdecoy/express
```

```typescript
import express from 'express';
import { webdecoy } from '@webdecoy/express';
import { tripwire, rateLimit } from '@webdecoy/node';

const app = express();

app.use(
  webdecoy({
    // No apiKey → purely local rules (tripwires + rate limiting).
    rules: [
      tripwire({ paths: ['/.env', '/wp-config.php'] }),
      rateLimit({ max: 100, window: 60 }),
    ],
    skipPaths: ['/health', '/public'],
  })
);
```

Fastify (`@webdecoy/fastify`) and Next.js (`@webdecoy/nextjs`) expose the same rule-based middleware.

## More local rules

Rules run locally (no API key) before any server verification; the first `DENY`/`THROTTLE` wins and short-circuits the request.

```typescript
import { WebDecoy, rateLimit, tripwire, filter } from '@webdecoy/node';

const wd = new WebDecoy({
  rules: [
    rateLimit({ max: 100, window: 60 }),                        // 100 req / 60s per IP
    tripwire({ paths: ['/.env', '/wp-config.php'] }),           // honeypot paths
    filter({ expression: 'ip.tor or ip.vpn', action: 'DENY' }), // needs an API key (IP enrichment)
  ],
});
```

- **`rateLimit({ max, window, algorithm?, action?, keyBy? })`** — fixed or sliding window, keyed by IP (or a custom function). No key.
- **`tripwire({ paths?, prefixes?, patterns?, includeDefaults? })`** — deterministic honeypot-path detection. No key.
- **`filter({ expression, action? })`** — an expression language over IP reputation/geo (e.g. `ip.tor`, `ip.country in ["CN", "RU"]`). Requires an API key for enrichment.

## What counts as a false positive?

The zero-false-positive claim is about *design*, and it holds if you know the edge cases:

- **The honeytoken link** is rendered hidden and `rel=nofollow`, and isn't in your sitemap or nav — so real users and well-behaved crawlers (Googlebot respects `nofollow`) never follow it. A scraper that ignores `nofollow` and follows every link does.
- **Aggressive link-prefetchers and unfurl/preview bots** (e.g. some browsers' speculative prefetch, chat link previews) *can* fetch a hidden link. If you serve link previews or use prefetching, start with `dryRun: true` to measure before enforcing, or scope the trap to paths those bots won't touch.
- **The default scanner-bait paths** (`/.env`, `/.git/config`, …) are never hit by legitimate traffic — but *your own* security scanners or uptime checks might. Exclude them or run `dryRun` first.

The honest rule of thumb: enforce tripwires you control the surface of, and use `dryRun` to observe any path you're unsure about.

## Optional: the WebDecoy platform (API key)

Everything above runs locally and free, forever. Add an API key to turn on the hosted platform when you want deeper detection and visibility:

- **`protect()`** — full server-side analysis (a threat score + allow/block/challenge decision), not just local rules.
- **TLS fingerprinting** — JA3/JA4 hashing and matching against known automation (curl, wget, Selenium, …) and spoofed-browser (TLS↔UA mismatch) detection.
- **IP enrichment** — reputation, geo, and Tor/VPN/proxy/hosting detection that powers `filter()` expressions.
- **Dashboard & analytics** — every tripwire hit and violation, tracked over time.

```typescript
import { WebDecoy } from '@webdecoy/node';

const wd = new WebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY, // from app.webdecoy.com
});

const result = await wd.protect({
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

### Getting an API key

1. Sign up at [app.webdecoy.com](https://app.webdecoy.com)
2. Create an organization and a property for your app
3. Generate an API key in Settings (`sk_live_` for production, `sk_test_` for testing)

## How it works

| Tier | What | Needs a key? |
|------|------|:---:|
| **0 — Tripwires** | Requests for hidden honeypot paths are blocked immediately, before any scoring. Deterministic, zero-FP. | No |
| **1 — Local analysis** | Fast on-server heuristics: suspicious/missing headers, datacenter IPs, known bot user-agents, missing `Sec-CH-UA`. | No |
| **2 — Server verification** | JA3/JA4 TLS fingerprinting, known-bot database, TLS↔UA mismatch, IP reputation, GeoIP (Tor/VPN/proxy). | Yes |

## Packages

| Package | Version | Description |
|---------|---------|-------------|
| [@webdecoy/node](https://www.npmjs.com/package/@webdecoy/node) | [![npm](https://img.shields.io/npm/v/@webdecoy/node.svg)](https://www.npmjs.com/package/@webdecoy/node) | Core SDK + local rules (tripwire, rateLimit, filter) |
| [@webdecoy/express](https://www.npmjs.com/package/@webdecoy/express) | [![npm](https://img.shields.io/npm/v/@webdecoy/express.svg)](https://www.npmjs.com/package/@webdecoy/express) | Express.js middleware |
| [@webdecoy/fastify](https://www.npmjs.com/package/@webdecoy/fastify) | [![npm](https://img.shields.io/npm/v/@webdecoy/fastify.svg)](https://www.npmjs.com/package/@webdecoy/fastify) | Fastify plugin |
| [@webdecoy/nextjs](https://www.npmjs.com/package/@webdecoy/nextjs) | [![npm](https://img.shields.io/npm/v/@webdecoy/nextjs.svg)](https://www.npmjs.com/package/@webdecoy/nextjs) | Next.js middleware |
| [@webdecoy/client](https://www.npmjs.com/package/@webdecoy/client) | [![npm](https://img.shields.io/npm/v/@webdecoy/client.svg)](https://www.npmjs.com/package/@webdecoy/client) | Browser-side signal collector |

## Configuration (platform options)

```typescript
const wd = new WebDecoy({
  apiKey: 'sk_live_xxxxx',                 // optional — only for platform features
  apiUrl: 'https://ingest.webdecoy.com',   // optional (defaults to production)
  enableTLSFingerprinting: true,           // optional (default: true)
  threatScoreThreshold: 70,                // optional, 0–100 (default: 80)
  timeout: 5000,                           // optional, ms (default: 5000)
  debug: false,                            // optional (default: false)
  tlsRejectUnauthorized: true,             // optional (default: true)
});
```

## API reference

### `tripwire(config?)` / `honeytoken(options?)`

Deterministic honeypot-path detection. `tripwire()` returns a `Rule` for the `rules` array; `honeytoken()` returns `{ path, linkHtml }` — a hidden decoy link and the tripwire path it points at.

### `rateLimit(config)` / `filter(config)`

Additional local rules for the `rules` array. `filter()` requires an API key for IP enrichment.

### `protect(metadata, options?): Promise<ProtectResult>`

Full analysis of a request (platform feature). Returns a decision:

```typescript
interface ProtectResult {
  allowed: boolean;
  detection: {
    decision: 'allow' | 'block' | 'challenge';
    confidence: number;      // 0–100 threat score
    threat_level: 'MINIMAL' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
    bot_detected: boolean;
    bot_type?: string;       // e.g. "curl", "selenium"
    detection_id: string;
    rule_enforced: boolean;
  };
  error?: string;
}
```

All TypeScript types are exported (`WebDecoyConfig`, `RequestMetadata`, `ProtectResult`, `Rule`, `TripwireConfig`, `RateLimitConfig`, `FilterConfig`, `Honeytoken`, …).

## Examples

See [examples](./examples) for complete working setups — e.g. [express-basic](./examples/express-basic).

## FAQ

**Will this slow down my app?** Local rules (tripwires, rate limiting) add <1ms and make no network calls. Server verification (with a key) typically takes 50–200ms and runs asynchronously for low-risk requests.

**What if the WebDecoy service is down?** Local rules are unaffected (they never call out). Platform `protect()` fails open by default, so requests continue.

**Behind a CDN or load balancer?** Yes — the middleware handles `X-Forwarded-For` and similar. Configure your proxy's trusted-IP settings correctly.

## Support

- **Website**: [webdecoy.com](https://webdecoy.com)
- **Dashboard**: [app.webdecoy.com](https://app.webdecoy.com)
- **Issues**: [github.com/WebDecoy/node-sdk/issues](https://github.com/WebDecoy/node-sdk/issues)
- **Email**: support@webdecoy.com

## Contributing

Contributions welcome — please read the [Contributing Guide](./CONTRIBUTING.md) first.

## License

MIT — see [LICENSE](./LICENSE).
