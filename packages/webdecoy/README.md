# @webdecoy/node

The core WebDecoy SDK for Node.js and edge runtimes: tripwires, rate limits and other local rules, plus optional server-side bot detection reported to your WebDecoy dashboard.

[![npm version](https://img.shields.io/npm/v/@webdecoy/node.svg)](https://www.npmjs.com/package/@webdecoy/node)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Full documentation: [docs.webdecoy.com/sdk-plugins/node-sdk](https://docs.webdecoy.com/sdk-plugins/node-sdk/). Copy-paste install snippets for every stack: [docs.webdecoy.com/installation/install-with-ai](https://docs.webdecoy.com/installation/install-with-ai/).

## Using a framework? Install its adapter

Most apps should install a framework adapter alongside this package. The adapters handle request mapping, client IP, monitor mode and honeytoken injection for you. Install `@webdecoy/node` too: it is where `tripwire()`, `rateLimit()` and the other rules are imported from.

| Framework | Install |
|---|---|
| Express | `npm install @webdecoy/express @webdecoy/node` ([README](https://www.npmjs.com/package/@webdecoy/express)) |
| Fastify | `npm install @webdecoy/fastify @webdecoy/node` ([README](https://www.npmjs.com/package/@webdecoy/fastify)) |
| Next.js | `npm install @webdecoy/nextjs @webdecoy/node` ([README](https://www.npmjs.com/package/@webdecoy/nextjs)) |
| Hono (Workers, Bun, Deno, Node) | `npm install @webdecoy/hono @webdecoy/node` ([README](https://www.npmjs.com/package/@webdecoy/hono)) |
| Any other server or fetch runtime | `npm install @webdecoy/node` (this page) |

## Installation

```bash
npm install @webdecoy/node
```

## Quick start

```js
import http from 'node:http';
import { WebDecoy } from '@webdecoy/node';

const wd = new WebDecoy({ apiKey: process.env.WEBDECOY_API_KEY });

http.createServer(async (req, res) => {
  const decision = await wd.protect({
    method: req.method,
    path: new URL(req.url, 'http://localhost').pathname,
    ip: req.socket.remoteAddress ?? '',
    user_agent: req.headers['user-agent'],
    headers: Object.fromEntries(
      Object.entries(req.headers).map(([name, value]) => [name, String(value)])
    ),
    timestamp: Date.now(),
  });

  // protect() returns a decision and blocks nothing itself.
  // Log decision.conclusion ('ALLOW', 'DENY', 'CHALLENGE' or 'ERROR') first;
  // refuse with a 403 when decision.allowed is false only once you are ready.
  res.end('ok');
}).listen(3000);
```

Behind a proxy, `req.socket.remoteAddress` is the proxy. Use `resolveClientIp()` from this package to read the real client address (see [Client IP behind a proxy](#client-ip-behind-a-proxy)).

### The API key is optional

`apiKey` is optional. Without it the SDK runs **local rules only** (tripwires by default, plus any rules you add), makes no network calls, and reports nothing to the dashboard. With it, the SDK also sends suspicious requests for server-side detection and reports rule hits to your dashboard.

`new WebDecoy()` does **not** read `WEBDECOY_API_KEY` from the environment by itself (only the Vercel middleware does). Pass it as `apiKey`, as above.

To get a key: sign up at [app.webdecoy.com](https://app.webdecoy.com), add your site, then create a key on the **API Keys** page. Keys start with `sk_live_` (production) or `sk_test_` (testing); any other prefix throws when the SDK is constructed. Keep the key on the server and out of committed files.

### Monitor first

`protect()` only returns a decision. It never writes a response, so nothing is blocked until your code acts on `decision.allowed`. The framework adapters and `createFetchGuard()` follow the same rule: they start in **monitor mode** (`mode: 'monitor'`), record the decision and serve every request. Set `mode: 'enforce'` only after you have reviewed what would have been blocked.

## The decision

`protect(metadata, options?)` returns a `Decision`:

```ts
const decision = await wd.protect(metadata);

decision.conclusion            // 'ALLOW' | 'DENY' | 'CHALLENGE' | 'ERROR'
decision.allowed               // true for ALLOW and ERROR (fails open), false for DENY and CHALLENGE
decision.id                    // 'dec_...'
decision.isDenied()            // also isAllowed(), isChallenged(), isErrored()
decision.deniedBy('tripwire')  // whether a named rule denied the request
decision.results               // every configured rule, its state and its conclusion
decision.reason                // the deciding reason, when there is one
decision.detection             // { decision, confidence, threat_level, bot_detected, bot_type?, detection_id, rule_enforced }
decision.error                 // set when conclusion is 'ERROR'
decision.edge                  // what a WebDecoy edge validator said about this request, if one fronted it
```

Each entry in `results` has a `state`:

| `state` | Meaning |
|---|---|
| `RUN` | Evaluated, and its conclusion counts. |
| `DRY_RUN` | Evaluated; the conclusion is recorded but not enforced. |
| `NOT_RUN` | Could not evaluate because a signal it needs was absent (for example a `filter()` rule with no IP enrichment). |
| `CACHED` | Not evaluated; a prior decision for this key was reused. |

`ERROR` is not a denial. It means no verdict was reached (for example WebDecoy could not be reached, or the request had no IP), and `allowed` is `true`.

`ProtectResult` is the exported interface type for this decision.

## Local rules

Rules run in-process, in order, before any server call. The first `DENY` or `THROTTLE` decides. When you pass no `rules`, the SDK arms `tripwire()` with its built-in scanner-bait paths; pass `rules: []` to opt out.

```ts
import { WebDecoy, tripwire, rateLimit, filter } from '@webdecoy/node';

const wd = new WebDecoy({
  rules: [
    tripwire({ paths: ['/admin-backup.zip'] }), // plus built-in paths such as /.env
    rateLimit({ max: 100, window: 60 }),        // 100 requests per 60 s per IP
    filter({ expression: 'ip.tor or ip.vpn' }), // needs an apiKey (IP enrichment)
  ],
});
```

| Rule | What it does | Needs an API key? |
|---|---|---|
| `tripwire({ paths?, prefixes?, patterns?, includeDefaults?, action?, dryRun? })` | Matches requests for decoy and scanner-bait paths. | No |
| `honeytoken()` | Returns `{ path, linkHtml }`: a hidden decoy link and the path to arm with `tripwire({ paths: [path] })`. | No |
| `rateLimit({ max, window, algorithm?, keyBy?, store?, action?, dryRun? })` | Fixed or sliding window, keyed by IP by default. In-memory unless you pass a shared `store` (for example `upstashRateLimitStore()`). | No |
| `attackSignatures({ inspect?, exclude?, action?, dryRun? })` | Denies requests carrying unambiguous injection payloads. | No |
| `webBotAuth()` | Verifies Web Bot Auth (RFC 9421) agent signatures and denies impersonators of known agents. | No |
| `botPolicy({ deny, allow })` | One crawler policy that produces both your `robots.txt` and the rule that enforces it. | No |
| `filter({ expression, action?, dryRun? })` | Expressions over IP reputation and geo, such as `ip.tor` or `ip.country in ["CN", "RU"]`. | Yes |

A tripwire match is evidence, not proof of intent: link prefetchers, preview bots and your own security scanners can request a hidden or scanner-bait path. Use `dryRun: true` on a rule to observe it before enforcing.

## Fetch runtimes (Bun, Deno, Workers, Astro, SvelteKit, Remix)

`createFetchGuard()` wraps the SDK for any runtime that hands you a WHATWG `Request`. It is the same implementation `@webdecoy/hono` uses.

```ts
import { createFetchGuard } from '@webdecoy/node';

const guard = createFetchGuard({ apiKey: process.env.WEBDECOY_API_KEY });

export default {
  async fetch(request: Request): Promise<Response> {
    const { response } = await guard.check(request);
    if (response) return response; // only ever set in enforce mode
    return guard.decorate(await handle(request)); // handle() is your app
  },
};
```

Options: everything in [Configuration](#configuration), plus `mode` (default `'monitor'`), `skipPaths`, `trustProxy` (default `1`), `getIP`, `honeytoken` (default on when an `apiKey` is set; injects a hidden trap link into HTML through `decorate()`) and `onBlocked`.

## Vercel middleware: detection and clearance

One Routing Middleware file for Astro, SvelteKit, Nuxt, Remix or a static site on Vercel. It reports bots to WebDecoy and runs the clearance gate on the paths you protect, both configured from the project's environment.

```ts
// middleware.ts (project root)
export { default } from '@webdecoy/node/vercel';

export const config = {
  // Everything but static assets. Keep /.well-known: the challenge uses it.
  matcher: ['/((?!_astro/|_next/static/|favicon.ico|.*\\.(?:css|js|png|jpg|svg|webp|woff2?)$).*)'],
};
```

| Variable | Turns on | Secret? |
|---|---|---|
| `WEBDECOY_API_KEY` | Detection: bots, tripwire hits and agents the bot registry names are reported to your dashboard. From the **API Keys** page. | Yes |
| `WEBDECOY_SITE_KEY`, `WEBDECOY_SCANNER_ID` | The clearance gate, with the sensor key. From **Enforcement, Setup**. | No |
| `WEBDECOY_SENSOR_KEY` | The clearance gate. From **Enforcement, Setup**. | Yes |

Either half works without the other; with neither, every request passes. Detection starts in monitor mode (the request is served and the verdict rides on the request as `x-webdecoy-decision`, `x-webdecoy-detection-id` and `x-webdecoy-would-block`), and the gate follows the site's mode in WebDecoy, monitor until you switch it. Every failure, WebDecoy unreachable included, lets the request through. Without `WEBDECOY_API_KEY` the middleware is the clearance gate alone, exactly as before.

To customize it, use `createVercelMiddleware(options)` from `@webdecoy/node/vercel`: it takes the core [Configuration](#configuration) options (`rules`, `threatScoreThreshold`, ...), `mode`, `skipPaths`, `trustProxy` and the gate's `siteKey`, `scannerId`, `sensorKey` and `ingest`, each defaulting to the environment. `clearanceMiddleware()` is the gate alone. Next.js sites use `@webdecoy/nextjs/vercel`, the same middleware in Next's types. Guide: [Vercel middleware](https://docs.webdecoy.com/installation/vercel-middleware/).

Verify it with the reserved test User-Agent; a detection labeled **Test** appears within a few seconds:

```bash
curl -A "WebDecoy-Test/1.0" https://your-site.vercel.app/
```

## Environment variables

The SDK reads only these, and only in the features named:

| Variable | Read by |
|---|---|
| `WEBDECOY_API_KEY` | The Vercel middleware (`@webdecoy/node/vercel`, `createDetectAndGate()`), when `apiKey` is not passed. |
| `WEBDECOY_SITE_KEY`, `WEBDECOY_SCANNER_ID`, `WEBDECOY_SENSOR_KEY` | The clearance gate (`@webdecoy/node/vercel`, `createClearanceGate()`), when the matching option is not passed. |
| `WEBDECOY_INGEST` | The clearance gate, to override its ingest endpoint. Optional. |
| `NODE_ENV` | The self-hosted captcha: with `production`, a missing or default `secret` throws. |

Everywhere else `WEBDECOY_API_KEY` is a naming convention used in these docs: pass its value as `apiKey`.

## Configuration

```ts
const wd = new WebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY, // optional; without it, local rules only
  rules: [tripwire()],                  // optional; default [tripwire()], [] to opt out
  apiUrl: 'https://in.webdecoy.com',    // optional (default shown)
  threatScoreThreshold: 80,             // optional, 0-100 (default 80)
  timeout: 5000,                        // optional, ms (default 5000)
  enableTLSFingerprinting: true,        // optional (default true)
  tlsRejectUnauthorized: true,          // optional (default true)
  countAIReferrals: true,               // optional (default true; aggregate counts, only with an apiKey)
  debug: false,                         // optional (default false)
});
```

Also accepted: `characteristics` (what identifies the same caller for rate limits and caching; default the client IP), `decisionCache`, `webBotAuth`, `logger` (any object with `debug`/`info`/`warn`/`error`; `fromPino()` adapts pino) and `tracer` (an OpenTelemetry tracer).

`protect()` also takes per-request options: `threshold`, `skipLocalAnalysis` and `metadata`.

Without an API key no request leaves your server. With one, a request goes to WebDecoy only when local analysis flags it as needing verification (or carries TLS details); that call is awaited, bounded by `timeout`, and fails open on error.

## Client IP behind a proxy

Rate limits and detections are keyed on the client address. `X-Forwarded-For` is partly written by the client, so read it only as far as your own infrastructure wrote it:

```ts
import { resolveClientIp } from '@webdecoy/node';

const ip = resolveClientIp({
  headers: req.headers,
  peer: req.socket.remoteAddress,
  trustProxy: 1, // proxies in front of this app; or 'cloudflare', 'railway', or your proxies' CIDRs
});
```

`trustProxy` defaults to `false` here (believe no forwarding header). The adapters accept the same option.

## Self-hosted captcha and detection engine

The SDK also ships an in-process captcha: it scores behavioral, environmental and fingerprint signals collected by [`@webdecoy/client`](https://www.npmjs.com/package/@webdecoy/client), verifies a SHA-256 proof of work, and issues a signed session token. No remote call is needed.

Mount the endpoints with your adapter (`webdecoyCaptcha` in Express, `webdecoyCaptchaPlugin` in Fastify, `createCaptchaHandler` in Next.js) or with `createCaptchaEndpoints()`. They serve `GET /__webdecoy/challenge`, `POST /__webdecoy/verify`, `POST /__webdecoy/score` and `POST /__webdecoy/token/verify`.

```ts
import express from 'express';
import { webdecoyCaptcha } from '@webdecoy/express';
import { Captcha } from '@webdecoy/node';

const app = express();
app.use(express.json());
app.use(webdecoyCaptcha({ secret: process.env.WEBDECOY_SECRET })); // required in production

const captcha = new Captcha({ secret: process.env.WEBDECOY_SECRET });

app.post('/login', async (req, res) => {
  const result = await captcha.verifyToken(req.body.webdecoy_token, req.ip);
  if (!result.valid) return res.status(403).json({ error: 'captcha failed' });
  // ...proceed
});
```

`WEBDECOY_SECRET` is just the variable name used here; pass the value as `secret`. Generate one with `openssl rand -hex 32`. Challenge and token stores are in memory by default; for serverless or multi-instance deployments, pass shared `challengeStore` and `tokenStore` implementations.

To score signals yourself, use `new DetectionEngine(options).score(signals, context)`.

## Testing your rules

```ts
import { createTestHarness, get, expectDenied, expectAllowed } from '@webdecoy/node/testing';
import { tripwire } from '@webdecoy/node';

const wd = createTestHarness({ rules: [tripwire()] });

test('a scanner is denied and a visitor is not', async () => {
  expectDenied(await wd.protect(get('/.env')), { rule: 'tripwire' });
  expectAllowed(await wd.protect(get('/')));
});
```

The harness is offline by default: it drops any `apiKey` unless you pass `allowNetwork: true`.

## Verify the install

With an `apiKey` configured, send one request with the reserved test User-Agent:

```bash
curl -A "WebDecoy-Test/1.0" http://localhost:3000/
```

A detection labeled **Test** appears on the **Detections** page within a few seconds. Without an `apiKey` nothing is reported; the decision's `error` says so. See [Verify your install](https://docs.webdecoy.com/getting-started/verify-installation/).

## License

MIT
