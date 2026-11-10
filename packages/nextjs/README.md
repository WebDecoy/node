# @webdecoy/nextjs

WebDecoy for Next.js: bot-detection middleware with tripwires and rate limits, clearance-token enforcement on Vercel, and helpers for route handlers. Starts in monitor mode.

[![npm version](https://img.shields.io/npm/v/@webdecoy/nextjs.svg)](https://www.npmjs.com/package/@webdecoy/nextjs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @webdecoy/nextjs @webdecoy/node
```

`@webdecoy/node` is the core SDK. Install it directly: rules such as `tripwire()` and `rateLimit()` are imported from it. Requires Next.js 13 or later.

## Quick start: detection middleware

```ts
// middleware.ts (project root, or src/ if you use it)
import { withWebDecoy } from '@webdecoy/nextjs';

export default withWebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY!,
});

// Protect the routes that matter and leave static assets alone.
export const config = {
  matcher: ['/api/:path*', '/checkout/:path*'],
};
```

### API key

`apiKey` is optional. Without it the middleware runs local rules only (the built-in tripwire paths by default) and nothing reports to your dashboard. The middleware does **not** read `WEBDECOY_API_KEY` from the environment by itself: pass it as `apiKey`, as above.

To get a key: sign up at [app.webdecoy.com](https://app.webdecoy.com), add your site, then create a key on the **API Keys** page. Keys start with `sk_live_` or `sk_test_`. Set it in your deployment's environment (for example the Vercel project settings), never in committed code.

### Monitor mode

`withWebDecoy` starts in **monitor mode**: it serves every request and passes the verdict to your app as request headers, which route handlers and server components can read:

| Request header | Value |
|---|---|
| `x-webdecoy-decision` | The detection's `decision` (`allow`, `block` or `challenge`). |
| `x-webdecoy-detection-id` | The detection id. |
| `x-webdecoy-would-block` | `true` when enforce mode would have refused the request. |

Inbound copies of these headers are stripped first, so a client cannot set them. Review what would have been blocked, then set `mode: 'enforce'`. In enforce mode a rule refusal answers `403` (naming the rule), a rate-limit throttle answers `429` with `Retry-After`, and a request blocked by the server-side score goes to `onBlocked` (default `403`).

## Local rules

With no `rules` option the middleware arms `tripwire()` with its built-in scanner-bait paths (`/.env`, `/wp-config.php` and similar). Pass `rules: []` to opt out, or add your own:

```ts
// middleware.ts
import { withWebDecoy } from '@webdecoy/nextjs';
import { tripwire, rateLimit } from '@webdecoy/node';

export default withWebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY,
  rules: [
    tripwire({ paths: ['/admin-backup.zip'] }),
    rateLimit({ max: 100, window: 60 }),
  ],
});
```

`rateLimit()` counts in memory per instance. On Vercel or any multi-instance deployment, pass a shared store such as `upstashRateLimitStore()` from `@webdecoy/node`. See the [@webdecoy/node README](https://www.npmjs.com/package/@webdecoy/node) for every rule.

## Options

`withWebDecoy` accepts every core SDK option (`apiKey`, `rules`, `apiUrl`, `threatScoreThreshold`, `timeout`, `debug`, ...) and the per-request options `threshold`, `skipLocalAnalysis` and `metadata`, plus:

| Option | Default | Description |
|---|---|---|
| `mode` | `'monitor'` | `'monitor'` records and serves every request; `'enforce'` blocks. |
| `skipPaths` | none | Paths to skip, as strings or regular expressions. |
| `trustProxy` | `1` | How much of `X-Forwarded-For` to believe: a hop count, `'cloudflare'`, `'railway'`, or your proxies' CIDRs. `1` is right on Vercel. |
| `getIP` | derived from `trustProxy` | `(req) => string`. Overrides `trustProxy`. |
| `onBlocked` | `403` JSON | `(req, detection, decision) => NextResponse`. Enforce mode, server-score blocks. |
| `onError` | log and continue | `(req, error) => NextResponse \| null`. The middleware fails open. |

Use Next's own `export const config = { matcher }` to choose which routes the middleware runs on.

## Clearance enforcement on Vercel

With a WebDecoy account, the paths you protect in WebDecoy can require a clearance token, checked in middleware before the page renders. A real browser earns one automatically; a client that never runs JavaScript does not get the page. It follows the site's mode in WebDecoy (monitor until you switch it) and fails open.

```ts
// middleware.ts
import { withClearance } from '@webdecoy/nextjs';

export default withClearance();

export const config = {
  // Everything but static assets. Keep /.well-known: the challenge uses it.
  matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
};
```

`withClearance()` reads these environment variables (or the matching options `siteKey`, `scannerId`, `sensorKey`, `ingest`):

| Variable | Where it comes from | Secret? |
|---|---|---|
| `WEBDECOY_SITE_KEY` | **Enforcement, Setup** in the dashboard | No |
| `WEBDECOY_SCANNER_ID` | **Enforcement, Setup** in the dashboard | No |
| `WEBDECOY_SENSOR_KEY` | **Enforcement, Setup** in the dashboard | Yes |
| `WEBDECOY_INGEST` | Optional override of the ingest endpoint | No |

If any of the first three is missing, the gate passes every request and logs a warning once. Guide: [Vercel middleware](https://docs.webdecoy.com/installation/vercel-middleware/).

A project has one `middleware.ts`, so choose `withWebDecoy` or `withClearance` for it.

## Pages Router API routes

`withBotProtection` wraps a Pages Router API handler. Like the middleware it defaults to monitor mode; the handler always runs and receives `req.webdecoy` and `req.webdecoyDecision`.

```ts
// pages/api/protected.ts
import type { NextApiRequest, NextApiResponse } from 'next';
import { withBotProtection } from '@webdecoy/nextjs';

async function handler(req: NextApiRequest, res: NextApiResponse) {
  res.json({ data: 'protected' });
}

export default withBotProtection(handler, {
  apiKey: process.env.WEBDECOY_API_KEY,
  blockThreshold: 80, // default
});
```

It reads the socket address and trusts no forwarding header unless you pass `trustProxy`.

## Other helpers

- `getEdgeVerdict(req)`: what a WebDecoy edge validator (the clearance middleware or the Cloudflare edge sensor) said about a request, readable in a route handler or server component. `present: false` means no validator fronted the request.
- `honeytokenLink(apiKey)`: the site's hidden trap link (`linkProps`, `activePaths`). Render the link in your root layout and arm it with `tripwire({ paths: bait.activePaths })`. The middleware cannot inject it automatically because App Router responses stream.
- `createCaptchaHandler({ secret })`: route handlers for the self-hosted captcha used by [`@webdecoy/client`](https://www.npmjs.com/package/@webdecoy/client). Mount at `app/__webdecoy/[...webdecoy]/route.ts` as `export const { GET, POST } = createCaptchaHandler({ secret: process.env.WEBDECOY_SECRET });`. `secret` is required when `NODE_ENV` is `production`.

## Environment variables

Only `withClearance()` reads environment variables (table above). `WEBDECOY_API_KEY` and `WEBDECOY_SECRET` are naming conventions: pass their values as `apiKey` and `secret`.

## Verify the install

With an `apiKey` configured, send one request with the reserved test User-Agent to a path your `matcher` covers:

```bash
curl -A "WebDecoy-Test/1.0" http://localhost:3000/api/health
```

A detection labeled **Test** appears on the **Detections** page within a few seconds.

## Documentation

- [Next.js middleware](https://docs.webdecoy.com/sdk-plugins/nextjs/)
- [Vercel middleware (clearance)](https://docs.webdecoy.com/installation/vercel-middleware/)
- [Install with an AI assistant](https://docs.webdecoy.com/installation/install-with-ai/): copy-paste snippets for every stack
- [Verify your install](https://docs.webdecoy.com/getting-started/verify-installation/)

## License

MIT
