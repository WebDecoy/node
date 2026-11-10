# @webdecoy/hono

WebDecoy middleware for Hono on Cloudflare Workers, Bun, Deno and Node: tripwires, rate limits and other local rules, plus optional server-side bot detection reported to your WebDecoy dashboard. Starts in monitor mode.

[![npm version](https://img.shields.io/npm/v/@webdecoy/hono.svg)](https://www.npmjs.com/package/@webdecoy/hono)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @webdecoy/hono @webdecoy/node
```

`@webdecoy/node` is the core SDK. Install it directly: rules such as `tripwire()` and `rateLimit()` are imported from it. Requires Hono 4.

## Quick start

```ts
import { Hono } from 'hono';
import { webdecoy } from '@webdecoy/hono';

const app = new Hono();

app.use('*', webdecoy({
  apiKey: process.env.WEBDECOY_API_KEY,
  skipPaths: ['/health'],
}));

app.get('/', (c) => {
  // c.get('webdecoy') carries the decision; in monitor mode this is where it surfaces
  return c.text('ok');
});

export default app;
```

On Cloudflare Workers, `process.env` needs the `nodejs_compat` compatibility flag and a recent compatibility date. Behind Cloudflare, `trustProxy: 'cloudflare'` is stronger than the default of one trusted hop.

### API key

`apiKey` is optional. Without it the middleware runs local rules only (the built-in tripwire paths by default) and nothing reports to your dashboard. The middleware does **not** read `WEBDECOY_API_KEY` from the environment by itself: pass it as `apiKey`, as above.

To get a key: sign up at [app.webdecoy.com](https://app.webdecoy.com), add your site, then create a key on the **API Keys** page. Keys start with `sk_live_` or `sk_test_`. Store it as a secret in your runtime's environment (for example `wrangler secret put WEBDECOY_API_KEY`), never in committed code.

### Monitor mode

The middleware starts in **monitor mode**: it stores the decision on the context and serves every request, even one it would have blocked. Review what it would have blocked, then opt in with `mode: 'enforce'`. In enforce mode a rule refusal answers `403`, a rate-limit throttle answers `429` with `Retry-After`, and a server-score block answers `403`, unless you pass `onBlocked`.

## Reading the decision

```ts
app.get('/', (c) => {
  const decision = c.get('webdecoy'); // also available as c.get('webdecoyDecision')
  if (decision?.deniedBy('tripwire')) console.log('tripwire hit', decision.id);
  return c.text('ok');
});
```

The decision has `conclusion` (`'ALLOW'`, `'DENY'`, `'CHALLENGE'` or `'ERROR'`), `allowed`, `results` (every rule and what it concluded), `deniedBy(rule)`, `id` and `detection`. See the [@webdecoy/node README](https://www.npmjs.com/package/@webdecoy/node) for the full shape.

## Local rules

With no `rules` option the middleware arms `tripwire()` with its built-in scanner-bait paths (`/.env`, `/wp-config.php` and similar). Pass `rules: []` to opt out, or add your own:

```ts
import { tripwire, rateLimit } from '@webdecoy/node';

app.use('*', webdecoy({
  rules: [
    tripwire({ paths: ['/admin-backup.zip'] }),
    rateLimit({ max: 100, window: 60 }),
  ],
}));
```

`rateLimit()` counts in memory per isolate or process. On Workers or any multi-instance deployment, pass a shared store such as `upstashRateLimitStore()` from `@webdecoy/node`.

## Options

`webdecoy()` accepts every core SDK option (`apiKey`, `rules`, `apiUrl`, `threatScoreThreshold`, `timeout`, `debug`, ...) and the per-request options `threshold`, `skipLocalAnalysis` and `metadata`, plus:

| Option | Default | Description |
|---|---|---|
| `mode` | `'monitor'` | `'monitor'` records and serves every request; `'enforce'` blocks. |
| `skipPaths` | none | Paths to skip, as strings or regular expressions. |
| `trustProxy` | `1` | How much of `X-Forwarded-For` to believe: a hop count, `'cloudflare'`, `'railway'`, or your proxies' CIDRs. |
| `getIP` | derived from `trustProxy` | `(request: Request) => string`. Overrides `trustProxy`. |
| `honeytoken` | on when `apiKey` is set | Inject a hidden trap link into full HTML responses and arm the tripwire it points at. |
| `onBlocked` | `403`, or `429` for a throttle | `(c, decision) => Response`. Enforce mode only; replaces the default response for every block. |

## Without Hono

For Bun, Deno, Astro, SvelteKit, Remix or a bare Workers `fetch` handler, `createFetchGuard()` from `@webdecoy/node` is the same implementation this middleware wraps:

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

## Environment variables

None are read automatically. `WEBDECOY_API_KEY` above is a naming convention: pass its value as `apiKey`.

## Verify the install

With an `apiKey` configured, send one request with the reserved test User-Agent:

```bash
curl -A "WebDecoy-Test/1.0" http://localhost:8787/
```

Use your dev server's port. A detection labeled **Test** appears on the **Detections** page within a few seconds.

## Documentation

- [Install with an AI assistant](https://docs.webdecoy.com/installation/install-with-ai/#hono): copy-paste snippets for every stack
- [Node.js SDK](https://docs.webdecoy.com/sdk-plugins/node-sdk/)
- [Verify your install](https://docs.webdecoy.com/getting-started/verify-installation/)

## License

MIT
