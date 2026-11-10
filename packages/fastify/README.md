# @webdecoy/fastify

WebDecoy plugin for Fastify 4 and 5: tripwires, rate limits and other local rules, plus optional server-side bot detection reported to your WebDecoy dashboard. Starts in monitor mode.

[![npm version](https://img.shields.io/npm/v/@webdecoy/fastify.svg)](https://www.npmjs.com/package/@webdecoy/fastify)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Installation

```bash
npm install @webdecoy/fastify @webdecoy/node
```

`@webdecoy/node` is the core SDK. Install it directly: rules such as `tripwire()` and `rateLimit()` are imported from it.

## Quick start

```js
import Fastify from 'fastify';
import webdecoy from '@webdecoy/fastify';

const app = Fastify();

await app.register(webdecoy, {
  apiKey: process.env.WEBDECOY_API_KEY,
  skipPaths: ['/health'],
});

app.get('/', async (request) => {
  // request.webdecoy carries the detection (decision, confidence, threat_level, bot_detected)
  // request.webdecoyDecision carries the full typed decision
  return { ok: true };
});

await app.listen({ port: 3000 });
```

The plugin hooks every route (it is registered with `fastify-plugin`, so it is not scoped to an encapsulation context). The default export and the named export `webdecoyPlugin` are the same plugin.

### API key

`apiKey` is optional. Without it the plugin runs local rules only (the built-in tripwire paths by default) and nothing reports to your dashboard. The plugin does **not** read `WEBDECOY_API_KEY` from the environment by itself: pass it as `apiKey`, as above.

To get a key: sign up at [app.webdecoy.com](https://app.webdecoy.com), add your site, then create a key on the **API Keys** page. Keys start with `sk_live_` or `sk_test_`. Keep it in your server environment, never in committed code.

### Monitor mode

The plugin starts in **monitor mode**: it records the decision on the request and serves every request, even one it would have blocked. Review what it would have blocked, then opt in:

```js
await app.register(webdecoy, {
  apiKey: process.env.WEBDECOY_API_KEY,
  mode: 'enforce',
});
```

In enforce mode a rule refusal answers `403` (naming the rule), a rate-limit throttle answers `429` with `Retry-After`, and a request blocked by the server-side score goes to `onBlocked` (default `403`).

## Local rules

With no `rules` option the plugin arms `tripwire()` with its built-in scanner-bait paths (`/.env`, `/wp-config.php` and similar). Pass `rules: []` to opt out, or add your own:

```js
import { tripwire, rateLimit } from '@webdecoy/node';

await app.register(webdecoy, {
  rules: [
    tripwire({ paths: ['/admin-backup.zip'] }),
    rateLimit({ max: 100, window: 60 }),
  ],
});

app.addHook('onResponse', async (request) => {
  if (request.webdecoyDecision?.deniedBy('tripwire')) {
    request.log.warn({ decision: request.webdecoyDecision.id }, 'tripwire hit');
  }
});
```

See the [@webdecoy/node README](https://www.npmjs.com/package/@webdecoy/node) for every rule and the decision shape (`conclusion`, `allowed`, `results`, `deniedBy()`).

## Options

The plugin accepts every core SDK option (`apiKey`, `rules`, `apiUrl`, `threatScoreThreshold`, `timeout`, `debug`, ...) and the per-request options `threshold`, `skipLocalAnalysis` and `metadata`, plus:

| Option | Default | Description |
|---|---|---|
| `mode` | `'monitor'` | `'monitor'` records and serves every request; `'enforce'` blocks. |
| `skipPaths` | none | Paths to skip, as strings or regular expressions. |
| `trustProxy` | unset: uses `request.ip` | How much of `X-Forwarded-For` to believe: a hop count, `'cloudflare'`, `'railway'`, or your proxies' CIDRs. |
| `getIP` | derived from `trustProxy` | `(request) => string`. Overrides `trustProxy`. |
| `honeytoken` | on when `apiKey` is set | Inject a hidden trap link into HTML replies and arm the tripwire it points at. |
| `onBlocked` | `403` JSON | `(request, reply, detection, decision) => void`. Enforce mode, server-score blocks. |
| `onError` | log and allow | `(request, reply, error) => void`. The plugin fails open. |

### Request properties

| Property | What it is |
|---|---|
| `request.webdecoy` | The detection: `decision`, `confidence`, `threat_level`, `bot_detected`, `bot_type`, `detection_id`, `rule_enforced`. |
| `request.webdecoyDecision` | The full decision: `conclusion`, `allowed`, `results`, `deniedBy(rule)`, `id`. In monitor mode this is the only place a verdict surfaces. |
| `request.webdecoyEdge` | What a WebDecoy edge validator said about the request, when one fronts your app. |

### Client IP behind a proxy

Unset, the plugin uses `request.ip`, which follows Fastify's own `trustProxy` server option and otherwise is the socket address. Behind a load balancer or platform proxy, set `trustProxy` on the WebDecoy plugin rather than relying on Fastify's numeric server option:

```js
await app.register(webdecoy, {
  apiKey: process.env.WEBDECOY_API_KEY,
  trustProxy: 1, // or 'cloudflare', 'railway', or ['10.0.0.0/8']
});
```

### Honeytoken injection

With an `apiKey`, the plugin injects a hidden link into buffered HTML replies (`reply.send(html)`, `@fastify/view`) and arms a tripwire on its path. Streamed replies are left untouched and a warning is logged once.

## Self-hosted captcha

`webdecoyCaptchaPlugin` mounts the captcha endpoints (`/__webdecoy/challenge`, `/verify`, `/score`, `/token/verify`) used by [`@webdecoy/client`](https://www.npmjs.com/package/@webdecoy/client):

```js
import { webdecoyCaptchaPlugin } from '@webdecoy/fastify';

await app.register(webdecoyCaptchaPlugin, { secret: process.env.WEBDECOY_SECRET });
```

`secret` is required when `NODE_ENV` is `production`. Generate one with `openssl rand -hex 32`.

## Environment variables

None are read automatically. `WEBDECOY_API_KEY` and `WEBDECOY_SECRET` above are naming conventions: pass their values as `apiKey` and `secret`.

## Verify the install

With an `apiKey` configured, send one request with the reserved test User-Agent:

```bash
curl -A "WebDecoy-Test/1.0" http://localhost:3000/
```

A detection labeled **Test** appears on the **Detections** page within a few seconds. If nothing appears, check that the plugin is registered before your routes and that `apiKey` is passed.

## Documentation

- [Fastify plugin](https://docs.webdecoy.com/sdk-plugins/fastify/)
- [Install with an AI assistant](https://docs.webdecoy.com/installation/install-with-ai/): copy-paste snippets for every stack
- [Verify your install](https://docs.webdecoy.com/getting-started/verify-installation/)

## License

MIT
