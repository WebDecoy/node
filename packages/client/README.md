# @webdecoy/client

Browser widget for [WebDecoy](https://github.com/WebDecoy/node) captcha — collects behavioral, environmental, and fingerprint signals, solves a SHA-256 proof-of-work, and submits to your WebDecoy-protected server.

[![npm version](https://img.shields.io/npm/v/@webdecoy/client.svg)](https://www.npmjs.com/package/@webdecoy/client)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pairs with the in-process detection engine in [`@webdecoy/node`](https://www.npmjs.com/package/@webdecoy/node).

## Installation

```bash
npm install @webdecoy/client
```

Or load the standalone bundle directly via `<script>`:

```html
<script src="https://unpkg.com/@webdecoy/client/dist/webdecoy.global.js"></script>
```

## Usage

### Checkbox widget

```html
<div id="captcha-box"></div>
<script type="module">
  import { WebDecoyCaptcha } from '@webdecoy/client';

  WebDecoyCaptcha.configure({ serverUrl: 'https://your-server.com' });
  const id = WebDecoyCaptcha.render('captcha-box', {
    siteKey: 'pk_live_...',
    theme: 'light',
    callback: (token) => console.log('verified:', token),
  });

  // Later: WebDecoyCaptcha.getResponse(id) → token
</script>
```

### Auto-init (no JS)

```html
<div data-webdecoy="pk_live_..." data-endpoint="https://your-server.com"></div>
<script src="https://unpkg.com/@webdecoy/client/dist/webdecoy.global.js"></script>
```

### Invisible mode

Passively scores the session and auto-protects form submissions (injects a
hidden `webdecoy_token` field, scores on submit):

```js
import { WebDecoyCaptcha } from '@webdecoy/client';

WebDecoyCaptcha.configure({ serverUrl: 'https://your-server.com' });
WebDecoyCaptcha.invisible({ siteKey: 'pk_live_...' });
```

Or score on demand:

```js
const result = await WebDecoyCaptcha.execute('pk_live_...', { action: 'login' });
if (result.success) { /* result.token */ }
```

## Session clearance

```js
import { startClearance } from '@webdecoy/client';

startClearance({ siteKey: 'YOUR_PUBLISHABLE_ORGANIZATION_ID' });
```

With version **0.18.5 or later**, the client defers initial minting to browser
idle, reuses fresh `wd_clearance` cookies, and renews before expiry throughout
long sessions. Repeated startup shares one lifecycle and collected fingerprint
per page. Cookie changes from another tab are noticed during periodic checks;
returning to a visible page checks clearance again.

Mint requests time out after 10 seconds. Transient failures retry with backoff
from one minute to five minutes; explicit server refusal stops automatic
attempts on that page. Unsigned expiry is only a scheduling hint. The server and
edge validator continue to verify every token and enforce revocation.

The cookie is Secure, SameSite Lax and host-only. Accepted interaction aggregates
remain on renewal requests, and the server evaluates them again; pass
`behavior: false` to disable the behavioral upgrade. The client does not intercept
or retry application fetch/XHR requests: an edge API challenge is a JSON 403
that your application must handle explicitly.

## What it collects

| Group | Signals |
|-------|---------|
| Behavioral | mouse trajectory/velocity/micro-tremor, click precision, touch kinematics, scroll, keystroke cadence |
| Sensor | device motion/orientation entropy (mobile) |
| Environmental | WebDriver/CDP/Playwright markers, canvas, WebGL, audio, fonts, WebRTC, speech, worker consistency, CSS media, permissions, DOMRect, RAF/JS timing |
| Form | submit method, per-field textarea typing stats |

Signals are hashed and bound into the proof-of-work so they can't be tampered
with after solving. The server scores them with `@webdecoy/node`.

## Server setup

Mount the matching endpoints on your backend (default base path `/__webdecoy`):

```js
import express from 'express';
import { webdecoyCaptcha } from '@webdecoy/express';

const app = express();
app.use(express.json());
app.use(webdecoyCaptcha({ secret: process.env.WEBDECOY_SECRET }));
```

See [`@webdecoy/node`](https://www.npmjs.com/package/@webdecoy/node) for Fastify
and Next.js adapters and the full detection/scoring reference.

## API

- `WebDecoyCaptcha.configure({ serverUrl })`
- `WebDecoyCaptcha.render(container, options) → widgetId`
- `WebDecoyCaptcha.getResponse(widgetId) → token | null`
- `WebDecoyCaptcha.reset(widgetId)`
- `WebDecoyCaptcha.invisible(options) → InvisibleSession`
- `WebDecoyCaptcha.execute(siteKey, { action, minTime, powDifficulty }) → Promise<result>`
- `WebDecoyCaptcha.autoInit()`

## License

MIT
