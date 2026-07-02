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
