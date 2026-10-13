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
or retry application fetch/XHR requests globally. An edge API challenge is a JSON
403; the opt-in helper below handles safe reads through your application’s flow.

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

## API challenge recovery

With `@webdecoy/client` **0.19.0 or later** and an updated edge validator, opt in
for the API reads your application wants to recover:

```ts
import { createClearanceFetch } from '@webdecoy/client';
import { earnClearance } from './clearance-flow'; // your application's flow

const fetchProtected = createClearanceFetch({
  origin: location.origin,
  timeoutMs: 10_000,
  recover: ({ origin, challenge, signal }) =>
    earnClearance({ origin, reason: challenge.reason, signal }),
  onEvent: event => console.debug(event.type, event.status),
});

const controller = new AbortController();
const response = await fetchProtected('/api/catalog', {
  credentials: 'same-origin',
  signal: controller.signal, // your application's AbortController
});
// Handle response.ok/status/body just as with native fetch.
```

`earnClearance` is application code, not an SDK export. It must earn and install
the host's `wd_clearance` cookie through your configured issuance/verification
flow and return `true` only when ready to retry. `startClearance()` returns
`void`; awaiting it does not wait for a token. A self-hosted captcha widget token
is not a clearance cookie. A stronger-grade response needs a flow that earns the
route's required grade; simply replacing a token cannot grant that grade.

The helper retries **GET/HEAD once** after a recognized recoverable challenge.
Concurrent calls through one adapter share one recovery callback for its
configured origin; that callback receives the first challenge's reason. Use one
adapter for each origin/recovery flow. The edge evaluates every retry again.
POST/PATCH/PUT/DELETE and other methods pass through once with their original
body. There is no mutation replay opt-in and no XHR interception. The standalone
script exposes the same helpers at `window.WebDecoyClearance`.

Recovery and the retry share a deadline after the first challenge: 10 seconds by
default, configurable from 1 ms to 60 seconds. Refusal, resolver rejection,
offline state, or deadline expiry returns the original readable challenge
response. Caller cancellation and fetch network errors reject as native fetch
does. One cancelled caller does not cancel other callers waiting for the shared
flow; when none remain, the recovery signal aborts. Your flow must stop network
work and close its UI on that signal. If it ignores cancellation, later calls
remain attached to that stopped attempt until it settles, rather than opening
overlapping recovery dialogs. Browsers without `AbortSignal.any()` return the
challenge without attempting recovery.

Only version-1 responses with the exact WebDecoy challenge headers qualify.
Ordinary application 403s, unsupported/malformed contracts, revoked sessions,
crawler-policy refusals and agent impersonation do not trigger recovery.
Redirected responses, different origins and `credentials: 'omit'` also do not.
The helper preserves request options and leaves response bodies/streams unread.
It adds no request headers or CORS permission. Cross-origin calls need
`credentials: 'include'`, the protected host's cookie, and an application-approved
CORS policy that exposes the four challenge headers; otherwise the browser
cannot identify the response. A cookie set on the page's host does not clear a
different API host.

`onEvent` reports `challenge-served`, `recovery-attempted`,
`recovery-succeeded`/`recovery-failed`, and the retried `enforcement-outcome`
(status). Attempts are per waiting request; count callback invocations separately
for shared flows. Success means the retry returned an OK response, not a new
trust grade. These local observations send no telemetry automatically and must
remain distinct from the validator's verdict counts. Observation failures cannot
change the request. Interactive application flows must provide keyboard access,
focus restoration, an announced status and cancellation; the helper renders no UI.
