# Catching a real browser that isn't a real user

Tripwires catch automation by intent: a hidden path a person can never reach, so
any request for it is a bot by construction. That is deterministic and
unspoofable, and it has one blind spot — a Playwright-driven Chrome that browses
only the links a human would. It presents a genuine fingerprint, it follows no
hidden links, and it requests no honeypot paths.

What it cannot fake is having a person behind it. `@webdecoy/client` collects
that evidence in the browser, `DetectionEngine` scores it on your server, and
`clientSignals()` lets the requests that follow act on the result.

**This augments the keyless rules; it does not replace them.** No JavaScript
means no signals, and a request with no session is `NOT_RUN`, never a denial —
curl and Googlebot both send nothing, and scoring silence would deny exactly the
crawlers you most need to keep.

## 1. Serve the endpoints, with a store

The `/score` endpoint already existed. What is new is the store: without it the
verdict goes back to the browser and your origin never learns anything from it.

```typescript
import express from 'express';
import { webdecoyCaptcha } from '@webdecoy/express';
import { MemoryClientSignalStore } from '@webdecoy/node';

const signalStore = new MemoryClientSignalStore();

const app = express();
app.use(express.json());
app.use(webdecoyCaptcha({ secret: process.env.WEBDECOY_SECRET, signalStore }));
```

`MemoryClientSignalStore` is per-process, like the rate limiter. On more than one
replica implement `ClientSignalStore` over something shared, or the request after
the submission may land on a different instance and find nothing.

## 2. Add the rule

```typescript
import { webdecoy } from '@webdecoy/express';
import { tripwire, clientSignals } from '@webdecoy/node';

app.use(webdecoy({
  rules: [
    tripwire(),                                   // intent — deterministic
    clientSignals({ store: signalStore }),        // interaction — probabilistic
  ],
}));
```

By default the rule follows the engine's own recommendation. `minScore` overrides
it with a threshold of your own, 0–1, higher being more bot-like.

Start with `dryRun: true`. This is the one rule in the SDK that is a judgement
rather than a fact, and you want a day of your own traffic before it blocks
anyone.

## 3. Load the widget

```bash
npm install @webdecoy/client
```

```typescript
import { WebDecoyCaptcha } from '@webdecoy/client';

WebDecoyCaptcha.configure({ serverUrl: '' });   // same origin
WebDecoyCaptcha.invisible({ action: 'browse' });
```

The package also ships a prebuilt global bundle at
`@webdecoy/client/global` for pages without a bundler. Serve it from your own
origin rather than a third-party CDN, or pin a version and add
`integrity`/`crossorigin` — a script tag with neither is a supply-chain
dependency on whoever is serving it.

The widget submits to `/score` with a `sessionId` and sets the `wd_cs` cookie.
The rule reads that cookie — or an `X-WD-Session` header, for a client that
cannot use cookies.

## 4. Confirm it works

```typescript
import { createTestHarness, request, expectDenied } from '@webdecoy/node/testing';

const wd = createTestHarness({ rules: [clientSignals({ store, minScore: 0.5 })] });
expectDenied(await wd.protect(request({ headers: { cookie: 'wd_cs=sess-1' } })));
```

Against a real browser: drive the page with Playwright, let the widget submit,
and compare the recorded score with your own session. `webdriver` alone
contributes to the score, and a session with no pointer movement, no scroll and
no keystrokes contributes considerably more.

## What the signals are

The collection contract is the code — `summarizeBehavior()` in
`@webdecoy/client` is the published list of what leaves the browser. In outline:

| Group | Examples |
|---|---|
| Behavioural | pointer trajectory, micro-tremor, velocity variance, scroll and key events |
| Environmental | `navigator.webdriver`, plugin count, automation flags, CDP artifacts |
| Temporal | time to first interaction, session duration, event deltas |
| Form | per-field dwell times, paste versus keystroke, submit timing |

No page content, no form values, no cookies other than the session id.

## Limits worth knowing

- **A client signal is a claim by code running on the client.** A determined
  attacker can lie to it. Its value is that most automation does not bother, and
  that faking human interaction convincingly is much harder than faking a
  fingerprint.
- **The score is probabilistic.** Unlike a tripwire hit, a high score is not
  proof. That is why `dryRun` is the recommended starting point and why the
  deterministic rules stay in the list.
- **Sessions expire** after 15 minutes by default.
