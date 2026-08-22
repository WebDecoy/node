# Installing WebDecoy

Instructions for a coding agent asked to add bot protection to an application.
For the full API surface see [`llms.txt`](./llms.txt); this file is the install,
what to verify, and the mistakes that are expensive.

## Pick the package

| The app uses | Install | Import |
|---|---|---|
| Express | `@webdecoy/express` | `webdecoy()` middleware |
| Fastify | `@webdecoy/fastify` | `webdecoy` plugin |
| Next.js | `@webdecoy/nextjs` | `withWebDecoy()` in `middleware.ts` |
| Hono, Workers, Bun, Deno | `@webdecoy/hono` | `webdecoy()` middleware |
| Anything else with a `fetch` handler | `@webdecoy/node` | `createFetchGuard()` |

Every adapter depends on `@webdecoy/node`, which comes in automatically.

## Install

```typescript
import { webdecoy } from '@webdecoy/express';
import { tripwire, rateLimit } from '@webdecoy/node';

app.use(webdecoy({
  rules: [tripwire(), rateLimit({ max: 100, window: 60 })],
  skipPaths: ['/health', '/metrics'],
}));
```

Mount it **before** the application's routes and after any body parser. No API
key is required — tripwires and rate limiting run entirely in-process.

## Verify, and show the user the receipt

```bash
curl -A "WebDecoy-Test/1.0" http://localhost:3000/
```

`WebDecoy-Test/` is a reserved User-Agent. It always produces a labelled test
detection through the real pipeline, and never fires the application's own rules.
With an API key it appears in the dashboard; without one, the result says so
explicitly rather than pretending.

Then confirm a real tripwire:

```bash
curl -i http://localhost:3000/.env    # 403 in enforce mode; logged in monitor mode
curl -i http://localhost:3000/        # 200, unaffected
```

An install is not finished until one of these has produced a visible result.
Report which one you ran and what it returned.

## Do not do these

- **Do not set `mode: 'enforce'` on a first install.** The default is `'monitor'`
  and it is the default deliberately: the middleware records what it would have
  done and serves the request. Switching to enforce is the user's decision once
  they have seen a day of traffic. Say so rather than deciding for them.
- **Do not invent an API key or add one the user has not given you.** The local
  rules are the whole product for a keyless install. If the user wants the
  dashboard, point them at https://app.webdecoy.com and let them paste the key.
- **Do not add `filter()` without a key.** It needs IP enrichment; without one it
  reports `NOT_RUN` and does nothing.
- **Do not leave a proxied app on the default `trustProxy`.** Forwarding headers
  are not believed by default because the client writes the leftmost value. If
  the app sits behind Cloudflare, a load balancer or a platform proxy, either set
  the framework's own trust-proxy setting (Express `app.set('trust proxy', 1)`,
  Fastify `{ trustProxy: 1 }`) or pass `trustProxy` to the middleware. Getting
  this wrong attributes every request to the proxy and applies rate limits
  site-wide.
- **Do not describe `attackSignatures()` as a WAF.** It is a small curated set of
  unambiguous injection payloads. Turning on `inspect: ['body']` on a CMS will
  produce false positives; start it with `dryRun: true`.
- **Do not rely on in-process rate limits across replicas.** On more than one
  process the limit becomes `max × instances`. Use `upstashRateLimitStore()` or
  say plainly that the limit is per-instance.

## Common additions

Control AI crawlers, publishing and enforcing one policy:

```typescript
import { botPolicy } from '@webdecoy/node';

const policy = botPolicy({ deny: ['training_crawler'], allow: ['perplexitybot'] });
app.get('/robots.txt', (_req, res) => res.type('text/plain').send(policy.robotsTxt()));
app.use(webdecoy({ rules: [policy.rule(), tripwire()] }));
```

Verify AI agents cryptographically (RFC 9421, no key, no network on the warm
path):

```typescript
import { webBotAuth } from '@webdecoy/node';
app.use(webdecoy({ rules: [webBotAuth(), tripwire()] }));
```

Shared rate limits across replicas:

```typescript
import { rateLimit, upstashRateLimitStore } from '@webdecoy/node';

rateLimit({
  max: 100,
  window: 60,
  store: upstashRateLimitStore({
    url: process.env.UPSTASH_REDIS_REST_URL!,
    token: process.env.UPSTASH_REDIS_REST_TOKEN!,
  }),
});
```

## Write a test for it

```typescript
import { createTestHarness, get, expectDenied, expectAllowed } from '@webdecoy/node/testing';
import { tripwire } from '@webdecoy/node';

const wd = createTestHarness({ rules: [tripwire()] });

test('a scanner is denied and a visitor is not', async () => {
  expectDenied(await wd.protect(get('/.env')), { rule: 'tripwire' });
  expectAllowed(await wd.protect(get('/')));
});
```

Offline by default — an API key in the environment is ignored unless
`allowNetwork: true`, so this never files test traffic as a real detection.

## Reading a verdict in application code

```typescript
const decision = req.webdecoyDecision;        // Express, Fastify, Next.js
const decision = c.get('webdecoyDecision');   // Hono

decision?.conclusion       // 'ALLOW' | 'DENY' | 'CHALLENGE' | 'ERROR'
decision?.deniedBy('tripwire')
decision?.results          // every rule: RUN | DRY_RUN | NOT_RUN | CACHED
```

`webdecoyDecision` means the same thing in every adapter. `req.webdecoy` is the
older, narrower detection response and is still populated — do not confuse the
two.

In monitor mode this is the only place the verdict surfaces, so an app that
wants to log or meter denials reads it here.
