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

Fastify (`@webdecoy/fastify`), Next.js (`@webdecoy/nextjs`) and Hono (`@webdecoy/hono`) expose the same rule-based middleware.

### Hono — Workers, Bun, Deno

```bash
npm install @webdecoy/hono
```

```typescript
import { Hono } from 'hono';
import { webdecoy } from '@webdecoy/hono';
import { tripwire } from '@webdecoy/node';

const app = new Hono();
app.use('*', webdecoy({ rules: [tripwire()], skipPaths: ['/health'] }));
```

`c.get('webdecoy')` carries the decision — in monitor mode, which is the default,
that is the only place the verdict surfaces.

### Any other fetch runtime — no package needed

Bun, Deno, Astro, Nitro, SvelteKit and Remix all hand you a WHATWG `Request` and
want a `Response`. `createFetchGuard()` is the same implementation the Hono
adapter wraps:

```typescript
import { createFetchGuard, tripwire } from '@webdecoy/node';

const guard = createFetchGuard({ mode: 'enforce', rules: [tripwire()] });

export default {
  async fetch(request: Request): Promise<Response> {
    const { response } = await guard.check(request);
    if (response) return response;              // denied
    return guard.decorate(await handle(request)); // injects the honeytoken link
  },
};
```

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

- **`rateLimit({ max, window, algorithm?, action?, keyBy?, store? })`** — fixed or sliding window, keyed by IP (or a custom function). No key. See [shared rate limits](#rate-limits-across-more-than-one-process) before you run two replicas.
- **`tripwire({ paths?, prefixes?, patterns?, includeDefaults? })`** — deterministic honeypot-path detection. No key.
- **`webBotAuth({ onImpersonation?, onClaimed?, allowCategories? })`** — verify AI-agent signatures (Web Bot Auth / RFC 9421) locally; deny impersonators of known agents. No key.
- **`filter({ expression, action? })`** — an expression language over IP reputation/geo (e.g. `ip.tor`, `ip.country in ["CN", "RU"]`). Requires an API key for enrichment.
- **`attackSignatures({ inspect?, exclude?, action? })`** — deny requests carrying unambiguous injection payloads. No key. See [attack signatures](#attack-signatures).

## Verify AI agents (Web Bot Auth)

AI agents like OpenAI's Operator now **cryptographically sign** their requests
([Web Bot Auth](https://datatracker.ietf.org/wg/webbotauth/about/), RFC 9421).
WebDecoy verifies those signatures **locally** — on Node and on the edge, with no
API key and no network on the warm path — so you can tell a real verified agent
from someone forging its identity.

```typescript
import { WebDecoy } from '@webdecoy/node';

const wd = new WebDecoy();

const verdict = await wd.detectBot(request); // a WHATWG Request, or { method, url, headers }
// verdict.status: 'verified' | 'impersonation' | 'claimed' | 'none'
if (verdict.status === 'impersonation') return new Response('Forbidden', { status: 403 });
if (verdict.status === 'verified') console.log('verified agent:', verdict.agentName, verdict.category);
```

Or drop it into the rules engine to deny impersonation automatically:

```typescript
const wd = new WebDecoy({ rules: [webBotAuth()] }); // denies known-agent impersonation
```

Full guide: [**Verify AI agents with Web Bot Auth in Next.js**](docs/verify-ai-agents-web-bot-auth.md).

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
| [@webdecoy/hono](https://www.npmjs.com/package/@webdecoy/hono) | [![npm](https://img.shields.io/npm/v/@webdecoy/hono.svg)](https://www.npmjs.com/package/@webdecoy/hono) | Hono middleware (Workers, Bun, Deno) |
| [@webdecoy/client](https://www.npmjs.com/package/@webdecoy/client) | [![npm](https://img.shields.io/npm/v/@webdecoy/client.svg)](https://www.npmjs.com/package/@webdecoy/client) | Browser-side signal collector |

## One bot policy, published and enforced

`botPolicy()` produces both the `robots.txt` you publish and the rule that
enforces it, from one object — so they cannot drift:

```typescript
import { WebDecoy, botPolicy } from '@webdecoy/node';

const policy = botPolicy({
  deny: ['training_crawler'],     // or 'ai', a category, or an agent name
  allow: ['perplexitybot'],
});

app.get('/robots.txt', (_req, res) => res.type('text/plain').send(policy.robotsTxt()));

const wd = new WebDecoy({ rules: [policy.rule()] });
```

A `robots.txt` that disallows GPTBot while the middleware lets it through is a
policy you believe is in force and is not. The reverse — enforcing against a
crawler the published file invites — is how a site quietly leaves a search index.

`robots.txt` is a request, honoured at the crawler's discretion. The registry
records whether each operator *documents* honouring it, and the generated file
names the ones in your deny set that do not:

```
# These do not document honouring robots.txt, so the lines below are a
# request only. The bots() rule is what actually stops them:
#   ByteSpider (ByteDance)
#   Webz.io (Webz.io)
```

`policy.unenforceable` is the same list, in code. Requires no API key.

## Catching a real browser that isn't a real user

A Playwright-driven Chrome that browses only the links a human would presents a
genuine fingerprint, follows no hidden links and requests no honeypot paths — the
one thing a tripwire cannot see. What it cannot fake is having a person behind
it.

```typescript
import { MemoryClientSignalStore, clientSignals, tripwire } from '@webdecoy/node';

const signalStore = new MemoryClientSignalStore();

app.use(webdecoyCaptcha({ secret: process.env.WEBDECOY_SECRET, signalStore }));
app.use(webdecoy({
  rules: [
    tripwire(),                                          // intent — deterministic
    clientSignals({ store: signalStore, dryRun: true }), // interaction — probabilistic
  ],
}));
```

`@webdecoy/client` collects behavioural, environmental and form signals in the
browser; `/score` records the verdict against the session; `clientSignals()` acts
on it for the requests that follow. Before this the score went back to the
browser and the origin never learned anything from it.

**A request with no session is `NOT_RUN`, never a denial** — curl and Googlebot
both send nothing, and scoring silence would deny exactly the crawlers you most
need to keep. This augments the keyless rules; it does not replace them.

Full guide: [**Catching a real browser that isn't a real user**](docs/client-signals.md).

## Attack signatures

Tripwires catch scanners by the path they ask for. `attackSignatures()` looks at
what they send:

```typescript
attackSignatures({
  inspect: ['path', 'query'],  // default; 'body' and 'headers' are opt-in
  exclude: ['traversal'],      // signature ids
  dryRun: false,
});
```

**This is not a WAF, and should not become one.** A WAF's value is breadth, and
breadth is bought with false positives. This is a small curated set — SQL
injection, XSS, traversal, command injection, `${jndi:` — chosen because each has
no innocent reading in a path or query string. It composes with the deterministic
signals: a request carrying an injection payload *and* walking into a tripwire is
much stronger evidence than either alone.

Bodies and headers are off by default, because a CMS saving an article and a URL
passed as a query parameter both legitimately contain things that look like
attacks. Turn them on with `dryRun: true` first. The `Cookie` header is never
inspected at all — session tokens are opaque, and one that trips a signature logs
a user out for a reason nobody can explain.

## Rate limits across more than one process

`rateLimit()` counts in this process's memory by default. That is correct for a
single process and wrong the moment you run two: the effective limit becomes
`max × instances`, and on Vercel or Lambda it also resets on every cold start.

Point the rule at a shared store to make one limit one limit:

```typescript
import { rateLimit, upstashRateLimitStore } from '@webdecoy/node';

const store = upstashRateLimitStore({
  url: process.env.UPSTASH_REDIS_REST_URL!,
  token: process.env.UPSTASH_REDIS_REST_TOKEN!,
});

const wd = new WebDecoy({
  rules: [rateLimit({ max: 100, window: 60, store })],
});
```

Upstash speaks Redis over HTTP, so this works on Vercel Edge, Cloudflare Workers
and Deno, where an ordinary Redis client cannot open a socket. It uses `fetch`
directly — no `@upstash/redis` dependency.

If Redis is unreachable the store **fails open** and the request is allowed; pass
`onError: 'closed'` to deny instead. Either way the outcome appears in
`decision.results`, so it does not look like a normal evaluation.

Any object implementing `RateLimitStore` works. A store that returns promises is
consumed during `protect()`'s async pre-fetch; a `sync` store is consumed inline.
The synchronous `evaluateRules()` cannot consume a networked store, and reports
`NOT_RUN` rather than allowing silently.

## Client IP behind a proxy

Rate limits, IP enrichment and every detection we record are keyed on the caller's address, so it matters that the address is real. `X-Forwarded-For` is written by the client for the first hop — the leftmost value in it is whatever the caller decided to send — so the middleware believes it only as far as you say it should, counted from the **right** of the chain, which is the end your own infrastructure wrote.

```typescript
app.use(webdecoy({
  trustProxy: 1,   // one proxy in front of this app
}));
```

| `trustProxy` | Meaning |
|---|---|
| `false` | Read no forwarding headers. The socket address is the client. |
| `1`, `2`, … | The number of proxies between the client and this app. |
| `'cloudflare'` | Use `CF-Connecting-IP`. Only safe if the origin is unreachable except through Cloudflare. |
| `['10.0.0.0/8', …]` | CIDRs of proxies you run. The chain is walked right to left and the first address that isn't yours is the client. |

**Defaults.** Express and Fastify defer to `req.ip` / `request.ip`, which already honour the framework's own trust-proxy setting and otherwise resolve to the socket address — so if you've configured `app.set('trust proxy', …)` there's nothing to do here. Next.js middleware has no socket to fall back on, so it defaults to `1` trusted hop, which is correct on Vercel and on any single-proxy deployment.

If your app sits behind a proxy and neither of those is configured, set `trustProxy` — otherwise every request is attributed to the proxy and rate limits apply to your whole site at once.

The same option is accepted by `webdecoyCaptcha()` / `createCaptchaHandler()`, and `getIP` still overrides all of it. To derive the address yourself the same way, `@webdecoy/node` exports `resolveClientIp()`, `normalizeIp()` and `ipInCidr()`.

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

### `webBotAuth(config?)` / `detectBot(request)`

Local Web Bot Auth verification (RFC 9421). `webBotAuth()` returns a `Rule` that denies agent impersonation; `detectBot(request)` returns the verdict directly for custom handling. See the [Web Bot Auth guide](docs/verify-ai-agents-web-bot-auth.md). Exported types: `AgentVerdict`, `AgentStatus`, `AgentCategory`, `WebBotAuthConfig`, `AgentVerifierOptions`, `SignedAgentDirectory`.

### `protect(metadata, options?): Promise<Decision>`

Full analysis of a request. Returns a typed decision:

```typescript
const d = await wd.protect(metadata);

d.conclusion            // 'ALLOW' | 'DENY' | 'CHALLENGE' | 'ERROR'
d.allowed               // true for ALLOW and ERROR (fail open)
d.id                    // 'dec_…', correlates with the dashboard
d.isDenied()            // narrowing helpers
d.deniedBy('tripwire')  // which rule, without string-matching
d.results               // every rule, in order, and what it concluded
d.detection             // the service's response, as before
d.edge                  // what the edge validator said
```

`results` is the part worth knowing about. Every configured rule appears, with a
`state`:

| `state` | Meaning |
|---|---|
| `RUN` | Evaluated, and its conclusion counts. |
| `DRY_RUN` | Evaluated; conclusion recorded but not enforced. |
| `NOT_RUN` | Could not evaluate — a signal it needs was absent (a `filter()` with no IP enrichment, a `webBotAuth()` on a request with no host). |
| `CACHED` | Not evaluated; a prior decision for this key was reused. |

`NOT_RUN` is the one that used to be invisible: such a rule reported ALLOW, which
reads as "checked and fine" rather than "never checked". A dry-run rule that
matched reports `conclusion: 'DENY'` with `state: 'DRY_RUN'` — what it *would*
have done is the reason you turned it on.

`ERROR` is not a synonym for `DENY`. It means no verdict was reached, and the
request is allowed through.

### `characteristics` — what counts as the same caller

Rate limits and the decision cache key on the client IP by default. On an
authenticated API that is usually the wrong subject:

```typescript
const wd = new WebDecoy({
  characteristics: [(ctx) => ctx.headers['x-api-key']],
  rules: [rateLimit({ max: 100, window: 60 })],
});
```

Built-ins are `'ip'`, `'path'`, `'method'`, `'userAgent'`; a function derives
anything else. A rule's own `keyBy` still wins. If a characteristic is absent on
a request the key falls back to the IP, rather than bucketing every request
missing that field together.

All TypeScript types are exported (`WebDecoyConfig`, `RequestMetadata`, `ProtectResult`, `Rule`, `TripwireConfig`, `RateLimitConfig`, `FilterConfig`, `Honeytoken`, …).

## Testing your rules

```typescript
import { createTestHarness, get, expectDenied, expectAllowed } from '@webdecoy/node/testing';
import { tripwire } from '@webdecoy/node';

const wd = createTestHarness({ rules: [tripwire()] });

test('a scanner is denied and a visitor is not', async () => {
  expectDenied(await wd.protect(get('/.env')), { rule: 'tripwire' });
  expectAllowed(await wd.protect(get('/')));
});
```

The harness is **offline by default** — an API key in the environment is ignored
unless you pass `allowNetwork: true`, so a unit test never turns into a live call
or files test traffic as a real detection. Each harness gets its own rule state,
so rate-limit counters do not leak between cases.

`protectMany(sdk, request, n)` runs a rate limit to its edge without sleeping.
Assertion failures print every rule and its state, because "expected false to be
true" tells you nothing about which of six rules was supposed to fire.

## Logging

Diagnostics default to `console`, with everything below `warn` gated on `debug`.
Pass any object with `debug`/`info`/`warn`/`error`:

```typescript
new WebDecoy({ logger: myLogger });
new WebDecoy({ logger: fromPino(pino()) });  // pino's argument order is reversed
```

`fromPino()` exists because passing a pino instance directly type-checks and then
silently drops every structured field.

## Tracing

Pass an OpenTelemetry tracer and `protect()` emits a span, with a child span for
rule evaluation:

```typescript
import { trace } from '@opentelemetry/api';

new WebDecoy({ tracer: trace.getTracer('webdecoy') });
```

The tracer is **injected, not imported** — this package has no dependencies and
runs on Workers and Vercel Edge, where a stray transitive import is expensive.
The `Tracer` type is a structural subset of OpenTelemetry's, so
`trace.getTracer()` satisfies it with no adapter. Omit it and there are no spans,
no dependency, and no behaviour change.

Attributes are the questions an operator actually asks: `decision.id` (which
joins the span to the dashboard row), `decision.conclusion`, `decision.rule`,
`rules.evaluated`, and `webdecoy.remote` — whether the request cost a round trip
to ingest or was settled locally.

A tracer that throws cannot fail a request. Observability that can take the
request path down is worse than none.

## Examples

See [examples](./examples) for complete working setups — e.g. [express-basic](./examples/express-basic).

## FAQ

**Will this slow down my app?** Local rules (tripwires, rate limiting) add <1ms and make no network calls. Server verification (with a key) typically takes 50–200ms and runs asynchronously for low-risk requests.

**What if the WebDecoy service is down?** Local rules are unaffected (they never call out). Platform `protect()` fails open by default, so requests continue.

**Behind a CDN or load balancer?** Yes, but tell the middleware how many proxies are in front of it. See [Client IP behind a proxy](#client-ip-behind-a-proxy).

## Support

- **Website**: [webdecoy.com](https://webdecoy.com)
- **Dashboard**: [app.webdecoy.com](https://app.webdecoy.com)
- **Issues**: [github.com/WebDecoy/node/issues](https://github.com/WebDecoy/node/issues)
- **Email**: support@webdecoy.com

## Contributing

Contributions welcome — please read the [Contributing Guide](./CONTRIBUTING.md) first.

## License

MIT — see [LICENSE](./LICENSE).
