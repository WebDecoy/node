# Verify AI agents with Web Bot Auth in Next.js

AI agents that browse the web on a user's behalf — OpenAI's Operator, ChatGPT's
browsing tool, and a growing cohort behind the IETF
[`webbotauth`](https://datatracker.ietf.org/wg/webbotauth/about/) working group —
now **cryptographically sign** their requests using
[Web Bot Auth](https://datatracker.ietf.org/doc/draft-meunier-web-bot-auth-architecture/)
(RFC 9421 HTTP Message Signatures, tag `web-bot-auth`). A signed request proves
"this really is that agent," and an *unverifiable* signature that claims a known
agent's identity is a forgery you can block.

`@webdecoy/node` verifies these signatures **locally, in your middleware** — on
Node and on every WinterCG edge runtime (Vercel Edge, Cloudflare Workers). No
API key, and **no network on the warm path**: trusted agent directories are
fetched once and cached, so a verification is a header parse, a map lookup, and
one WebCrypto check (well under 5 ms).

> This is the same verification WebDecoy runs at ingest and at the edge — the
> SDK, the edge validator, and the backend all share the
> [`github.com/WebDecoy/web-bot-auth`](https://github.com/WebDecoy/web-bot-auth)
> profile and speak the same verdict taxonomy.

## The verdict

Every request resolves to one of four statuses:

| `status` | Meaning | Typical action |
|---|---|---|
| `verified` | Signature validated against a trusted agent's published key. `agentName` and `category` are populated. | Allow (optionally with elevated trust) |
| `impersonation` | A signature claimed a **known** agent's key but failed verification (bad signature, or outside its validity window). A forgery. | **Deny** |
| `claimed` | A signature is present but unverifiable — an unknown/uncurated signer, or malformed. Not proof of an agent, nor of a forgery. | Let your other rules decide |
| `none` | No Web Bot Auth signature. Ordinary traffic. | Continue |

## Option A — `detectBot()` in Next.js middleware

`detectBot()` is the low-level primitive. It takes a WHATWG `Request` (what
Next.js middleware and Edge routes already hand you) and returns the verdict, so
you decide what to do:

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { WebDecoy } from '@webdecoy/node';

const wd = new WebDecoy(); // no API key needed for local verification

export async function middleware(req: NextRequest) {
  const verdict = await wd.detectBot(req);

  switch (verdict.status) {
    case 'impersonation':
      // Someone is forging a known agent's identity — block it.
      return new NextResponse('Forbidden', { status: 403 });

    case 'verified':
      // A real, cryptographically verified agent. Let it through and tag it
      // for your route handlers.
      const res = NextResponse.next();
      res.headers.set('x-verified-agent', verdict.agentName ?? '');
      res.headers.set('x-verified-agent-category', verdict.category ?? '');
      return res;

    default:
      return NextResponse.next();
  }
}

export const config = { matcher: ['/((?!_next/static|favicon.ico).*)'] };
```

`detectBot()` also accepts a plain `{ method, url, headers }` object for
non-`Request` environments (Node HTTP, Express):

```typescript
const verdict = await wd.detectBot({
  method: req.method,
  url: `https://${req.headers.host}${req.url}`,
  headers: req.headers as Record<string, string>,
});
```

## Option B — the `webBotAuth()` rule

If you already use WebDecoy's rules engine, add `webBotAuth()` to your `rules`
array. It runs alongside your rate limits and tripwires and, by default, **denies
impersonation** — no branching code required. Verification happens automatically
before the rule evaluates.

```typescript
// middleware.ts
import { withWebDecoy } from '@webdecoy/nextjs';
import { webBotAuth, rateLimit } from '@webdecoy/node';

export default withWebDecoy({
  rules: [
    webBotAuth(),                       // deny agent impersonation
    rateLimit({ max: 100, window: 60 }),
  ],
});

export const config = { matcher: ['/api/:path*'] };
```

An impersonation attempt is denied with a `403` before it reaches your app. The
verdict is also surfaced on `ProtectResult.agent` for `withBotProtection`/manual
`protect()` callers.

### Rule options

```typescript
webBotAuth({
  onImpersonation: 'DENY',            // default; forged known-agent signature
  onClaimed: 'ALLOW',                 // default; unverifiable/unknown signer
  allowCategories: ['ai_crawlers'],   // optional: only these verified categories pass
  dryRun: false,                      // record the verdict but never block
});
```

- Set `onClaimed: 'DENY'` to require that **every** signed request come from an
  agent you trust (an unknown signer is then treated as a violation).
- `allowCategories` lets you accept, say, verified search engines but not
  AI crawlers — a verified agent outside the list is handled per `onClaimed`.

## Trusted directories (and why there's no SSRF)

Verification is **curated**: the SDK only ever fetches the well-known directories
of agents on an allowlist — never a URL taken from the incoming request's
`Signature-Agent` header. That means a hostile request can't make your
middleware fetch an arbitrary origin (no SSRF), and the warm path stays on
in-memory keys.

The default list tracks the agents that sign production traffic today (OpenAI
Operator, ChatGPT). Override it — for example to add your own signed crawlers —
via the constructor:

```typescript
const wd = new WebDecoy({
  webBotAuth: {
    directories: [
      { name: 'OpenAI', category: 'ai_crawlers', directory: 'https://operator.openai.com' },
      { name: 'Acme Crawler', category: 'monitoring', directory: 'https://crawler.acme.example' },
    ],
    cacheTtlMs: 6 * 60 * 60 * 1000, // stale-while-revalidate; default 6h
  },
});
```

A directory publishes its keys at
`/.well-known/http-message-signatures-directory` as a JWK Set (Ed25519 / OKP and
RSA supported). Keys are matched by their RFC 7638/8037 JWK thumbprint — the
value agents put in the signature's `keyid` — never by a mutable `kid` label.

## Runtime support

- **Vercel Edge Middleware / Cloudflare Workers** — verified against a real
  Vercel Edge Runtime VM in the SDK's test suite. Uses only `crypto.subtle`,
  `fetch`, `Request`/`Headers`, `URL`, and `atob` — no Node built-ins.
- **Node ≥ 18** — global `fetch` and WebCrypto Ed25519.

## How it relates to the platform

Local verification is free and needs no key. With a WebDecoy API key, verified
and impersonation verdicts also flow into your dashboard alongside TLS
fingerprinting, IP reputation, and detection analytics — so you can see *which*
agents visit and *who* tried to impersonate them over time.

## See also

- [`github.com/WebDecoy/web-bot-auth`](https://github.com/WebDecoy/web-bot-auth) — the underlying Go/TS profile
- [RFC 9421 — HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421)
- [IETF `webbotauth` working group](https://datatracker.ietf.org/wg/webbotauth/about/)
