# Verify signed AI-agent requests in Next.js and Node.js

A familiar User-Agent name is a claim. For supported signed requests,
`@webdecoy/node` can check a cryptographic signature against keys from configured
trusted agent directories and return a verdict you can inspect in your app.
Local verification needs no WebDecoy API key.

This guide covers the SDK's supported `web-bot-auth` signature profile, built on
[RFC 9421 HTTP Message Signatures](https://www.rfc-editor.org/rfc/rfc9421).
Signing support and request coverage vary by agent. An unsigned request is not
proof of a human, and a valid signature is not permission to access a route.

## Run the proof first

The [standalone signed-agent example](../playgrounds/signed-agent/README.md)
generates a demo Ed25519 key, signs real request components and runs the
published SDK verifier. It prints these controlled results:

| Request | SDK status | Reason |
| --- | --- | --- |
| Valid signature from the demo trusted key | `verified` | — |
| Covered target URL changed after signing | `impersonation` | `bad-signature` |
| Trusted-key signature outside its validity window | `impersonation` | `expired` |
| Signature from an unknown key | `claimed` | `unknown-key` |
| No signature | `none` | — |

```bash
cd playgrounds/signed-agent
npm ci --workspaces=false
npm run dev
npm test
```

Requires Node.js 20+. No monorepo build or API key is needed. Only the directory
response is supplied by an injected fixture containing the generated public
key. Signing and verification are real; SDK verdicts are not mocked. These are
not captured requests from OpenAI, Google or another provider, and this is not
a complete protocol-conformance or production-accuracy test.

## Understand the verdict

- **`verified`:** the signature validates against a key in the configured trusted
  directories. The result includes the agent name, category and key ID.
- **`impersonation`:** a known-key signature did not pass verification or its
  validity checks. Inspect `reason` before deciding how to respond.
- **`claimed`:** the signature cannot be verified with the available keys or
  supported format. An unknown signer is not proof of abuse.
- **`none`:** no applicable signature was recognized. Other detection and policy
  checks still apply.

`impersonation` is the SDK's classification. An expired signature or a modified
covered component can also reflect clock or proxy issues. It does not, by
itself, establish the requester's intent.

## Observe in Next.js middleware

Install the core SDK:

```bash
npm install @webdecoy/node
```

Start by recording the outcome without changing route access:

```typescript
// middleware.ts
import { NextRequest, NextResponse } from 'next/server';
import { WebDecoy } from '@webdecoy/node';

const wd = new WebDecoy({});

export async function middleware(req: NextRequest) {
  const verdict = await wd.detectBot(req);
  console.info('agent verification', {
    status: verdict.status,
    reason: verdict.reason,
    agent: verdict.agentName,
  });
  return NextResponse.next();
}

export const config = { matcher: ['/api/:path*'] };
```

`detectBot()` returns evidence; it does not block a request. Keep authorization,
rate limits and your existing edge protection in place. After observing legitimate
traffic, decide which outcomes your application should deny, challenge or allow.

For custom Node.js handlers, the same API accepts
`{ method, url, headers }`. Use the original absolute request URL and covered
header values. Reconstructing the wrong public scheme, host, port or path behind
a proxy can invalidate a signature; accept forwarding information only from
proxies you actually trust.

## Use the verdict in the rules engine

If you already use the Next.js adapter:

```bash
npm install @webdecoy/nextjs @webdecoy/node
```

```typescript
import { withWebDecoy } from '@webdecoy/nextjs';
import { webBotAuth, rateLimit } from '@webdecoy/node';

export default withWebDecoy({
  rules: [webBotAuth(), rateLimit({ max: 100, window: 60 })],
});

export const config = { matcher: ['/api/:path*'] };
```

The middleware starts in **monitor mode**. `webBotAuth()` returns a denial for
known-key verification failures by default, but a denial verdict does not itself
mean an HTTP403 response in monitor mode. Inspect `req.webdecoyDecision` in
supported handlers. Switch to `mode: 'enforce'` only after reviewing your traffic.
The in-memory rate limit is per process; use a shared store across replicas.

```typescript
webBotAuth({
  onImpersonation: 'DENY',
  onClaimed: 'ALLOW',
  // Optional: decide which verified categories this rule accepts.
  allowCategories: ['ai_crawlers'],
});
```

A verified agent outside `allowCategories` is handled according to `onClaimed`.
With the default `onClaimed: 'ALLOW'`, that list is not a blocking policy. Set
policy options deliberately rather than treating category labels as permissions.

## Trust and directory fetching

The SDK fetches keys from configured directory URLs. It does not choose a fetch
target from the incoming request's `Signature-Agent` header. Keep that trusted
list under application control.

```typescript
import { WebDecoy, DEFAULT_SIGNED_AGENT_DIRECTORIES } from '@webdecoy/node';

const wd = new WebDecoy({
  webBotAuth: {
    directories: [...DEFAULT_SIGNED_AGENT_DIRECTORIES],
    fetchTimeoutMs: 5000,
  },
});
```

Passing `directories` replaces the defaults. A cold lookup can await directory
fetching; cached keys are reused and stale caches may refresh in the background.
Do not promise zero network traffic for every verification. Directory reachability
and key availability affect which requests can be verified.

No latency or detection-accuracy claim is established by the local example.
The Node.js fixture uses Node's crypto module to generate signatures; it does
not establish browser or edge-runtime compatibility for every provider's profile.

## Keep identity and permission separate

WebDecoy complements Cloudflare and other edge protections. A signature check
at the app can inspect only requests reaching that middleware. Verification does
not give an agent permission to scrape, purchase, create an account or bypass
your rate limits. It also does not establish that a person is present or that
an AI system cited your site.

Local outcomes are separate from hosted dashboard reporting. Configuring an API
key enables platform features; keyless `detectBot()` output is not evidence of
a cloud detection.

## References and next steps

- [HTTP Message Signatures, RFC 9421](https://www.rfc-editor.org/rfc/rfc9421)
- [IETF Web Bot Auth working group](https://datatracker.ietf.org/wg/webbotauth/about/)
- [Cloudflare's Web Bot Auth integration profile](https://developers.cloudflare.com/bots/reference/bot-verification/web-bot-auth/)
- [SDK verifier implementation](../packages/webdecoy/src/agent/verifier.ts)
- [Interactive Express tripwire playground](../playgrounds/express/README.md)
