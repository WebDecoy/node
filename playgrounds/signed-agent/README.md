# Verify an AI-agent signature locally

A reproducible cryptographic example for `@webdecoy/node`. Generate a demo key,
sign a request, and inspect how verification changes when a covered URL is
modified, the signature expires, the signer is unknown, or no signature exists.

This is a Node.js console example, not a server or hosted browser UI.

```bash
cd playgrounds/signed-agent
npm ci --workspaces=false
npm run dev
npm test
```

Requires Node.js 20+. The standalone folder pins the published SDK and needs no
WebDecoy account, API key, or monorepo build.

| Controlled scenario | SDK status | Reason |
| --- | --- | --- |
| Signature matches the generated trusted key | `verified` | — |
| Covered target URL changed after signing | `impersonation` | `bad-signature` |
| Trusted-key signature is outside its validity window | `impersonation` | `expired` |
| Actual signature from a key absent from the trusted directory | `claimed` | `unknown-key` |
| Request carries no signature | `none` | — |

`proof.mjs` runs real Ed25519 signing and SDK verification. Only the trusted
**public-key directory response** is supplied by an injected local fixture;
the SDK verifier and its verdicts are not mocked. The demo private keys are
generated in memory, never printed or saved. No request to an AI provider is made.

The demo signs `@method`, `@target-uri`, and `signature-agent` with the
`web-bot-auth` tag. It sets zero clock tolerance to make the expired case explicit;
production SDK defaults differ. This fixture exercises the SDK's supported
signature profile, not all RFC 9421 variants or every agent implementation.

A verified signature is evidence of a trusted signing key and its covered
request components. Your authorization, rate limits and abuse policy still
apply. The SDK's `impersonation` label is a failed known-key verification result;
expiration or changed components can also come from clock or proxy issues and
do not alone establish malicious intent.

[Next.js integration and verdict guide](../../docs/verify-ai-agents-web-bot-auth.md)
· [Interactive Express tripwire playground](../express/README.md)
· [WebDecoy Node SDK](https://github.com/WebDecoy/node)
