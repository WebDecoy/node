---
type: adoption quickstart
title: WebDecoy Node SDK Quickstart and Documentation Map
description: Install the WebDecoy package that matches an application's runtime, start with keyless local rules in monitor mode, and verify a visible decision before enforcing. Use the routing map to find detailed guidance for adapters, rules, platform services, captcha, operations, testing, and maintenance.
tags: [webdecoy, quickstart, installation, node-sdk, monitoring, framework-adapters]
verified:
  - by: openwiki/0.4.3
    at: 2026-08-28T15:55:55.028Z
sources:
  - id: openwiki-source-1a6972c3f3823f18b8dcd3d7
    resource: repo://packages/express/package.json
  - id: openwiki-source-8f7e5cd79c42ec2cd52dd899
    resource: repo://packages/express/src/index.ts
  - id: openwiki-source-761c69d9cd483de91dfad2be
    resource: repo://packages/express/src/middleware.ts
  - id: openwiki-source-227b749653efc43996e6c8a7
    resource: repo://packages/fastify/package.json
  - id: openwiki-source-56273319a65bb37863fa4a22
    resource: repo://packages/fastify/src/index.ts
  - id: openwiki-source-5e591d9213de4da308715d91
    resource: repo://packages/hono/package.json
  - id: openwiki-source-efa1678dbd645afa1ab342c9
    resource: repo://packages/hono/src/index.ts
  - id: openwiki-source-0ce52cdad3703194898900ac
    resource: repo://packages/nextjs/package.json
  - id: openwiki-source-7eecb1f330e55e75d2a290c1
    resource: repo://packages/nextjs/src/index.ts
  - id: openwiki-source-be9a1d5de59128a61e54b944
    resource: repo://packages/webdecoy/package.json
  - id: openwiki-source-904cc07726251ca5837e405c
    resource: repo://packages/webdecoy/src/decision.ts
  - id: openwiki-source-cae18997a46bb069be01eb86
    resource: repo://packages/webdecoy/src/rules/attack-signatures.ts
  - id: openwiki-source-231ad040b0b500c93a55493c
    resource: repo://packages/webdecoy/src/rules/rate-limit-rule.ts
  - id: openwiki-source-558977e725f0b1e1ca7b5997
    resource: repo://packages/webdecoy/src/sdk.ts
  - id: openwiki-source-778b888fbcba0e9011ba7137
    resource: repo://packages/webdecoy/src/test-trigger.ts
  - id: openwiki-source-cb5ba9ca28a4bd36736e8439
    resource: repo://packages/webdecoy/src/testing.ts
generated: { by: "openwiki/0.4.3", at: "2026-08-28T15:55:55.028Z" }
---

# WebDecoy Node SDK Quickstart and Documentation Map

This page is the safe first path for adding WebDecoy. Start with a framework adapter (or the fetch guard), make a **keyless local-rule** installation, confirm that it produces a visible decision, and observe real traffic in monitor mode. Do not turn on enforcement, add broad payload inspection, or invent credentials as part of first setup.

## 1. Pick the boundary package

Install the package that owns the boundary where requests enter the application. The adapter packages depend on `@webdecoy/node`, so an adapter install brings in the core SDK; install `@webdecoy/node` directly when the application has no supplied adapter or when it needs core rules/types explicitly.

| Application boundary | Install | Primary entrypoint |
| --- | --- | --- |
| Express | `npm install @webdecoy/express` | `webdecoy()` middleware |
| Fastify | `npm install @webdecoy/fastify` | default Fastify plugin or `webdecoyPlugin` |
| Next.js | `npm install @webdecoy/nextjs` | `withWebDecoy()` in `middleware.ts` |
| Hono on Workers, Bun, Deno, or Node | `npm install @webdecoy/hono` | `webdecoy()` middleware |
| Another WHATWG fetch runtime | `npm install @webdecoy/node` | `createFetchGuard()` |
| Browser captcha or browser signals | `npm install @webdecoy/client` | browser widget/client API, paired with server captcha endpoints |

The repository supports Node `>=18`. For Express and Fastify, the adapter peer dependencies support the current major versions declared in their package manifests. Do not deep-import `dist` or repository source paths: use the published package entrypoints instead. See [Package Architecture, Public Surfaces, and Runtime Boundaries](/openwiki/architecture/packages-and-runtime-boundaries.md) for the supported surfaces and Node/edge/browser boundaries.

## 2. First install: local rules, monitor mode, no key

The following Express setup is a conservative baseline. It needs no WebDecoy account or API key: `tripwire()` and the in-process `rateLimit()` evaluate locally. Place WebDecoy after the body parser your application needs and before protected routes. `skipPaths` bypasses the whole protection boundary, so reserve it for deliberate exemptions such as health and metrics endpoints.

```typescript
import express from 'express';
import { webdecoy } from '@webdecoy/express';
import { rateLimit, tripwire } from '@webdecoy/node';

const app = express();

app.use(express.json());
app.use(webdecoy({
  rules: [
    tripwire(),
    rateLimit({ max: 100, window: 60 }),
  ],
  skipPaths: ['/health', '/metrics'],
  // mode defaults to 'monitor'; leave it there for the initial rollout.
}));

// Make monitor-mode decisions visible while the application still serves traffic.
app.use((req, _res, next) => {
  const decision = req.webdecoyDecision;
  if (decision && decision.conclusion !== 'ALLOW') {
    console.log('WebDecoy decision', {
      conclusion: decision.conclusion,
      reason: decision.reason,
      results: decision.results,
    });
  }
  next();
});

app.get('/', (_req, res) => res.send('ok'));
app.listen(3000);
```

`mode: 'monitor'` is the default deliberately. The adapter evaluates and exposes the full decision but continues to the application even for a denial or throttle. In Express, use `req.webdecoyDecision` for the typed verdict; `req.webdecoy` is a legacy, narrower detection payload. Once traffic and rule outcomes have been reviewed, `mode: 'enforce'` makes a rule denial a 403 and a throttle a 429 with `Retry-After` unless a blocking callback replaces the response.

**Do not provide a fabricated API key.** An absent key is a valid local-only installation. If hosted detection, IP enrichment, dashboard telemetry, or automatic supported-adapter honeytokens are needed later, obtain a real server credential from [https://app.webdecoy.com](https://app.webdecoy.com) and put it in the deployment's server-side secret configuration—not source code or browser code. In particular, `filter()` needs API-key-backed IP enrichment; without it, an IP-dependent filter is `NOT_RUN`, not an effective local control.

### Configure real client identity before relying on IP limits

Rate limits, IP filters, reports, and captcha IP binding are only as correct as the resolved client address. A direct Express server can use the socket-derived default. Behind a proxy, configure the actual deployment topology before trusting an IP-keyed limit. For example, when **exactly one controlled proxy** sits in front of the Express app:

```typescript
app.set('trust proxy', 1);
```

Alternatively, pass WebDecoy's `trustProxy` option, or use controlled proxy CIDRs for a variable topology. Never trust a client-provided leftmost `X-Forwarded-For` value. A missing proxy configuration collapses visitors into the proxy's address and can make a per-IP rate limit apply site-wide; an over-broad configuration lets callers influence their apparent address. Read [Client Identity, Proxy Trust, Characteristics, and Edge Context](/openwiki/concepts/client-identity-proxy-trust-and-edge-context.md) before enforcing IP-based policy.

### Treat local state as local

The baseline rate limiter is in process memory. It is appropriate for one process, but each replica or cold start has its own counter: a fleet's effective allowance can become `max × instances`. Before running multiple replicas, use a shared `RateLimitStore`, such as `upstashRateLimitStore()`, and choose/test its failure policy. The detailed configuration and failure modes are in [Rules, Shared State, Honeytokens, and Attack-Signature Boundaries](/openwiki/concepts/rules-rate-limits-and-deception.md) and [Production Rollout, Security Posture, and Operational Failure Modes](/openwiki/operations/production-rollout-and-safety.md).

## 3. Verify a visible result

An installation is not complete merely because the server starts. Run one of these deliberate checks and retain the result in application logs or an integration record.

### Reserved installation probe

```bash
curl -A "WebDecoy-Test/1.0" http://localhost:3000/
```

`WebDecoy-Test/` is a reserved User-Agent handled before normal rules. It creates a labeled test-trigger decision through the real detection path when a real API key is configured; the service treats that traffic as test traffic rather than ordinary stats/billing/enforcement. In monitor mode the request still reaches the application, so the logging middleware above is the local visible receipt. Without an API key, the SDK still returns a labeled denial and explicitly reports that no dashboard report could be made—do not claim a dashboard receipt in that case.

Use this probe once for installation verification, not in unit tests, load tests, uptime checks, or normal synthetic traffic.

### Controlled ordinary tripwire

With the baseline `tripwire()`, run:

```bash
curl -i http://localhost:3000/.env
curl -i http://localhost:3000/
```

In monitor mode, `/.env` should produce the logged `DENY` decision while the application still receives the request; the normal route should remain unaffected. In a later, scoped enforce-mode canary, the same trap request should return 403. Do not use a trap path that could be reached by normal navigation, an expected security scanner, a prefetcher, or a link-preview service without observing it first.

## 4. Expand deliberately

The quickstart is intentionally narrow. Choose the next task below rather than treating every exported API as a first-install requirement.

| If the next task is… | Read this page | Why it comes next |
| --- | --- | --- |
| Understand the outcome that middleware exposes or enforce safely | [Request Protection, Decisions, and Enforcement Semantics](/openwiki/concepts/request-decisions-and-enforcement.md) | Explains `ALLOW`, `DENY`, `CHALLENGE`, `ERROR`, monitor/enforce separation, rule states, caching, and fail-open errors. |
| Integrate Express, Fastify, Next.js, Hono, or a generic fetch handler | [Framework Adapters and Fetch Runtime Integration](/openwiki/integrations/framework-adapters.md) | Covers registration order, native decision surfaces, blocking callbacks, skip paths, proxy defaults, and response behavior. |
| Add rate limits, tripwires/honeytokens, bot policy, filters, or signatures | [Rules, Shared State, Honeytokens, and Attack-Signature Boundaries](/openwiki/concepts/rules-rate-limits-and-deception.md) | Covers ordered rule evaluation, shared stores, bot-policy limits, dry runs, and safe honeytoken arming. |
| Manage AI crawlers or verify a claimed AI-agent identity | [Bot Classification, Robots Policy, and Web Bot Auth](/openwiki/concepts/bot-identity-policy-and-web-bot-auth.md) | Separates self-declared User-Agent policy and `robots.txt` from cryptographic Web Bot Auth verification. |
| Add hosted detection, enrichment, reports, or browser clearance | [WebDecoy Ingest, Enrichment, Reporting, and Network Contracts](/openwiki/integrations/webdecoy-platform-and-network-contracts.md) | Defines which calls are authenticated, when a request reaches the network, caches, timeouts, and telemetry failure behavior. |
| Add self-hosted captcha or make browser signals influence a later request | [Self-Hosted Captcha and Browser-Signal Decision Flow](/openwiki/concepts/captcha-and-browser-signals.md) | Covers endpoint mounting, proof-of-work/token lifecycle, score handoff, and shared persistence requirements. |
| Roll out to production or add replicas | [Production Rollout, Security Posture, and Operational Failure Modes](/openwiki/operations/production-rollout-and-safety.md) | Provides the monitor-to-enforce runbook, proxy checks, shared-state requirements, observability, and shutdown guidance. |
| Test the application's policy without live traffic | [Testing Strategy, Application Harnesses, and Cross-Package Invariants](/openwiki/testing/application-and-repository-tests.md) | Shows the offline `@webdecoy/node/testing` harness and how to select framework-level tests. |
| Change SDK code, builds, edge-compatible imports, or publish a release | [Monorepo Build, CI, Edge Checks, and npm Release](/openwiki/operations/build-test-and-release.md) | Documents Turbo commands, focused validation, CI gates, edge checks, and tag-triggered publication. |

### Keep attack signatures narrow

`attackSignatures()` is a compact curated detector for unambiguous injection payloads; **it is not a WAF**. Its default inspection surface is path and query. If a future policy needs body or header inspection, start with `dryRun: true` and review real traffic before enforcement—CMS content, URLs embedded in fields, and application data can resemble attack text. The rules page above explains its byte bounds, cookie exclusion, and safe rollout.

## 5. Add an offline policy test

Use the public testing subpath to make the first protection policy executable. It creates a fresh SDK with isolated in-memory rule state and suppresses an API key unless `allowNetwork: true`, so unit tests do not accidentally file real detections.

```typescript
import { tripwire } from '@webdecoy/node';
import {
  createTestHarness,
  expectAllowed,
  expectDenied,
  get,
} from '@webdecoy/node/testing';

const wd = createTestHarness({ rules: [tripwire()] });

test('a scanner is denied and an ordinary route is allowed', async () => {
  expectDenied(await wd.protect(get('/.env')), { rule: 'tripwire' });
  expectAllowed(await wd.protect(get('/')));
});
```

Assert the typed conclusion and relevant rule outcome, not only `decision.allowed`: an `ERROR` is allowed for availability but means no verdict was reached. For rate limits, create a harness per test so counters do not leak between cases, then use `protectMany()` to cross the configured boundary without sleeping.

## First-install checklist

- [ ] Installed the adapter for the actual request boundary (or `@webdecoy/node` for a fetch handler).
- [ ] Mounted protection after required body parsing and before protected routes.
- [ ] Kept the initial deployment in `mode: 'monitor'`.
- [ ] Did not invent, commit, or expose an API key; local rules work without one.
- [ ] Configured framework or adapter proxy trust to match the deployed ingress path before enforcing IP-keyed controls.
- [ ] Ran one visible installation probe or controlled tripwire check and recorded what happened.
- [ ] Confirmed a normal route remains unaffected in monitor mode.
- [ ] Chosen a shared rate-limit store before scaling beyond one process.
- [ ] Added an offline rule-policy test.
- [ ] Reviewed the production rollout guide before switching any scope to enforce.
