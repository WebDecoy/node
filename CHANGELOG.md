# Changelog

All notable changes to the Web Decoy Node.js SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.12.0] - 2026-08-22

### Fixed

- **The client IP is no longer taken from a header the client writes.** The Express and Next.js adapters read the leftmost `X-Forwarded-For` value and treated it as the caller's address. That value is supplied by the client on the first hop, so a single `-H 'X-Forwarded-For: 1.2.3.4'` bought a fresh rate-limit bucket per forged address, put an address of the caller's choosing on every violation reported to the dashboard, and reduced `filter({ expression: 'ip.tor or ip.vpn' })` to an opt-in check. The captcha endpoints in both adapters had the same flaw.

  Forwarding headers are now believed only as far as you say they should be, counted from the right of the chain — the end written by infrastructure you control.

  - New `trustProxy` option on every adapter and on the captcha endpoints: `false` (believe nothing), a number of trusted hops, `'cloudflare'` (use `CF-Connecting-IP`), or an array of CIDRs to walk past.
  - New exports from `@webdecoy/node`: `resolveClientIp()`, `normalizeIp()`, `ipInCidr()`, and the `TrustedProxies` type — so an application building its own `RequestMetadata` derives the same address the middleware does. Edge-safe: no `node:net`.
  - Addresses are normalised before use. Ports, brackets and IPv6 zone ids are stripped, IPv4-mapped IPv6 collapses to its IPv4 form so a dual-stack listener keys one client once, and anything that does not parse falls back to the peer address rather than becoming a key of its own.

### Changed

- **Behaviour change — read this if you run behind a proxy.**
  - **Express** now defers to `req.ip`, which honours the app's own `trust proxy` setting and otherwise resolves to the socket address. An app already configured with `app.set('trust proxy', …)` needs no change. An app behind a proxy that never configured Express will now attribute traffic to the proxy: set `trust proxy`, or pass `trustProxy` to the middleware.
  - **Next.js** reads the chain from the right and defaults to `1` trusted hop, which is correct on Vercel and on any single-proxy deployment. Edge middleware has no socket to fall back on, so there is no believe-nothing default available here. Behind a CDN in front of your platform, set `trustProxy: 2`; behind Cloudflare with the origin locked to it, `trustProxy: 'cloudflare'`.
  - **Fastify** is unchanged. It already deferred to `request.ip`, which was the safe answer; it gains the `trustProxy` option for parity.
  - `getIP` still overrides everything, and existing `getIP` implementations are untouched.

### Internal

- **Lint runs for the first time.** Every package declared `eslint` and `@typescript-eslint` as devDependencies and ran `eslint src/**/*.ts`, but no config file had ever existed in the tree, so `npm run lint` exited 2 in all five and had done since the repo was created. There is now one flat config at the root (ESLint 9, `typescript-eslint` 8), the duplicated per-package toolchain is gone, and CI runs lint so it cannot rot again. `no-explicit-any` is a warning under a per-package budget that CI does not let grow.

  Two client-side changes fell out of it and are worth knowing about:
  - `_measureJSExecution()` now accumulates its arithmetic loop into a recorded `mathSink` value, matching what the array loop already did with `arrayLen`. The loop previously discarded its result and could legally be optimised away entirely — which would drive `mathOps` toward zero and trip the "JS execution unusually fast" automation signal on an ordinary browser. It also reports `stringLen` for the same reason. Both are additive keys on an open record.
  - The `HTMLFormElement.prototype.submit` interception uses rest parameters and a closure instead of `arguments` and a `this` alias. Behaviour is unchanged — `submit()` takes no arguments.

## [0.11.1] - 2026-08-20

### Added
- **WebDecoyBot recognized in the bot registry.** The SDK now classifies WebDecoy's own first-party crawler — the User-Agent behind install verification and agent-readiness scans (`WebDecoyBot/1.0`, `+https://bot.webdecoy.com`) — as a known, low-threat monitoring crawler instead of an unknown bot. Generated from the shared Go registry; the cross-language parity test keeps it in lockstep with the server matcher.

## [0.11.0] - 2026-08-18

### Added
- **Local Web Bot Auth verification** (RFC 9421 HTTP Message Signatures, tag `web-bot-auth`).
  - `detectBot(request)` — verify an inbound request's agent signature and get a `verified` / `impersonation` / `claimed` / `none` verdict (with agent name/category for verified agents). Accepts a WHATWG `Request` or `{ method, url, headers }`.
  - `webBotAuth()` rule — denies impersonation of known agents in the rules engine by default; `onImpersonation` / `onClaimed` / `allowCategories` options.
  - Cached, curated directory client (Ed25519 + RSA-PSS-SHA512, JWK-thumbprint keyids); zero network on the warm path, no SSRF surface. Runs on Node and Vercel Edge / WinterCG runtimes.
  - New exports: `AgentVerifier`, `createAgentVerifier`, `DirectoryCache`, `DEFAULT_SIGNED_AGENT_DIRECTORIES`, and types `AgentVerdict`, `AgentStatus`, `AgentCategory`, `WebBotAuthConfig`, `AgentVerifierOptions`, `SignedAgentDirectory`.
- Doc: "Verify AI agents with Web Bot Auth in Next.js" (`docs/verify-ai-agents-web-bot-auth.md`).

## [0.10.0] - 2026-07-31

### Added
- **Honeytoken injection for Fastify.** Express and Next.js gained this in 0.8.x;
  Fastify still generated a token and left you to place the link. The plugin now
  injects a hidden trap link into HTML replies and arms the tripwire it points at.
  - On by default when `apiKey` is set; `honeytoken: false` opts out.
  - Injected in an `onSend` hook, so only full `text/html` replies are rewritten
    and Fastify recomputes `Content-Length`.
  - The token is derived from the API key, so every replica advertises and arms
    the same path.
  - **Streamed replies are not rewritten** — buffering a stream to insert an
    anchor would discard the streaming behaviour the app asked for. The plugin
    logs a warning once per process with the markup to embed manually, so the
    gap is visible rather than silent.

## [0.9.0] - 2026-07-31

### Added
- **Bot classification in the request path** — rules can now act on who the
  User-Agent says it is, synchronously and with no network call.
  - `bots()` rule: `bots({ categories: ['training_crawler'] })`,
    `bots({ ai: true, allow: ['perplexitybot'] })`,
    `bots({ agents: ['gptbot', 'ClaudeBot'], action: 'THROTTLE' })`.
  - New filter namespace: `bot.known`, `bot.ai`, `bot.category`, `bot.name`,
    `bot.id`, `bot.organization`, `bot.score`, `bot.respects_robots`.
  - New exports: `bots`, `BotRule`, `matchUserAgent`, `classifyUserAgent`,
    `BOT_REGISTRY`, `BOT_CATEGORIES`, and types `BotVerdict`, `BotAgent`,
    `BotCategory`, `BotRuleConfig`.
  - 168 known agents, matched locally. Category names match the
    `ai_scraper_category` values shown in your dashboard.
  - `ai: true` covers training crawlers, AI search crawlers, AI agents and AI
    assistants. It excludes `search_crawler` — blocking Googlebot would deindex
    your site.

  This matches a **self-declared** User-Agent, so it acts only on agents that
  identify honestly. That is the right tool for cooperative crawlers and the
  wrong one for anything spoofing a browser; use `tripwire()` for those.

## [0.4.0] - 2026-06-30

### Added
- Stealth-browser detection for botasaurus-class scrapers
- `F4` tripwire rule with honeytoken support — deterministic, zero-false-positive deception

### Fixed
- Dropped Playwright heuristics that false-positived on real Chrome

### Documentation
- Documented tripwire deception and the rules engine in the README

## [0.3.0] - 2026-05-31

### Added
- Self-hosted detection engine ported from FCaptcha (Phase 1)
- Captcha service with proof-of-work and token issuance (Phase 2)
- `@webdecoy/client` browser widget (Phase 3)
- Captcha HTTP endpoints and framework adapters (Phase 4)

### Changed
- Aligned client endpoint paths across the SDK
- Switched to a shields.io dynamic npm version badge
- Bumped CI `checkout`/`setup-node` actions to v5 (Node 24)

### Documentation
- Captcha docs, client README, and a runnable example

## [0.2.1] - 2026-05-29

### Fixed
- Corrected repository URLs to `WebDecoy/node`
- Updated CI to Node 20/22 and regenerated the lock file

### Changed
- Bumped all packages to 0.2.1
- Added the npm publish workflow
- Removed old planning docs

## [0.2.0] - 2026-02-08

### Added
- Rules engine with rate limiting, request filters, and violation reporting
- Contributing guide, changelog, and CI workflow
- Implementation summary and dashboard integration guide

### Fixed
- Workspace dependencies for npm compatibility

## [0.1.0] - 2025-11-26

### Added
- Initial release of `@webdecoy/node` core SDK
- Initial release of `@webdecoy/express` middleware
- Two-tier bot detection (local + server-side)
- TLS fingerprinting support (JA3/JA4)
- Express.js middleware integration
- TypeScript type definitions
- Basic Express example
- Comprehensive documentation

### Core Features (@webdecoy/node)
- Local analysis for suspicious headers
- Datacenter IP detection (AWS, GCP, Azure, etc.)
- User-Agent analysis for known bots
- Server-side verification API client
- Configurable threat score thresholds
- Fail-safe design (fail open on errors)
- Debug logging support

### Express Integration (@webdecoy/express)
- Middleware with automatic request protection
- Custom IP extraction
- Path skipping (health checks, static assets)
- Custom block handlers
- Custom error handlers
- Detection info attached to request object

### Documentation
- Main README with quick start
- Package-specific README files
- Express example with setup guide
- Contributing guidelines
- MIT License

[Unreleased]: https://github.com/WebDecoy/node/compare/v0.12.0...HEAD
[0.12.0]: https://github.com/WebDecoy/node/compare/v0.11.1...v0.12.0
[0.11.1]: https://github.com/WebDecoy/node/compare/v0.11.0...v0.11.1
[0.11.0]: https://github.com/WebDecoy/node/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/WebDecoy/node/compare/v0.9.0...v0.10.0
[0.4.0]: https://github.com/WebDecoy/node/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/WebDecoy/node/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/WebDecoy/node/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/WebDecoy/node/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WebDecoy/node/releases/tag/v0.1.0
