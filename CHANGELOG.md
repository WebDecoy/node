# Changelog

All notable changes to the Web Decoy Node.js SDK will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
- Corrected repository URLs to `WebDecoy/node-sdk`
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

[Unreleased]: https://github.com/WebDecoy/node-sdk/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/WebDecoy/node-sdk/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/WebDecoy/node-sdk/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/WebDecoy/node-sdk/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/WebDecoy/node-sdk/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/WebDecoy/node-sdk/releases/tag/v0.1.0
