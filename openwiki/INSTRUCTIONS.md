# WebDecoy Node SDK documentation brief

Document this repository as the canonical implementation guide for the WebDecoy Node.js SDK monorepo.

Prioritize:

- the core `@webdecoy/node` request, signal, rule, decision, reporting, and testing APIs;
- framework adapters for Express, Fastify, Next.js, and Hono, including runtime differences;
- monitor versus enforce behavior and how applications consume decisions;
- local and remote rules, rate-limit storage, proxy trust, edge-runtime compatibility, and error behavior;
- package relationships, public exports, build and release workflow, examples, and test strategy;
- integration contracts with WebDecoy ingest/backend services, including authentication and network boundaries;
- safe installation and verification workflows, preserving the operational cautions in `AGENTS.md`.

Accuracy rules:

- Treat implementation, exports, tests, and package manifests as primary evidence.
- Use README, `llms.txt`, existing docs, examples, and changelog as supporting context; reconcile them against current code.
- Clearly distinguish stable public APIs from internal helpers and deprecated compatibility surfaces.
- Never reproduce secrets, credentials, local environment values, or generated artifacts.
- Do not create one page per file or package. Organize pages around concepts, integration workflows, and maintainer tasks.
- Use Mermaid only where a request lifecycle or package dependency relationship is materially clearer as a diagram.

The navigation should let a new adopter find installation and framework guidance quickly while giving maintainers deeper architecture, testing, compatibility, and release documentation.
