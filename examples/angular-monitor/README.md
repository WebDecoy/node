# Observe Angular SSR traffic with WebDecoy

A runnable Angular 22 SSR application using published `@webdecoy/express` and
`@webdecoy/node` 0.18.0. This is WebDecoy's request middleware, not FCaptcha.

## Run the production server locally

Use a current Node release supported by Angular 22 (tested with Node 26.5).
The nested app intentionally installs published packages independently of the
SDK monorepo's workspaces:

```sh
cd examples/angular-monitor/app
npm ci --workspaces=false
npm run build
npm test
npm run serve
```

Open http://127.0.0.1:4300 and click **Load public catalog**. The server logs a
`webdecoy-decision` record. Start with no API key for an entirely local demo.
Do not use `ng serve` to verify production middleware placement: build and run
the emitted Node server as above.

## Prove the pipeline

```sh
curl -i http://127.0.0.1:4300/api/products
curl -i http://127.0.0.1:4300/.env
curl -i -A 'WebDecoy-Test/1.0' http://127.0.0.1:4300/api/products
```

- Catalog: 200 with two public demo items.
- Tripwire: terminal says `DENY`, `tripwire: true`, `wouldBlock: true`; HTTP stays
  404 because monitor mode preserves the application's response. There is no
  real `.env` file at this route.
- Reserved test: terminal labels `testTrigger: true`. Without a key,
  `dashboardConfigured: false` and `reportingError: true` explicitly show that
  nothing was reported. The catalog still returns 200 in monitor mode.

The per-process rate rule is 60 requests per 60 seconds. Monitor mode records
its denials without returning 429. It includes page/API requests, not actual
static assets or the health endpoint. This low limit is for learning, not a
production recommendation.

## Optional dashboard connection

Set `WEBDECOY_API_KEY` in your **server environment**, using your own key from
https://app.webdecoy.com. Restart, then send the reserved test request again.
Check the dashboard for the labelled test event and check for reporting errors.
A configured key alone does not prove delivery. Never put the key in Angular
configuration, a component, an HTTP interceptor, or a browser bundle. The SDK
can send request metadata when a key is supplied; use your own test traffic.
No cloud credentials or dashboard delivery are included in automated tests.

## Architecture and scope

`src/server.ts` mounts WebDecoy before both the API and AngularNodeAppEngine.
Only real static files and `/health` bypass the middleware. Server routes use
`RenderMode.Server`. If a CDN serves prerendered HTML without reaching Node,
this middleware cannot observe that request. Protect a separately hosted API
in its own backend as well.

The Angular component uses standalone APIs, `inject(HttpClient)`, signals and
`@for`. Its browser code contains no WebDecoy key or security decision logic.
The sample uses no browser globals or HTML honeytoken injection, so it avoids
adding DOM mutations during hydration. `honeytoken: false` is explicit.

The demo logs limited structured decisions, not IPs, query strings, headers,
tokens or bodies. These are rule outcomes, not proof of a visitor's identity or
intent. Monitor mode never means a request was blocked. SDK errors fail open
by default; authentication and authorization remain the application's job.

## Deployment considerations

The sample binds to loopback and trusts no forwarding headers. Configure trusted
proxies for your actual deployment; don't blindly trust arbitrary X-Forwarded-For.
Keep in-process rate limits to one process, or use a shared store across replicas.
Observe representative traffic before deciding whether to switch to enforcement.
If you do, make the mode change explicit and test legitimate clients too.

Tests exercise the built production server: SSR HTML, catalog availability,
tripwire receipts, the reserved trigger and rate-limit observation. They do not
measure detection accuracy or verify cloud reporting.
