# What reaches your Astro SSR origin?

This local playground uses Astro's Node adapter in middleware mode, Fastify and the WebDecoy Node SDK. It shows what server-side request monitoring can observe. It runs on loopback with synthetic requests and requires no account or API key.

## Run it

Use Node 22.23.4 or later.

```sh
cd playgrounds/astro-fastify
npm ci
npm test
npm start
```

Visit <http://127.0.0.1:4321/>. The built Astro app renders an HTML page on demand and Fastify records an `ALLOW` decision in the terminal. Then visit <http://127.0.0.1:4321/lab/check/>. The synthetic tripwire records `DENY` while the route still serves its ordinary HTTP 404. The verdict and HTTP response answer different questions. Monitor mode keeps the application's response.

## Verify the coverage boundary

The test suite also puts a small HTTP server in front of the SSR origin. It reads the prerendered snapshot from Astro's build output and serves it without contacting Fastify. That request creates no origin decision. A request forwarded to the SSR route creates one. This models an upstream cache hit without using a CDN or sending real traffic.

The example intentionally serves only the two origin routes. A production app needs its own static file handling and safe proxy configuration. The output is limited to the HTTP method, registered route, rule conclusion and tripwire result. The sample has no cloud integration. In a connected installation, reporting requires an authorized server-side site key and a verified receipt in the associated tenant.

[Back to the WebDecoy Node SDK](../../README.md)
