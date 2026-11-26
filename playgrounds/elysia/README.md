# WebDecoy and Elysia

This demo passes Bun's incoming requests through the WebDecoy Fetch guard
before Elysia handles them. The rules run in process and need no WebDecoy
account or API key. The server binds to loopback.

## Run locally

```sh
bun install --frozen-lockfile
bun run start
```

In a second terminal:

```sh
curl -i http://127.0.0.1:3000/
curl -i http://127.0.0.1:3000/demo-decoy
```

The ordinary route returns 200 and logs `ALLOW`. The demo path has no Elysia
route and returns Elysia's usual 404, while the guard logs `DENY` in monitor
mode. The decision changes the response only when enforcement is enabled.

Run `bun test` to verify both modes against a loopback server on an ephemeral
port. The demo uses the socket peer IP and trusts zero forwarding hops.
Configure trusted proxies deliberately if deploying behind a reverse proxy.
