# See a WebDecoy tripwire work in Express

Run a local server, compare an ordinary request with a controlled decoy request,
and inspect the verdict before choosing to block. Local rules need no account
or API key. This demo starts in monitor mode and binds to `127.0.0.1`.

## Run from this repository

Requires Node.js 20+ for the verification tests. From the repository root:

```bash
npm ci
npm run build -w @webdecoy/node -w @webdecoy/express
npm run dev -w webdecoy-express-example
```

## Compare two requests

In another terminal:

```bash
curl -i http://127.0.0.1:3000/
curl -i http://127.0.0.1:3000/demo-decoy
```

| Request | Monitor-mode HTTP response | Local decision |
| --- | --- | --- |
| `/` | `200` | `ALLOW`, `tripwire: false` |
| `/demo-decoy` | `404`, from the demo route | `DENY`, `tripwire: true` |

The second request is deliberately made by you. It demonstrates that a selected
path matched a rule, not that a malicious AI bot was identified. The `404` alone
is not a detection receipt: inspect the `decision` JSON, which comes from
`req.webdecoyDecision`.

## Opt into enforcement on this local demo

Stop the server with Ctrl+C, then restart it:

```bash
WEBDECOY_MODE=enforce npm run dev -w webdecoy-express-example
```

Repeat the two requests. `/` remains `200`; `/demo-decoy` returns `403` before
the demo route runs. Restart without that variable to return to monitor mode.

Run the HTTP checks without a browser or API key:

```bash
npm test -w webdecoy-express-example
```

## Use it on your own app

The example keeps one controlled decoy path and exposes summaries in local
responses for verification. In production, keep verdicts in server-side logs,
choose decoy paths outside legitimate user flows, and review scanners,
prefetchers and accessibility flows before enforcing. Changing a User-Agent
does not prove that a client is malicious or human.

Behind a proxy, configure the documented `trustProxy` setting for your actual
topology; never trust arbitrary forwarded headers. This example does not
collect JA4, identify every AI agent, or report to the cloud dashboard.

[Express setup documentation](https://docs.webdecoy.com/sdk-plugins/express/?utm_source=github&utm_medium=example&utm_campaign=express_tripwire_proof)
· [Optional WebDecoy dashboard](https://app.webdecoy.com/?utm_source=github&utm_medium=example&utm_campaign=express_tripwire_proof)
