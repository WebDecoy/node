# WebDecoy Express playground

[Open in StackBlitz](https://stackblitz.com/github/WebDecoy/node/tree/main/playgrounds/express?file=app.mjs)
· [Watch the 30-second demo](https://youtu.be/4jeuH3tKeos)

Send a real Express request, inspect the SDK's tripwire decision, and compare
monitoring with enforcement. No WebDecoy account or API key required. Browser
runtime startup and dependency installation may take a moment.

1. Open the preview and click **Send ordinary request**: HTTP200, `ALLOW`.
2. Click **Send decoy request**: HTTP404, `DENY`, `tripwire: true`.
3. Check **Enable enforcement for this demo**, then send the decoy again: HTTP403.
4. Send the ordinary request again: HTTP200.

The monitor response comes from our demo route; the enforce response comes from
the real SDK before that route runs. Status alone is not a detection receipt.

## Run locally

Requires Node.js 20+ and npm. Download this folder (it is standalone) or, from a
repository checkout:

```bash
cd playgrounds/express
npm ci --workspaces=false
npm run dev
```

Open `http://127.0.0.1:3000`. Run `npm test` for the real HTTP checks. The folder
pins published SDK packages and has its own lockfile, with no monorepo imports or
build step. If browser restrictions prevent WebContainers from starting, use
this local path; see [StackBlitz browser support](https://developer.stackblitz.com/platform/webcontainers/browser-support).

## What to bring to your app

See `app.mjs`: import `webdecoy` and `tripwire`, then mount middleware before your
routes. The two routers isolate the playground's monitor and enforce fixtures;
your real app should start with monitor mode. The preview renders actual JSON
responses with `textContent`; it does not generate synthetic SDK verdicts.

This is a controlled path-matching example. A hit does not establish malicious
intent: legitimate scanners and prefetchers may fetch decoys. Exposed verdicts
are for this demo; keep operational details server-side in your own app. This
keyless example does not send detections to the hosted dashboard or verify AI
agent identities.

[Full Express setup](https://docs.webdecoy.com/sdk-plugins/express/)
· [Separate AI-agent verification guide](https://github.com/WebDecoy/node/blob/main/docs/verify-ai-agents-web-bot-auth.md)
