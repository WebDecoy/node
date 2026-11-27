---
'@webdecoy/node': minor
'@webdecoy/fastify': patch
'@webdecoy/hono': patch
---

Give every reported rule violation a unique `eventId` so ingest stores it once even when a batch is delivered twice. Deliver buffered violations before a process exits: the reporter now holds the process open for at most one flush interval when events are waiting, `fastify.close()` sends what the plugin still holds, and the Hono middleware passes `executionCtx.waitUntil` to the reporter on Workers. `FetchGuard.check()` accepts an optional lifecycle with `waitUntil`.
