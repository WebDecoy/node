---
'@webdecoy/node': minor
---

Add a monitor-first guard for native `node:http` servers. Evaluate requests and get a typed enforcement response without consuming the request body or trusting forwarded headers by default.
