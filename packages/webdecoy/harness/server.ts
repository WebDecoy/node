/**
 * Live stealth-detection harness server.
 *
 * Serves a page that loads the REAL built @webdecoy/client bundle, collects
 * signals in whatever browser (or bot) loads it, and scores them with the REAL
 * DetectionEngine. Unlike fixtures.ts, the signals here come from an actual
 * client — this is the ground-truth path for a real botasaurus run.
 *
 *   npx tsx harness/server.ts            # then open http://localhost:8787
 *
 *   GET  /            -> page.html (browser mode: runs the collector)
 *   POST /score       -> score posted signals, return verdict JSON (+ log)
 *   GET  /probe       -> request-mode path: score UA+headers only (no JS)
 */

import { createServer, type IncomingHttpHeaders } from 'http';
import { readFileSync } from 'fs';
import { join } from 'path';
import { DetectionEngine } from '../src/detection/engine';
import type { Signals } from '../src/detection/types';

const PORT = Number(process.env.PORT ?? 8787);
const HERE = __dirname;
const BUNDLE = join(HERE, '../../client/dist/webdecoy.global.js');
const engine = new DetectionEngine({ requirePoW: false });

function lower(h: IncomingHttpHeaders): Record<string, string> {
  const o: Record<string, string> = {};
  for (const k of Object.keys(h)) o[k.toLowerCase()] = Array.isArray(h[k]) ? (h[k] as string[]).join(',') : String(h[k] ?? '');
  return o;
}

function score(signals: Signals, userAgent: string, headers: Record<string, string>, label: string) {
  const v = engine.score(signals, { ip: '203.0.113.10', siteKey: 'harness', userAgent, headers });
  const triggered = v.detections
    .filter((d) => d.score > 0)
    .sort((a, b) => b.score * b.confidence - a.score * a.confidence);
  const env = (signals.environmental ?? {}) as Record<string, unknown>;
  const stealthHits = triggered.filter((d) => ['stealth', 'headless', 'cdp', 'automation', 'fingerprint'].includes(d.category));

  console.log(`\n${'-'.repeat(70)}`);
  console.log(`[${label}]  score=${(v.score * 100).toFixed(0)}%  ->  ${v.recommendation.toUpperCase()}`);
  console.log(`  UA: ${userAgent.slice(0, 90)}`);
  console.log(`  environment/stealth detections:`);
  if (stealthHits.length === 0) console.log('    (none — looks like a genuine browser)');
  for (const d of stealthHits) console.log(`    [${d.category.padEnd(11)}] ${(d.score * 100).toFixed(0)}%  ${d.reason}`);
  if (env.lieDetection) console.log(`  lieDetection raw:`, JSON.stringify(env.lieDetection));
  return { score: v.score, recommendation: v.recommendation, detections: triggered };
}

const server = createServer((req, res) => {
  const url = req.url ?? '/';
  const method = req.method ?? 'GET';

  if (method === 'GET' && (url === '/' || url.startsWith('/?'))) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8' });
    res.end(readFileSync(join(HERE, 'page.html')));
    return;
  }
  if (method === 'GET' && url === '/webdecoy.global.js') {
    res.writeHead(200, { 'content-type': 'application/javascript' });
    res.end(readFileSync(BUNDLE));
    return;
  }
  if (method === 'GET' && url.startsWith('/probe')) {
    const headers = lower(req.headers);
    const result = score({ meta: {} }, headers['user-agent'] ?? '', headers, 'REQUEST MODE (/probe, no JS)');
    res.writeHead(200, { 'content-type': 'application/json' });
    res.end(JSON.stringify(result, null, 2));
    return;
  }
  if (method === 'POST' && url === '/score') {
    let body = '';
    req.on('data', (c) => (body += c));
    req.on('end', () => {
      try {
        const payload = JSON.parse(body || '{}');
        const headers = lower(req.headers);
        const ua = payload.userAgent || headers['user-agent'] || '';
        const result = score(payload.signals ?? {}, ua, headers, payload.label ?? 'BROWSER MODE (/score)');
        res.writeHead(200, { 'content-type': 'application/json' });
        res.end(JSON.stringify(result, null, 2));
      } catch (e) {
        res.writeHead(400);
        res.end(String(e));
      }
    });
    return;
  }
  res.writeHead(404);
  res.end('not found');
});

server.listen(PORT, () => {
  console.log(`\nWebDecoy stealth harness listening on http://localhost:${PORT}`);
  console.log(`  browser mode:  open http://localhost:${PORT}/  in a browser (or botasaurus)`);
  console.log(`  request mode:  GET http://localhost:${PORT}/probe`);
});
