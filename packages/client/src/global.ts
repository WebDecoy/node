/**
 * Standalone <script> entry point.
 *
 * Exposes `window.WebDecoyCaptcha`, auto-initializes any `[data-webdecoy]`
 * elements, and — given a `data-site-key` on the script tag — silently mints a
 * wd_clearance cookie for real browsers (closes the #124 decoy → deny loop in
 * monitor/allow-and-observe mode). Deferred to idle; no page-load cost.
 *
 *   <script src="webdecoy.global.js" data-site-key="ORG_ID"
 *           data-ingest="https://ingest.webdecoy.com" async></script>
 */

import { WebDecoyCaptcha } from './client';
import { startClearance } from './clearance';

// Capture the script tag before any async hop invalidates document.currentScript.
const selfScript = document.currentScript as HTMLScriptElement | null;

(window as unknown as Record<string, unknown>).WebDecoyCaptcha = WebDecoyCaptcha;

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => WebDecoyCaptcha.autoInit());
} else {
  WebDecoyCaptcha.autoInit();
}

const siteKey = selfScript?.getAttribute('data-site-key');
if (siteKey) {
  startClearance({
    siteKey,
    ingestUrl: selfScript?.getAttribute('data-ingest') || undefined,
    scope: selfScript?.getAttribute('data-scope') || undefined,
  });
}

export { WebDecoyCaptcha };
