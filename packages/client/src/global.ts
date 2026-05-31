/**
 * Standalone <script> entry point.
 *
 * Exposes `window.WebDecoyCaptcha` and auto-initializes any `[data-webdecoy]`
 * elements once the DOM is ready.
 */

import { WebDecoyCaptcha } from './client';

(window as unknown as Record<string, unknown>).WebDecoyCaptcha = WebDecoyCaptcha;

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', () => WebDecoyCaptcha.autoInit());
} else {
  WebDecoyCaptcha.autoInit();
}

export { WebDecoyCaptcha };
