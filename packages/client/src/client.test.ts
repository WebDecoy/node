/**
 * @jest-environment jsdom
 *
 * Smoke tests for the client API and widget rendering in a DOM environment.
 * Full signal-collection + PoW flow is exercised by browser e2e (Phase 4),
 * since jsdom lacks Web Workers and full canvas/WebGL.
 */

import { WebDecoyCaptcha } from './client';
import { getServerUrl, setServerUrl } from './config';

afterEach(() => {
  setServerUrl(null);
  WebDecoyCaptcha.widgets.clear();
  document.body.innerHTML = '';
});

describe('WebDecoyCaptcha API', () => {
  it('configures the server URL', () => {
    WebDecoyCaptcha.configure({ serverUrl: 'https://api.example.com' });
    expect(getServerUrl()).toBe('https://api.example.com');
    expect(WebDecoyCaptcha.serverUrl).toBe('https://api.example.com');
  });

  it('sets serverUrl via the property setter', () => {
    WebDecoyCaptcha.serverUrl = 'https://x.test';
    expect(getServerUrl()).toBe('https://x.test');
  });

  it('renders a checkbox widget into a container and tracks it', () => {
    const el = document.createElement('div');
    el.id = 'box';
    document.body.appendChild(el);

    const id = WebDecoyCaptcha.render('box', { siteKey: 'pk_test_123' });

    expect(id).toMatch(/^webdecoy_/);
    expect(WebDecoyCaptcha.widgets.has(id)).toBe(true);
    expect(el.querySelector('.webdecoy-checkbox')).not.toBeNull();
    expect(el.querySelector('.webdecoy-label')?.textContent).toBe("I'm not a robot");
  });

  it('returns no token before verification', () => {
    const el = document.createElement('div');
    document.body.appendChild(el);
    const id = WebDecoyCaptcha.render(el, { siteKey: 'pk_test_123' });
    expect(WebDecoyCaptcha.getResponse(id)).toBeNull();
  });

  it('throws when the container is missing', () => {
    expect(() => WebDecoyCaptcha.render('does-not-exist')).toThrow(/container element not found/);
  });

  it('auto-initializes [data-webdecoy] elements', () => {
    const el = document.createElement('div');
    el.setAttribute('data-webdecoy', 'pk_auto_1');
    el.setAttribute('data-endpoint', 'https://auto.example.com');
    document.body.appendChild(el);

    WebDecoyCaptcha.autoInit();

    expect(getServerUrl()).toBe('https://auto.example.com');
    expect(el.querySelector('.webdecoy-checkbox')).not.toBeNull();
  });
});
