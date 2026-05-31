/**
 * Public API for the WebDecoy browser client.
 *
 * Mirrors the FCaptcha global surface: render a checkbox widget, run an
 * invisible session, execute a one-shot score, configure the server origin, and
 * auto-initialize `[data-webdecoy]` elements. Ported from FCaptcha client.js.
 */

import { CaptchaWidget } from './widget';
import { InvisibleSession } from './invisible';
import { EnvironmentalCollector } from './collectors/environment';
import { getServerUrl, setServerUrl } from './config';
import type { InvisibleOptions, VerifyResponse, WidgetOptions } from './types';

type AnyWidget = CaptchaWidget | InvisibleSession;

export interface WebDecoyCaptchaAPI {
  widgets: Map<string, AnyWidget>;
  get serverUrl(): string | null;
  set serverUrl(url: string | null);
  configure(options: { serverUrl?: string }): void;
  render(container: string | HTMLElement, options?: WidgetOptions): string;
  getResponse(widgetId: string): string | null;
  reset(widgetId: string): void;
  invisible(options?: InvisibleOptions): InvisibleSession;
  execute(
    siteKey: string,
    options?: { action?: string; minTime?: number; powDifficulty?: number },
  ): Promise<VerifyResponse>;
  getSignals(): { environmental: Record<string, unknown> };
  autoInit(): void;
}

export const WebDecoyCaptcha: WebDecoyCaptchaAPI = {
  widgets: new Map<string, AnyWidget>(),

  get serverUrl(): string | null {
    return getServerUrl();
  },
  set serverUrl(url: string | null) {
    setServerUrl(url);
  },

  configure(options: { serverUrl?: string }): void {
    if (options.serverUrl) setServerUrl(options.serverUrl);
  },

  render(container: string | HTMLElement, options?: WidgetOptions): string {
    const widget = new CaptchaWidget(container, options);
    this.widgets.set(widget.id, widget);
    return widget.id;
  },

  getResponse(widgetId: string): string | null {
    const widget = this.widgets.get(widgetId);
    return widget && widget instanceof CaptchaWidget ? widget.getToken() : null;
  },

  reset(widgetId: string): void {
    const widget = this.widgets.get(widgetId);
    if (widget instanceof CaptchaWidget) widget.reset();
  },

  invisible(options?: InvisibleOptions): InvisibleSession {
    const session = new InvisibleSession(options);
    this.widgets.set(session.id, session);
    return session;
  },

  async execute(
    siteKey: string,
    options: { action?: string; minTime?: number; powDifficulty?: number } = {},
  ): Promise<VerifyResponse> {
    const session = new InvisibleSession({
      siteKey,
      serverUrl: getServerUrl(),
      minCollectionTime: options.minTime || 1000,
      autoScore: false,
      powDifficulty: options.powDifficulty || 3,
    });
    const result = await session.execute(options.action || '');
    session.destroy();
    return result;
  },

  getSignals(): { environmental: Record<string, unknown> } {
    const environmental = new EnvironmentalCollector();
    return { environmental: environmental.collect() };
  },

  autoInit(): void {
    document.querySelectorAll<HTMLElement>('[data-webdecoy]').forEach((container) => {
      const siteKey = container.dataset.sitekey || container.dataset.webdecoy;
      const theme = (container.dataset.theme as 'light' | 'dark') || 'light';
      const endpoint = container.dataset.endpoint;
      const callbackName = container.dataset.callback;
      const callback = callbackName
        ? ((window as unknown as Record<string, unknown>)[callbackName] as ((token: string) => void) | undefined)
        : undefined;

      if (endpoint) setServerUrl(endpoint);

      this.render(container, { siteKey, theme, callback: callback ?? null });
    });
  },
};
