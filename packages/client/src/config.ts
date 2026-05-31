/**
 * Shared runtime configuration for the browser widget.
 *
 * Replaces the mutable `FCaptcha.serverUrl` global from the reference client so
 * the collectors and PoW manager can read the configured server origin without
 * a circular import on the public API object.
 */

let serverUrl: string | null = null;

/** Origin that serves the WebDecoy captcha endpoints (`/api/pow/challenge`, etc). */
export function getServerUrl(): string | null {
  return serverUrl;
}

export function setServerUrl(url: string | null): void {
  serverUrl = url;
}
