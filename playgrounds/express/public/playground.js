const enforce = document.querySelector('#enforce');
const badge = document.querySelector('#mode-badge');
const help = document.querySelector('#mode-help');
const buttons = [...document.querySelectorAll('[data-probe]')];
const status = document.querySelector('#http-status');
const requestPath = document.querySelector('#request-path');
const output = document.querySelector('#response-body');
const explanation = document.querySelector('#result-explanation');

enforce.addEventListener('change', () => {
  badge.textContent = enforce.checked ? 'ENFORCE' : 'MONITOR';
  help.textContent = enforce.checked
    ? 'Enforcement stops the decoy before its route runs. Ordinary traffic still passes.'
    : 'Monitor records rule decisions and preserves the route response.';
});

for (const button of buttons) button.addEventListener('click', async () => {
  const mode = enforce.checked ? 'enforce' : 'monitor';
  const target = button.dataset.probe;
  const path = target === 'decoy' ? '/demo-decoy' : '/';
  buttons.forEach(b => { b.disabled = true; });
  enforce.disabled = true;
  requestPath.textContent = `GET ${path} · ${mode} mode`;
  status.textContent = 'SENDING';
  output.textContent = 'Waiting for Express…';
  explanation.textContent = '';
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 8000);
  try {
    const response = await fetch(`/${mode}${path}`, { signal: controller.signal, cache: 'no-store' });
    const body = await response.json();
    status.textContent = `HTTP ${response.status}`;
    output.textContent = JSON.stringify(body, null, 2);
    explanation.textContent = response.status === 403
      ? 'The SDK blocked this controlled decoy request before its Express route ran.'
      : body.decision?.tripwire
        ? 'The tripwire matched. Monitor mode preserved the demo route’s HTTP 404 response.'
        : 'This ordinary request did not match the configured tripwire.';
  } catch (error) {
    status.textContent = 'REQUEST FAILED';
    output.textContent = error.name === 'AbortError' ? 'The request timed out.' : 'Could not reach the playground server.';
    explanation.textContent = 'Check that npm run dev is running, then retry.';
  } finally {
    clearTimeout(timeout);
    buttons.forEach(b => { b.disabled = false; });
    enforce.disabled = false;
  }
});
