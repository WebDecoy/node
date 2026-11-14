/**
 * @jest-environment jsdom
 *
 * Accessibility contract for the checkbox widget: a named control, keyboard
 * operation, and status changes a screen reader announces.
 */

import { CaptchaWidget } from './widget';

let warn: jest.SpyInstance;
let error: jest.SpyInstance;
beforeEach(() => {
  warn = jest.spyOn(console, 'warn').mockImplementation(() => {});
  error = jest.spyOn(console, 'error').mockImplementation(() => {});
});
afterEach(() => {
  warn.mockRestore();
  error.mockRestore();
  document.body.innerHTML = '';
});

function render(): { el: HTMLElement; widget: CaptchaWidget } {
  const el = document.createElement('div');
  document.body.appendChild(el);
  return { el, widget: new CaptchaWidget(el, { siteKey: 'pk_test_a11y' }) };
}

const parts = (el: HTMLElement) => ({
  checkbox: el.querySelector('[role="checkbox"]') as HTMLElement,
  status: el.querySelector('[role="status"]') as HTMLElement,
  label: el.querySelector('.webdecoy-label') as HTMLElement,
});

describe('CaptchaWidget accessibility', () => {
  it('gives the checkbox an accessible name and keeps it focusable', () => {
    const { checkbox, status, label } = parts(render().el);
    expect(checkbox.getAttribute('aria-label')).toBe("I'm not a robot");
    expect(checkbox.getAttribute('aria-checked')).toBe('false');
    expect(checkbox.tabIndex).toBe(0);
    expect(status.getAttribute('aria-live')).toBe('polite');
    // The visible text duplicates the name, so it is hidden from the a11y tree.
    expect(label.getAttribute('aria-hidden')).toBe('true');
  });

  it.each([' ', 'Enter'])('starts verification from the keyboard (%p) and announces it', key => {
    const { checkbox, status } = parts(render().el);
    checkbox.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true }));
    expect(checkbox.getAttribute('aria-busy')).toBe('true');
    expect(checkbox.getAttribute('aria-disabled')).toBe('true');
    expect(status.textContent).toMatch(/Verifying/);
  });

  it('announces a failure, keeps the message on screen and allows a retry', async () => {
    jest.useFakeTimers();
    try {
      const { el, widget } = render();
      const { checkbox, status, label } = parts(el);
      (widget as unknown as { _showFailure(m?: string): void })._showFailure('Verification failed');
      expect(status.textContent).toMatch(/Verification failed.*try again/);
      expect(checkbox.hasAttribute('aria-busy')).toBe(false);
      expect(checkbox.hasAttribute('aria-disabled')).toBe(false);
      jest.advanceTimersByTime(10_000);
      // The red mark clears, the message does not vanish on a timer.
      expect(checkbox.classList.contains('failed')).toBe(false);
      expect(label.textContent).toBe('Verification failed');
    } finally {
      jest.useRealTimers();
    }
  });

  it('announces success and reports the checked state', () => {
    const { el, widget } = render();
    const { checkbox, status } = parts(el);
    (widget as unknown as { _showSuccess(t: string): void })._showSuccess('tok');
    expect(checkbox.getAttribute('aria-checked')).toBe('true');
    expect(checkbox.hasAttribute('aria-busy')).toBe(false);
    expect(status.textContent).toBe('Verified.');
  });

  it('reset returns to an idle, operable control with nothing announced', () => {
    const { el, widget } = render();
    const { checkbox, status, label } = parts(el);
    checkbox.dispatchEvent(new KeyboardEvent('keydown', { key: 'Enter', bubbles: true }));
    widget.reset();
    expect(checkbox.getAttribute('aria-checked')).toBe('false');
    expect(checkbox.hasAttribute('aria-busy')).toBe(false);
    expect(checkbox.hasAttribute('aria-disabled')).toBe(false);
    expect(status.textContent).toBe('');
    expect(label.textContent).toBe("I'm not a robot");
  });
});
