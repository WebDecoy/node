import { getFormAnalyzer } from './form';

function attachTextarea(id: string): HTMLTextAreaElement {
  const textarea = document.createElement('textarea');
  textarea.id = id;
  document.body.append(textarea);
  return textarea;
}

function paste(target: HTMLElement): void {
  target.dispatchEvent(new Event('paste', { bubbles: true }));
}

afterEach(() => {
  document.body.replaceChildren();
  getFormAnalyzer().textareaStats.clear();
});

it('records a first paste in a textarea before any key events', () => {
  const analyzer = getFormAnalyzer();
  const textarea = attachTextarea('message');
  paste(textarea);
  textarea.value = 'Sample text pasted into the form';

  expect(analyzer.analyze().textareaKeyboard).toEqual({
    message: expect.objectContaining({
      keyCount: 0,
      pasteCount: 1,
      contentLength: textarea.value.length,
      noKeyboardEvents: true,
    }),
  });
});

it('shares textarea stats across typing and repeated paste events', () => {
  const analyzer = getFormAnalyzer();
  const textarea = attachTextarea('notes');
  textarea.dispatchEvent(new KeyboardEvent('keydown', { key: 'a', bubbles: true }));
  paste(textarea);
  paste(textarea);

  const input = document.createElement('input');
  input.name = 'unrelated';
  document.body.append(input);
  paste(input);

  expect(analyzer.analyze().textareaKeyboard).toEqual({
    notes: expect.objectContaining({ keyCount: 1, pasteCount: 2 }),
  });
});
