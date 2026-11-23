import { EnvironmentalCollector } from './environment';

it('includes Menlo and Calibri in the existing font summary', () => {
  const installed = new Set(['Arial', 'Menlo', 'Calibri']);
  const canvas = {
    font: '',
    measureText(): { width: number } {
      const family = /"([^"]+)"/.exec(this.font)?.[1];
      return { width: family && installed.has(family) ? 105 : 100 };
    },
  };
  const context = jest.spyOn(HTMLCanvasElement.prototype, 'getContext')
    .mockReturnValue(canvas as unknown as CanvasRenderingContext2D);
  try {
    expect(new EnvironmentalCollector()._getFontsInfo()).toMatchObject({
      supported: true,
      count: 3,
      hasMenlo: true,
      hasCalibri: true,
      hasSFPro: false,
      hasSegoeUI: false,
    });
  } finally {
    context.mockRestore();
  }
});
