export class EnvironmentalCollector {
  collect(): Record<string, unknown> {
    return {
      // Comprehensive automation detection
      webdriver: this._detectWebdriver(),
      automationFlags: this._getAutomationFlags(),
      cdp: this._detectCDP(),
      playwright: this._detectPlaywright(),

      // Browser fingerprints
      canvasHash: this._getCanvasHash(),
      webglInfo: this._getWebGLInfo(),
      audioInfo: this._getAudioInfo(),

      // Headless detection
      headlessIndicators: this._getHeadlessIndicators(),

      // System info
      screen: this._getScreenInfo(),
      navigator: this._getNavigatorInfo(),

      // Timing fingerprints
      jsExecutionTime: this._measureJSExecution(),

      // Advanced fingerprint detections
      mathFingerprint: this._getMathFingerprint(),
      errorFingerprint: this._getErrorFingerprint(),
      domRectFingerprint: this._getDOMRectFingerprint(),
      cssMediaQueries: this._getCSSMediaQueries(),
      permissionsInfo: this._getPermissionsInfo(),
      fontsInfo: this._getFontsInfo(),

      // Native-function integrity (stealth self-hiding leaves patched toStrings)
      lieDetection: this._getLieDetection(),
    };
  }

  // Async detections collected separately
  async collectAsync(): Promise<Record<string, unknown>> {
    const [speechInfo, webrtcInfo, workerConsistency] = await Promise.all([
      this._getSpeechInfo(),
      this._getWebRTCInfo(),
      this._checkWorkerConsistency()
    ]);
    return { speechInfo, webrtcInfo, workerConsistency };
  }

  _detectWebdriver(): boolean {
    const nav = navigator as any;
    const w = window as any;
    return !!(
      nav.webdriver ||
      w.document.__webdriver_evaluate ||
      w.document.__selenium_evaluate ||
      w.document.__webdriver_script_fn ||
      w.document.__webdriver_script_func ||
      w.document.__webdriver_script_function ||
      w.document['$cdc_asdjflasutopfhvcZLmcfl_'] ||
      w.document['$wdc_'] ||
      w['_Selenium_IDE_Recorder'] ||
      w['_phantom'] ||
      w['__nightmare'] ||
      w.callPhantom ||
      w._phantom
    );
  }

  _getAutomationFlags(): Record<string, unknown> {
    const nav = navigator as any;
    const w = window as any;
    return {
      // Core automation
      webdriver: !!nav.webdriver,
      domAutomation: !!w.domAutomation,
      domAutomationController: !!w.domAutomationController,

      // Selenium
      _selenium: !!w._selenium,
      __webdriver_script_fn: !!w.__webdriver_script_fn,
      __driver_evaluate: !!w.__driver_evaluate,
      __webdriver_evaluate: !!w.__webdriver_evaluate,
      __fxdriver_evaluate: !!w.__fxdriver_evaluate,
      __driver_unwrapped: !!w.__driver_unwrapped,
      __webdriver_unwrapped: !!w.__webdriver_unwrapped,
      __fxdriver_unwrapped: !!w.__fxdriver_unwrapped,
      _Selenium_IDE_Recorder: !!w._Selenium_IDE_Recorder,
      calledSelenium: !!w.calledSelenium,
      $chrome_asyncScriptInfo: !!w.$chrome_asyncScriptInfo,
      $cdc_asdjflasutopfhvcZLmcfl_: !!w.$cdc_asdjflasutopfhvcZLmcfl_,

      // PhantomJS
      _phantom: !!w._phantom,
      callPhantom: !!w.callPhantom,

      // Nightmare
      __nightmare: !!w.__nightmare,

      // Watir
      __lastWatirAlert: !!w.__lastWatirAlert,
      __lastWatirConfirm: !!w.__lastWatirConfirm,
      __lastWatirPrompt: !!w.__lastWatirPrompt,

      // Browser properties
      plugins: navigator.plugins ? navigator.plugins.length : 0,
      languages: navigator.languages && navigator.languages.length > 0,
      mimeTypes: navigator.mimeTypes ? navigator.mimeTypes.length : 0,
      cookieEnabled: navigator.cookieEnabled,
      doNotTrack: navigator.doNotTrack,

      // Chrome specific
      chrome: !!w.chrome,
      chromeRuntime: !!(w.chrome && w.chrome.runtime && w.chrome.runtime.id),

      // Permissions API
      permissionsAPI: !!navigator.permissions
    };
  }

  _detectPlaywright(): { detected: boolean; signals: string[] } {
    try {
      const w = window as any;
      const signals: string[] = [];

      // Check for Playwright window properties
      const pwKeys = Object.getOwnPropertyNames(window).filter(k =>
        k.startsWith('__pw') || k.startsWith('__playwright')
      );
      if (pwKeys.length > 0) signals.push('playwright_globals');

      // navigator.webdriver *deleted* from the prototype is a genuine automation
      // tell. NOTE: a merely *configurable* descriptor is normal in real Chrome,
      // and chrome.runtime is absent on ordinary pages in real Chrome — both
      // fired on a real browser in live testing, so neither is a signal here.
      const proto = Object.getPrototypeOf(navigator);
      const desc = Object.getOwnPropertyDescriptor(proto, 'webdriver');
      if (!desc) {
        signals.push('webdriver_deleted');
      }

      return { detected: signals.length > 0, signals };
    } catch (e) {
      return { detected: false, signals: [] };
    }
  }

  _detectCDP(): { detected: boolean; signals: string[] } {
    try {
      const w = window as any;
      const signals: string[] = [];

      // ChromeDriver injects cdc_ prefixed properties (ChromeDriver Canary Detection)
      // These are randomly named but always start with cdc_
      const cdcKeys = Object.keys(window).filter(k => k.startsWith('cdc_'));
      if (cdcKeys.length > 0) {
        signals.push('chromedriver_cdc');
      }

      // Selenium WebDriver specific properties
      if ('__webdriver_evaluate' in window) signals.push('selenium_evaluate');
      if ('__driver_evaluate' in window) signals.push('selenium_driver_evaluate');
      if ('__webdriver_unwrapped' in window) signals.push('selenium_unwrapped');
      if ('__driver_unwrapped' in window) signals.push('selenium_driver_unwrapped');
      if ('__selenium_evaluate' in window) signals.push('selenium_direct');
      if ('__fxdriver_evaluate' in window) signals.push('firefox_driver');
      if ('__fxdriver_unwrapped' in window) signals.push('firefox_driver_unwrapped');

      // Puppeteer-specific CDP artifacts
      if ('__puppeteer_evaluation_script__' in window) signals.push('puppeteer_eval');

      // Check for CDP Runtime.evaluate artifacts
      // These appear when scripts are injected via CDP
      if ((document as any).__webdriver_script_fn) signals.push('cdp_script_injection');

      // Check for modified navigator.webdriver getter
      // Some tools try to hide webdriver but leave traces
      try {
        const descriptor = Object.getOwnPropertyDescriptor(navigator, 'webdriver');
        if (descriptor && typeof descriptor.get === 'function') {
          const getterStr = descriptor.get.toString();
          if (getterStr.indexOf('[native code]') === -1) {
            signals.push('webdriver_getter_modified');
          }
        }
      } catch (e) {
        // Skip if can't access descriptor
      }

      return {
        detected: signals.length > 0,
        signals: signals
      };
    } catch (e) {
      return { detected: false, signals: [] };
    }
  }

  _getCanvasHash(): Record<string, unknown> {
    try {
      const canvas = document.createElement('canvas');
      canvas.width = 200;
      canvas.height = 50;
      const ctx = canvas.getContext('2d') as CanvasRenderingContext2D;

      ctx.textBaseline = 'top';
      ctx.font = '14px Arial';
      ctx.fillStyle = '#f60';
      ctx.fillRect(125, 1, 62, 20);
      ctx.fillStyle = '#069';
      ctx.fillText('FCaptcha', 2, 15);
      ctx.fillStyle = 'rgba(102, 204, 0, 0.7)';
      ctx.fillText('FCaptcha', 4, 17);

      const dataUrl = canvas.toDataURL();
      let hash = 0;
      for (let i = 0; i < dataUrl.length; i++) {
        hash = ((hash << 5) - hash) + dataUrl.charCodeAt(i);
        hash = hash & hash;
      }
      return { hash: hash.toString(16), dataLength: dataUrl.length, supported: true };
    } catch (e) {
      return { error: true, supported: false };
    }
  }

  _getWebGLInfo(): Record<string, unknown> {
    try {
      const canvas = document.createElement('canvas');
      const gl = (canvas.getContext('webgl') || canvas.getContext('experimental-webgl')) as WebGLRenderingContext | null;

      if (!gl) return { supported: false };

      const debugInfo = gl.getExtension('WEBGL_debug_renderer_info') as any;
      const vendor = debugInfo ? gl.getParameter(debugInfo.UNMASKED_VENDOR_WEBGL) : 'unknown';
      const renderer = debugInfo ? gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL) : 'unknown';

      const rendererLower = renderer.toLowerCase();
      const suspiciousRenderer =
        rendererLower.includes('swiftshader') ||
        rendererLower.includes('llvmpipe') ||
        rendererLower.includes('softpipe') ||
        rendererLower.includes('virtualbox') ||
        rendererLower.includes('vmware');

      return {
        supported: true,
        vendor,
        renderer,
        version: gl.getParameter(gl.VERSION),
        shadingVersion: gl.getParameter(gl.SHADING_LANGUAGE_VERSION),
        suspiciousRenderer
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  _getAudioInfo(): Record<string, unknown> {
    try {
      const w = window as any;
      const AudioContextCtor = w.AudioContext || w.webkitAudioContext;
      if (!AudioContextCtor) return { supported: false };

      const audioCtx: AudioContext = new AudioContextCtor();
      const info = {
        supported: true,
        sampleRate: audioCtx.sampleRate,
        state: audioCtx.state,
        baseLatency: audioCtx.baseLatency
      };
      audioCtx.close();
      return info;
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * Native-function integrity check. Stealth automation hides itself by
   * overriding native functions; a patched native's `toString()` no longer
   * reports `[native code]`. A genuine browser never patches its own natives,
   * so any hit here is deliberate evasion (scored in the `stealth` category).
   */
  _getLieDetection(): Record<string, unknown> {
    try {
      const w = window as any;
      const patched: string[] = [];

      const isPatched = (fn: unknown): boolean => {
        try {
          return typeof fn === 'function' && (fn as { toString(): string }).toString().indexOf('[native code]') === -1;
        } catch {
          return false;
        }
      };
      const check = (fn: unknown, name: string): void => {
        if (isPatched(fn)) patched.push(name);
      };

      // If toString itself is patched, every other check is unreliable — flag it.
      check(Function.prototype.toString, 'Function.prototype.toString');
      check(navigator.permissions && navigator.permissions.query, 'navigator.permissions.query');
      check(w.Notification && w.Notification.requestPermission, 'Notification.requestPermission');
      check(w.HTMLCanvasElement && w.HTMLCanvasElement.prototype.toDataURL, 'HTMLCanvasElement.toDataURL');
      check(
        w.WebGLRenderingContext && w.WebGLRenderingContext.prototype.getParameter,
        'WebGLRenderingContext.getParameter',
      );
      check(navigator.mediaDevices && navigator.mediaDevices.enumerateDevices, 'mediaDevices.enumerateDevices');

      // The navigator.webdriver getter is the most-patched native.
      try {
        const desc =
          Object.getOwnPropertyDescriptor(Object.getPrototypeOf(navigator), 'webdriver') ||
          Object.getOwnPropertyDescriptor(navigator, 'webdriver');
        if (desc && typeof desc.get === 'function' && desc.get.toString().indexOf('[native code]') === -1) {
          patched.push('navigator.webdriver getter');
        }
      } catch {
        // ignore
      }

      return { supported: true, patched, patchedCount: patched.length };
    } catch (e) {
      return { supported: false };
    }
  }

  _getHeadlessIndicators(): Record<string, unknown> {
    const nav = navigator as any;
    return {
      hasOuterDimensions: window.outerWidth > 0 && window.outerHeight > 0,
      innerEqualsOuter: window.innerWidth === window.outerWidth && window.innerHeight === window.outerHeight,
      screenColorDepth: window.screen.colorDepth,
      screenPixelDepth: window.screen.pixelDepth,
      connectionType: nav.connection ? nav.connection.type : 'unknown',
      connectionRtt: nav.connection ? nav.connection.rtt : -1,
      notificationPermission: typeof Notification !== 'undefined' ? Notification.permission : 'unsupported',
      hasBattery: 'getBattery' in navigator,
      hasCredentials: 'credentials' in navigator,
      hasMediaDevices: 'mediaDevices' in navigator
    };
  }

  _getScreenInfo(): Record<string, unknown> {
    return {
      width: screen.width,
      height: screen.height,
      colorDepth: screen.colorDepth,
      pixelRatio: window.devicePixelRatio,
      availWidth: screen.availWidth,
      availHeight: screen.availHeight,
      innerWidth: window.innerWidth,
      innerHeight: window.innerHeight
    };
  }

  _getNavigatorInfo(): Record<string, unknown> {
    const nav = navigator as any;
    return {
      language: navigator.language,
      languageCount: navigator.languages?.length || 0,
      platform: navigator.platform,
      hardwareConcurrency: navigator.hardwareConcurrency,
      deviceMemory: nav.deviceMemory,
      maxTouchPoints: navigator.maxTouchPoints || 0,
      vendor: navigator.vendor,
      userAgent: navigator.userAgent,
      timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
      timezoneOffset: new Date().getTimezoneOffset()
    };
  }

  _measureJSExecution(): Record<string, number> {
    const results: Record<string, number> = {};

    let start = performance.now();
    for (let i = 0; i < 1000; i++) {
      Math.sqrt(i) * Math.sin(i);
    }
    results.mathOps = performance.now() - start;

    start = performance.now();
    const arr: number[] = [];
    for (let i = 0; i < 1000; i++) arr.push(i);
    results.arrayOps = performance.now() - start;
    results.arrayLen = arr.length; // Ensure array is "used" to prevent optimization

    start = performance.now();
    let str = '';
    for (let i = 0; i < 100; i++) str += 'a';
    results.stringOps = performance.now() - start;

    return results;
  }

  async measureRAFConsistency(): Promise<Record<string, unknown>> {
    return new Promise((resolve) => {
      const times: number[] = [];
      let frameCount = 0;
      const maxFrames = 10;

      function measure(timestamp: number): void {
        times.push(timestamp);
        frameCount++;

        if (frameCount < maxFrames) {
          requestAnimationFrame(measure);
        } else {
          const deltas: number[] = [];
          for (let i = 1; i < times.length; i++) {
            deltas.push(times[i] - times[i - 1]);
          }

          const mean = deltas.reduce((a, b) => a + b, 0) / deltas.length;
          const variance = deltas.reduce((sum, d) => sum + Math.pow(d - mean, 2), 0) / deltas.length;

          resolve({ avgFrameTime: mean, frameTimeVariance: variance, frames: maxFrames });
        }
      }

      requestAnimationFrame(measure);
    });
  }

  // ============================================================
  // Advanced Fingerprint Detection Methods
  // ============================================================

  /**
   * Math fingerprint - Different JS engines produce slightly different results
   * for certain math operations. Headless browsers/VMs may show inconsistencies.
   */
  _getMathFingerprint(): Record<string, unknown> {
    try {
      const results = {
        // These produce engine-specific results
        acos: Math.acos(0.123456789),
        acosh: Math.acosh(1e308),
        asin: Math.asin(0.123456789),
        asinh: Math.asinh(1),
        atanh: Math.atanh(0.5),
        cbrt: Math.cbrt(100),
        cosh: Math.cosh(1),
        expm1: Math.expm1(1),
        log1p: Math.log1p(10),
        sinh: Math.sinh(1),
        tan: Math.tan(-1e308),
        tanh: Math.tanh(1),
        // These can expose VM artifacts
        pow: Math.pow(Math.PI, -100),
        sin: Math.sin(Math.PI),
      };

      // Create a hash of the results
      const str = Object.values(results).map(v => String(v)).join(',');
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
      }

      return {
        hash: hash.toString(16),
        // Include a few key values for cross-checking
        sinPi: results.sin,
        tanLarge: results.tan,
        supported: true
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * Error fingerprint - Error message formatting varies by engine
   * Uses safe error triggers (no eval/Function) to get engine-specific messages
   */
  _getErrorFingerprint(): Record<string, unknown> {
    try {
      const errors: Record<string, string> = {};

      // TypeError - null property access
      try { (null as any).foo; } catch (e) { errors.typeError = (e as Error).message; }

      // RangeError - invalid array length
      try { ([] as any).length = -1; } catch (e) { errors.rangeError = (e as Error).message; }

      // URIError - bad URI encoding
      try { decodeURIComponent('%'); } catch (e) { errors.uriError = (e as Error).message; }

      // ReferenceError - undefined variable (via indirect detection)
      try {
        const obj: any = {};
        obj.undefinedMethod();
      } catch (e) { errors.refTypeError = (e as Error).message; }

      // Generate hash from error messages
      const str = Object.values(errors).join('|');
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
      }

      return {
        hash: hash.toString(16),
        typeError: errors.typeError,
        supported: true
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * DOMRect fingerprint - Element rendering varies slightly between browsers/configs
   */
  _getDOMRectFingerprint(): Record<string, unknown> {
    try {
      const container = document.createElement('div');
      container.style.cssText = 'position:absolute;left:-9999px;font-size:16px;font-family:Arial,sans-serif;';

      // Test element A - simple text
      const textA = document.createElement('span');
      textA.textContent = 'FCaptcha Test String 123';
      container.appendChild(textA);

      // Test element B - styled text
      const textB = document.createElement('span');
      textB.style.cssText = 'letter-spacing:1px;word-spacing:2px;';
      textB.textContent = 'WWWW 0000';
      container.appendChild(textB);

      document.body.appendChild(container);

      const rectA = textA.getBoundingClientRect();
      const rectB = textB.getBoundingClientRect();

      // Create range for additional precision
      const range = document.createRange();
      range.selectNode(textA);
      const rangeRect = range.getBoundingClientRect();

      document.body.removeChild(container);

      // Hash the measurements
      const values = [
        rectA.width, rectA.height, rectA.x, rectA.y,
        rectB.width, rectB.height,
        rangeRect.width, rangeRect.height
      ];

      const str = values.map(v => v.toFixed(6)).join(',');
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
      }

      return {
        hash: hash.toString(16),
        rectAWidth: rectA.width,
        rectBWidth: rectB.width,
        rangeWidth: rangeRect.width,
        supported: true
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * CSS Media Queries - Detect screen/device characteristics
   */
  _getCSSMediaQueries(): Record<string, unknown> {
    try {
      const queries = {
        // Color scheme preference
        prefersColorScheme: window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light',
        prefersReducedMotion: window.matchMedia('(prefers-reduced-motion: reduce)').matches,
        prefersReducedTransparency: window.matchMedia('(prefers-reduced-transparency: reduce)').matches,
        prefersContrast: window.matchMedia('(prefers-contrast: more)').matches ? 'more' :
                        window.matchMedia('(prefers-contrast: less)').matches ? 'less' : 'no-preference',

        // Pointer capabilities (helps identify device type)
        anyHover: window.matchMedia('(any-hover: hover)').matches,
        anyPointer: window.matchMedia('(any-pointer: fine)').matches ? 'fine' :
                    window.matchMedia('(any-pointer: coarse)').matches ? 'coarse' : 'none',
        hover: window.matchMedia('(hover: hover)').matches,
        pointer: window.matchMedia('(pointer: fine)').matches ? 'fine' :
                 window.matchMedia('(pointer: coarse)').matches ? 'coarse' : 'none',

        // Display characteristics
        colorGamut: window.matchMedia('(color-gamut: p3)').matches ? 'p3' :
                    window.matchMedia('(color-gamut: srgb)').matches ? 'srgb' : 'none',
        displayMode: window.matchMedia('(display-mode: standalone)').matches ? 'standalone' :
                     window.matchMedia('(display-mode: fullscreen)').matches ? 'fullscreen' : 'browser',
        orientation: window.matchMedia('(orientation: portrait)').matches ? 'portrait' : 'landscape',

        // HDR
        dynamicRange: window.matchMedia('(dynamic-range: high)').matches ? 'high' : 'standard',

        // Forced colors (accessibility)
        forcedColors: window.matchMedia('(forced-colors: active)').matches
      };

      return { ...queries, supported: true };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * Permissions API - Check browser permission states
   */
  _getPermissionsInfo(): Record<string, unknown> {
    // Sync check - async detailed check happens separately
    try {
      return {
        hasPermissionsAPI: 'permissions' in navigator,
        hasClipboard: 'clipboard' in navigator,
        hasShare: 'share' in navigator,
        hasCredentials: 'credentials' in navigator,
        hasBluetooth: 'bluetooth' in navigator,
        hasUsb: 'usb' in navigator,
        hasSerial: 'serial' in navigator,
        hasHid: 'hid' in navigator,
        hasXR: 'xr' in navigator,
        hasGeolocation: 'geolocation' in navigator,
        hasMIDI: 'requestMIDIAccess' in navigator,
        supported: true
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * Font detection - Check for system fonts
   * Uses canvas-based detection (fast, doesn't require font loading)
   */
  _getFontsInfo(): Record<string, unknown> {
    try {
      const baseFonts = ['monospace', 'sans-serif', 'serif'];
      const testFonts = [
        // Common system fonts
        'Arial', 'Helvetica', 'Times New Roman', 'Courier New', 'Georgia',
        'Verdana', 'Trebuchet MS', 'Comic Sans MS', 'Impact', 'Lucida Console',
        // Mac fonts
        'Menlo', 'Monaco', 'SF Pro', 'Helvetica Neue',
        // Windows fonts
        'Segoe UI', 'Consolas', 'Calibri', 'Cambria',
        // Linux fonts
        'DejaVu Sans', 'Liberation Sans', 'Ubuntu', 'Cantarell',
        // CJK fonts
        'MS Gothic', 'Meiryo', 'SimHei', 'Microsoft YaHei'
      ];

      const canvas = document.createElement('canvas');
      canvas.width = 400;
      canvas.height = 40;
      const ctx = canvas.getContext('2d') as CanvasRenderingContext2D;

      const testString = 'mmMWWLLiiff00';
      const testSize = '72px';

      // Get baseline widths
      const baseWidths: Record<string, number> = {};
      for (const baseFont of baseFonts) {
        ctx.font = testSize + ' ' + baseFont;
        baseWidths[baseFont] = ctx.measureText(testString).width;
      }

      // Test each font against baselines
      const detectedFonts: string[] = [];
      for (const font of testFonts) {
        let detected = false;
        for (const baseFont of baseFonts) {
          ctx.font = testSize + ' "' + font + '", ' + baseFont;
          const width = ctx.measureText(testString).width;
          if (width !== baseWidths[baseFont]) {
            detected = true;
            break;
          }
        }
        if (detected) {
          detectedFonts.push(font);
        }
      }

      // Create hash of detected fonts
      const str = detectedFonts.join(',');
      let hash = 0;
      for (let i = 0; i < str.length; i++) {
        hash = ((hash << 5) - hash) + str.charCodeAt(i);
        hash = hash & hash;
      }

      return {
        hash: hash.toString(16),
        count: detectedFonts.length,
        // Only include a few key fonts to keep payload small
        hasArial: detectedFonts.includes('Arial'),
        hasTimesNewRoman: detectedFonts.includes('Times New Roman'),
        hasSegoeUI: detectedFonts.includes('Segoe UI'),
        hasSFPro: detectedFonts.includes('SF Pro'),
        hasDejaVuSans: detectedFonts.includes('DejaVu Sans'),
        supported: true
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * Speech Synthesis API - Get available voices
   * Voices are OS/browser specific and hard to spoof
   */
  async _getSpeechInfo(): Promise<Record<string, unknown>> {
    try {
      if (!('speechSynthesis' in window)) {
        return { supported: false };
      }

      // Voices may load async
      const getVoices = (): Promise<SpeechSynthesisVoice[]> => {
        return new Promise((resolve) => {
          const voices = speechSynthesis.getVoices();
          if (voices.length > 0) {
            resolve(voices);
            return;
          }

          // Wait for voiceschanged event
          const timeout = setTimeout(() => resolve([]), 1000);
          speechSynthesis.onvoiceschanged = () => {
            clearTimeout(timeout);
            resolve(speechSynthesis.getVoices());
          };
        });
      };

      const voices = await getVoices();

      // Categorize voices
      const localVoices = voices.filter(v => v.localService);
      const defaultVoice = voices.find(v => v.default);

      // Get unique languages
      const languages = [...new Set(voices.map(v => v.lang))];

      // Create hash
      const voiceNames = voices.map(v => v.name).sort().join(',');
      let hash = 0;
      for (let i = 0; i < voiceNames.length; i++) {
        hash = ((hash << 5) - hash) + voiceNames.charCodeAt(i);
        hash = hash & hash;
      }

      return {
        hash: hash.toString(16),
        totalVoices: voices.length,
        localVoices: localVoices.length,
        languages: languages.length,
        defaultVoiceLang: defaultVoice?.lang || null,
        hasGoogleVoices: voices.some(v => v.name.includes('Google')),
        hasMicrosoftVoices: voices.some(v => v.name.includes('Microsoft')),
        hasAppleVoices: voices.some(v => v.name.includes('Samantha') || v.name.includes('Alex')),
        supported: true
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * WebRTC fingerprinting - Get local IPs and media devices
   * Very effective for detecting VMs, proxies, and headless browsers
   */
  async _getWebRTCInfo(): Promise<Record<string, unknown>> {
    try {
      const info: Record<string, unknown> = {
        supported: 'RTCPeerConnection' in window,
        mediaDevices: { supported: false },
        localIPs: []
      };

      if (!info.supported) return info;

      // Get media devices (doesn't require permission for enumeration)
      if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
        try {
          const devices = await navigator.mediaDevices.enumerateDevices();
          info.mediaDevices = {
            supported: true,
            audioInputs: devices.filter(d => d.kind === 'audioinput').length,
            audioOutputs: devices.filter(d => d.kind === 'audiooutput').length,
            videoInputs: devices.filter(d => d.kind === 'videoinput').length,
            // Headless browsers typically have 0 devices
            totalDevices: devices.length
          };
        } catch (e) {
          info.mediaDevices = { supported: false, error: true };
        }
      }

      // Get local IPs via WebRTC (no permission needed)
      try {
        const pc = new RTCPeerConnection({
          iceServers: [{ urls: 'stun:stun.l.google.com:19302' }]
        });

        const localIPs = new Set<string>();

        pc.onicecandidate = (event) => {
          if (event.candidate) {
            const candidate = event.candidate.candidate;
            // Extract IP addresses from ICE candidates
            const ipRegex = /([0-9]{1,3}\.){3}[0-9]{1,3}/g;
            const matches = candidate.match(ipRegex);
            if (matches) {
              matches.forEach(ip => {
                // Filter out STUN server responses, keep only local IPs
                if (ip.startsWith('192.168.') || ip.startsWith('10.') ||
                    ip.startsWith('172.') || ip.startsWith('169.254.')) {
                  localIPs.add(ip);
                }
              });
            }
          }
        };

        // Create data channel to trigger ICE gathering
        pc.createDataChannel('');
        await pc.createOffer().then(offer => pc.setLocalDescription(offer));

        // Wait briefly for ICE candidates
        await new Promise(r => setTimeout(r, 500));

        info.localIPs = Array.from(localIPs);
        info.hasLocalIP = localIPs.size > 0;

        pc.close();
      } catch (e) {
        info.localIPError = true;
      }

      return info;
    } catch (e) {
      return { supported: false, error: true };
    }
  }

  /**
   * Worker consistency check - Compare main thread vs worker values
   * Spoofed values often don't match between contexts
   */
  async _checkWorkerConsistency(): Promise<Record<string, unknown>> {
    try {
      if (typeof Worker === 'undefined') {
        return { supported: false };
      }

      const nav = navigator as any;

      // Create inline worker
      const workerCode = `
          self.onmessage = function() {
            const data = {
              userAgent: navigator.userAgent,
              language: navigator.language,
              languages: navigator.languages ? Array.from(navigator.languages) : [],
              platform: navigator.platform,
              hardwareConcurrency: navigator.hardwareConcurrency,
              deviceMemory: navigator.deviceMemory,
              timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
              timezoneOffset: new Date().getTimezoneOffset()
            };
            self.postMessage(data);
          };
        `;

      const blob = new Blob([workerCode], { type: 'application/javascript' });
      const worker = new Worker(URL.createObjectURL(blob));

      const workerData = await new Promise<any>((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('timeout')), 2000);
        worker.onmessage = (e) => {
          clearTimeout(timeout);
          resolve(e.data);
        };
        worker.onerror = () => {
          clearTimeout(timeout);
          reject(new Error('worker error'));
        };
        worker.postMessage('collect');
      });

      worker.terminate();

      // Compare with main thread values
      const mainData = {
        userAgent: navigator.userAgent,
        language: navigator.language,
        languages: navigator.languages ? Array.from(navigator.languages) : [],
        platform: navigator.platform,
        hardwareConcurrency: navigator.hardwareConcurrency,
        deviceMemory: nav.deviceMemory,
        timezone: Intl.DateTimeFormat().resolvedOptions().timeZone,
        timezoneOffset: new Date().getTimezoneOffset()
      };

      // Check for mismatches (indicates spoofing)
      const mismatches: string[] = [];
      if (workerData.userAgent !== mainData.userAgent) mismatches.push('userAgent');
      if (workerData.language !== mainData.language) mismatches.push('language');
      if (workerData.platform !== mainData.platform) mismatches.push('platform');
      if (workerData.hardwareConcurrency !== mainData.hardwareConcurrency) mismatches.push('hardwareConcurrency');
      if (workerData.deviceMemory !== mainData.deviceMemory) mismatches.push('deviceMemory');
      if (workerData.timezone !== mainData.timezone) mismatches.push('timezone');
      if (workerData.timezoneOffset !== mainData.timezoneOffset) mismatches.push('timezoneOffset');
      if (JSON.stringify(workerData.languages) !== JSON.stringify(mainData.languages)) mismatches.push('languages');

      return {
        supported: true,
        consistent: mismatches.length === 0,
        mismatches: mismatches,
        mismatchCount: mismatches.length
      };
    } catch (e) {
      return { supported: false, error: true };
    }
  }
}
