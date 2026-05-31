import { defineConfig } from 'tsup';

export default defineConfig([
  // Library builds (ESM + CJS) for bundler consumers.
  {
    entry: { index: 'src/index.ts' },
    format: ['esm', 'cjs'],
    dts: true,
    clean: true,
    platform: 'browser',
    target: 'es2019',
  },
  // Standalone IIFE for direct <script> use; exposes window.WebDecoyCaptcha.
  // tsup appends ".global.js" for the iife format, so the entry key is "webdecoy"
  // → dist/webdecoy.global.js (matches the package.json "browser" field).
  {
    entry: { webdecoy: 'src/global.ts' },
    format: ['iife'],
    globalName: 'WebDecoyCaptchaBundle',
    minify: true,
    platform: 'browser',
    target: 'es2019',
  },
]);
