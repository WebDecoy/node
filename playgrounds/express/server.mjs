import { createApp } from './app.mjs';
const port = Number(process.env.PORT || 3000);
createApp().listen(port, '127.0.0.1', () => {
  console.log(`WebDecoy playground: http://127.0.0.1:${port}`);
  console.log('Open the preview, then send an ordinary or decoy request. No API key required.');
});
