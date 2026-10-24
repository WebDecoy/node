import { createApp } from './app';

const mode = process.env.WEBDECOY_MODE === 'enforce' ? 'enforce' : 'monitor';
const port = Number(process.env.PORT || 3000);
createApp(mode).listen(port, '127.0.0.1', () => {
  console.log(`WebDecoy local demo: http://127.0.0.1:${port} (${mode} mode)`);
  console.log('Compare / with /demo-decoy. No API key or cloud reporting.');
});
