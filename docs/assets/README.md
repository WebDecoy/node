# Node SDK branding

`node-banner.svg` is the editable source for the 1600 × 800 README banner.
`node-banner.png` is the GitHub/npm-compatible render. It uses the WebDecoy duck,
dark background and pink accents. The rule decision is explicitly an example,
not a captured customer result or an efficacy benchmark.

The PNG also has a 2:1 aspect ratio suitable for the repository's GitHub social
preview. Upload it under **Settings → General → Social preview**. A README image
does not automatically configure that setting.

To regenerate from the SVG with Sharp installed in your development environment:

```js
import sharp from 'sharp';
await sharp('docs/assets/node-banner.svg').png().toFile('docs/assets/node-banner.png');
```

The core package README uses an absolute `raw.githubusercontent.com` URL so the
banner can render on npm. That URL becomes available after this asset is merged
to `main`; npm README and keyword changes require the next normal package release.
