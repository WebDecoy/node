# Express.js Basic Example

Basic example of Web Decoy integration with Express.js.

## Setup

1. Install dependencies:

```bash
npm install
```

2. Copy `.env.example` to `.env` and add your API key:

```bash
cp .env.example .env
```

3. Edit `.env` and set your Web Decoy API key:

```env
WEBDECOY_API_KEY=sk_live_your_key_here
```

## Run

Development mode:

```bash
npm run dev
```

Production build:

```bash
npm run build
npm start
```

## Test

The server will start on `http://localhost:3000`.

### Endpoints

- `GET /health` - Health check (unprotected)
- `GET /` - Protected home endpoint
- `GET /api/data` - Protected API endpoint
- `POST /api/submit` - Protected POST endpoint

### Testing Bot Detection

Test with a normal browser:

```bash
curl http://localhost:3000/api/data
```

The request will likely be blocked or challenged due to the curl user-agent.

Test with browser headers:

```bash
curl http://localhost:3000/api/data \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)" \
  -H "Accept: text/html,application/xhtml+xml" \
  -H "Accept-Language: en-US,en;q=0.9"
```

This should pass with a lower threat score.

## What's Happening

1. All requests (except `/health`) go through Web Decoy middleware
2. The middleware extracts request metadata (IP, headers, etc.)
3. Local analysis checks for suspicious patterns
4. If needed, server-side verification with TLS fingerprinting
5. Request is allowed or blocked based on threat score
6. Detection info is available via `req.webdecoy`

## Learn More

See the [main README](../../README.md) for more documentation.
