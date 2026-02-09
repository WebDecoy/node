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

Use these curl commands to test different bot detection scenarios:

#### 1. Chrome Browser (should ALLOW)

Real browser with full security headers - passes local analysis with minimal threat score:

```bash
curl -s http://localhost:3000/ \
  -H "User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36" \
  -H "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8" \
  -H "Accept-Language: en-US,en;q=0.5" \
  -H "Accept-Encoding: gzip, deflate, br" \
  -H "Sec-Ch-Ua: \"Not_A Brand\";v=\"8\", \"Chromium\";v=\"120\", \"Google Chrome\";v=\"120\"" \
  -H "Sec-Ch-Ua-Mobile: ?0" \
  -H "Sec-Ch-Ua-Platform: \"macOS\"" \
  -H "Sec-Fetch-Dest: document" \
  -H "Sec-Fetch-Mode: navigate" \
  -H "Sec-Fetch-Site: none" \
  -H "Sec-Fetch-User: ?1"
```

#### 2. Python Requests (should BLOCK)

Common scraping library - easily detected and blocked:

```bash
curl -s http://localhost:3000/ \
  -H "User-Agent: python-requests/2.28.0"
```

#### 3. Curl User-Agent (should BLOCK)

Default curl user-agent - flagged as automated tool:

```bash
curl -s http://localhost:3000/ \
  -H "User-Agent: curl/8.1.2"
```

#### 4. Empty User-Agent (should BLOCK)

Missing user-agent is highly suspicious:

```bash
curl -s http://localhost:3000/ \
  -H "User-Agent: "
```

#### 5. Scrapy Bot (should BLOCK)

Known web scraping framework:

```bash
curl -s http://localhost:3000/ \
  -H "User-Agent: Scrapy/2.8.0 (+https://scrapy.org)"
```

#### 6. Go HTTP Client (should BLOCK)

Default Go HTTP client user-agent:

```bash
curl -s http://localhost:3000/ \
  -H "User-Agent: Go-http-client/1.1"
```

### Simulating External IP Addresses

When testing locally, connections come from `::1` (IPv6 localhost). To simulate external IPs for realistic testing, use the `X-Forwarded-For` header:

```bash
curl -s http://localhost:3000/ \
  -H "User-Agent: python-requests/2.28.0" \
  -H "X-Forwarded-For: 203.0.113.50"
```

This detection will show the IP `203.0.113.50` in the Web Decoy dashboard instead of `::1`.

## What's Happening

1. All requests (except `/health`) go through Web Decoy middleware
2. The middleware extracts request metadata (IP, headers, etc.)
3. Local analysis checks for suspicious patterns
4. If needed, server-side verification with TLS fingerprinting
5. Request is allowed or blocked based on threat score
6. Detection info is available via `req.webdecoy`

## Learn More

See the [main README](../../README.md) for more documentation.
