# Dashboard Integration Guide

This guide explains how customers will obtain API keys from the Web Decoy dashboard and integrate the SDK.

## Getting an API Key

### Step 1: Create an Organization

1. Sign up or log in to [dashboard.webdecoy.com](https://dashboard.webdecoy.com)
2. Create a new organization (if not already done)
3. Navigate to your organization's settings

### Step 2: Generate an API Key

1. Go to **Settings** → **API Keys**
2. Click **"Create API Key"**
3. Fill in the form:
   - **Name**: e.g., "Production API" or "Development"
   - **Property**: Select which property (optional - leave blank for org-wide)
   - **Scopes**: Select required permissions:
     - `detections:read` - Read detection data
     - `detections:write` - Write new detections (required for SDK)
   - **Expiration**: Set expiration date (optional)
4. Click **"Generate Key"**
5. **Copy the API key immediately** - it will only be shown once!

### API Key Format

```
sk_live_AbCdEfGh1234567890123456
```

- Prefix: `sk_live_` for production, `sk_test_` for testing
- Length: 32 random characters after prefix
- Storage: Store securely in environment variables

### API Key Scopes

The SDK requires these scopes:

- **`detections:write`** (Required) - Submit detections to the platform
- **`detections:read`** (Optional) - Read detection history

## Integration Steps

### 1. Install the SDK

```bash
npm install @webdecoy/node @webdecoy/express
```

### 2. Set Environment Variables

Create a `.env` file:

```env
WEBDECOY_API_KEY=sk_live_your_key_here
WEBDECOY_API_URL=https://api.webdecoy.com
```

**Never commit `.env` to version control!**

### 3. Configure Your Application

#### Express.js

```typescript
import express from 'express';
import { webdecoy } from '@webdecoy/express';
import dotenv from 'dotenv';

dotenv.config();

const app = express();

app.use(webdecoy({
  apiKey: process.env.WEBDECOY_API_KEY!,
}));
```

#### Generic Node.js

```typescript
import { WebDecoy } from '@webdecoy/node';

const webdecoy = new WebDecoy({
  apiKey: process.env.WEBDECOY_API_KEY!,
});

const result = await webdecoy.protect({ /* ... */ });
```

### 4. Test the Integration

Run the validation helper:

```typescript
const validation = await webdecoy.validateConfig();
if (!validation.valid) {
  console.error('API key validation failed:', validation.error);
}
```

### 5. View Detections in Dashboard

1. Go to **Dashboard** → **Detections**
2. See real-time detections from your application
3. Filter by property, threat level, bot type
4. Review detection details and metadata

## Dashboard Features

### Detection Monitoring

**Real-time Dashboard:**
- Geographic detection map
- Detection trends over time
- Rule execution statistics
- Threat level breakdown

**Detection Details:**
- IP address and geolocation
- User-Agent and headers
- TLS fingerprint (if available)
- Risk score and threat level
- Bot type (if detected)
- Response action taken

### Response Rules

Configure automated responses:

1. Go to **Response Rules**
2. Create a new rule:
   - **Trigger**: Threat score threshold, bot type, etc.
   - **Action**: Block IP, challenge, webhook, email
   - **Duration**: Temporary or permanent
3. Rules are automatically enforced by the SDK

### Analytics

View comprehensive analytics:

- **Detection Trends**: Daily, weekly, monthly charts
- **Top Threat IPs**: Most frequent attackers
- **Bot Types**: Distribution of detected bots
- **Geographic Heatmap**: Attack sources by country
- **Response Actions**: Rules triggered and enforced

### API Key Management

Manage your API keys:

- **View Keys**: See all active keys (partial key shown)
- **Revoke Keys**: Immediately disable compromised keys
- **Rotate Keys**: Generate new keys and deprecate old ones
- **Monitor Usage**: Track API calls per key

## Property-Scoped vs Organization-Scoped Keys

### Organization-Scoped Key

- **Access**: All properties in the organization
- **Use Case**: Single application or unified monitoring
- **Creation**: Leave "Property" field blank when creating

### Property-Scoped Key

- **Access**: Only specific property
- **Use Case**: Multi-tenant apps, different environments
- **Creation**: Select property when creating key

## Security Best Practices

### 1. Environment Variables

```bash
# Good
WEBDECOY_API_KEY=sk_live_xxxxx

# Bad - don't hardcode!
const apiKey = 'sk_live_xxxxx';
```

### 2. Key Rotation

Rotate keys periodically:

1. Generate new API key
2. Update environment variables in all deployments
3. Monitor for errors
4. Revoke old key after grace period

### 3. Least Privilege

Only grant necessary scopes:

- SDK usage: `detections:write`
- Analytics dashboard: `detections:read`
- Admin tools: All scopes

### 4. Monitor Usage

Regularly check API key usage:

- Unexpected spikes in requests
- Requests from unknown IPs
- High error rates

### 5. Secure Storage

Production deployment:

- **AWS**: Use AWS Secrets Manager
- **GCP**: Use Secret Manager
- **Azure**: Use Key Vault
- **Docker**: Use secrets, not environment
- **Kubernetes**: Use Secrets resource

## Troubleshooting

### Invalid API Key

**Error:** `Invalid API key. Please check your Web Decoy configuration.`

**Solutions:**
1. Verify key is correct (check for extra spaces)
2. Ensure key hasn't been revoked
3. Check key has `detections:write` scope
4. Verify key hasn't expired

### Rate Limit Exceeded

**Error:** `Rate limit exceeded. Please try again later.`

**Solutions:**
1. Check your plan limits in dashboard
2. Implement request caching
3. Upgrade to higher tier plan
4. Contact support for temporary increase

### Connection Failed

**Error:** `Unable to connect to Web Decoy service.`

**Solutions:**
1. Check internet connectivity
2. Verify `WEBDECOY_API_URL` is correct
3. Check firewall/proxy settings
4. Verify Web Decoy service status

### No Detections Appearing

**Solutions:**
1. Verify API key has `detections:write` scope
2. Check application is making requests
3. Look for errors in application logs
4. Verify middleware is configured correctly
5. Check property filter in dashboard

## Support

If you need help:

1. **Documentation**: [docs.webdecoy.com](https://docs.webdecoy.com)
2. **Support Email**: support@webdecoy.com
3. **Dashboard**: Settings → Support
4. **Discord**: Community support and discussions

## Example Integration Checklist

- [ ] Created organization in dashboard
- [ ] Generated API key with `detections:write` scope
- [ ] Stored API key in `.env` file
- [ ] Added `.env` to `.gitignore`
- [ ] Installed SDK packages
- [ ] Configured middleware/SDK
- [ ] Tested with `validateConfig()`
- [ ] Made test requests
- [ ] Verified detections in dashboard
- [ ] Configured response rules (optional)
- [ ] Deployed to production
- [ ] Monitored for errors
- [ ] Set up key rotation schedule

## Next Steps

After integration:

1. **Fine-tune Thresholds**: Adjust `threatScoreThreshold` based on your needs
2. **Configure Rules**: Set up automated response actions
3. **Monitor Analytics**: Review detection trends
4. **Optimize Paths**: Skip protection for static assets
5. **Plan Rotation**: Schedule API key rotation
