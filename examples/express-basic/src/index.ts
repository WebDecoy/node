/**
 * Basic Express.js example with Web Decoy protection
 *
 * This example demonstrates:
 * - Basic middleware setup
 * - Protecting all routes
 * - Skipping health check endpoints
 * - Accessing detection info in routes
 */

import express from 'express';
import { webdecoy } from '@webdecoy/express';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

const app = express();
const port = process.env.PORT || 3000;

// Parse JSON bodies
app.use(express.json());

// Health check endpoint (unprotected)
app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

// Add Web Decoy protection
app.use(
  webdecoy({
    apiKey: process.env.WEBDECOY_API_KEY!,
    apiUrl: process.env.WEBDECOY_API_URL,
    threatScoreThreshold: 70, // Block requests with score >= 70
    skipPaths: ['/health'], // Don't protect health checks
    debug: process.env.NODE_ENV === 'development',
  })
);

// Protected routes
app.get('/', (req, res) => {
  res.json({
    message: 'Hello from Web Decoy protected API!',
    detection: req.webdecoy,
  });
});

app.get('/api/data', (req, res) => {
  // Access detection info
  const isBot = req.webdecoy?.bot_detected;
  const threatLevel = req.webdecoy?.threat_level;

  res.json({
    data: {
      message: 'This is protected data',
      timestamp: new Date().toISOString(),
    },
    security: {
      bot_detected: isBot,
      threat_level: threatLevel,
      detection_id: req.webdecoy?.detection_id,
    },
  });
});

app.post('/api/submit', (req, res) => {
  // Even POST requests are protected
  const { data } = req.body;

  res.json({
    success: true,
    received: data,
    detection_id: req.webdecoy?.detection_id,
  });
});

// Error handler
app.use((err: Error, req: express.Request, res: express.Response, next: express.NextFunction) => {
  console.error('Error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
  console.log(`🛡️  Web Decoy protection enabled`);
  console.log(`📊 Health check available at http://localhost:${port}/health`);
});
