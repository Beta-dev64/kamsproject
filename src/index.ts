import express from 'express';
import helmet from 'helmet';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import compression from 'compression';
import { securityMiddleware } from './middleware/security';
import config from './config';
import { logger } from './utils/logger';
import { db } from './database';

// Middleware imports
import { requestIdMiddleware, requestLogger, performanceMiddleware } from './middleware/requestLogger';
import { apiRateLimit } from './middleware/rateLimiter';
import { errorHandler, notFoundHandler, gracefulShutdown } from './middleware/errorHandler';
import { extractTenant, tenantIsolation } from './middleware/tenantIsolation';

// Create Express application
const app: any = express();

// Trust proxy for correct IPs and HTTPS handling behind load balancers
app.set('trust proxy', true);

// Enhanced security middleware - should be first
app.use(helmet({
  contentSecurityPolicy: false, // We'll use our custom CSP
  crossOriginEmbedderPolicy: false,
}));

// Optional HTTPS redirect in production
if (config.app.env === 'production') {
  app.use((req: any, res: any, next: any) => {
    const proto = req.headers['x-forwarded-proto'] || req.protocol;
    if (proto !== 'https') {
      return res.redirect(301, `https://${req.headers.host}${req.originalUrl}`);
    }
    next();
  });
}

// Apply comprehensive security headers
app.use(securityMiddleware.headers);

// Content Security Policy
app.use(securityMiddleware.csp);

// Request timeout protection
app.use(securityMiddleware.timeout(30000));

// Request size limiting (applied before body parsing)
app.use(securityMiddleware.requestSize(10 * 1024 * 1024)); // 10MB

// CORS configuration
app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) {
      return callback(null, true);
    }
    
    if (config.security.corsOrigins.includes(origin)) {
      return callback(null, true);
    }
    
    // For development, allow any localhost origin
    if (config.app.env === 'development' && origin.includes('localhost')) {
      return callback(null, true);
    }
    
    callback(new Error('Not allowed by CORS'));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-Tenant-Domain', 'X-Request-ID'],
  exposedHeaders: ['X-Request-ID', 'X-Rate-Limit-Remaining'],
}));

// Request parsing middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));
app.use(cookieParser());

// Enhanced security middleware (after body parsing)
app.use(securityMiddleware.xss);
app.use(securityMiddleware.sqlInjection);
app.use(securityMiddleware.noSqlInjection);
app.use(securityMiddleware.hpp as any); // Type assertion for hpp compatibility

// Compression middleware
app.use(compression());

// Request tracking middleware
app.use(requestIdMiddleware);
app.use(performanceMiddleware);

// Tenant extraction will be applied per-route as needed

// Advanced rate limiting with slow down (global)
app.use(securityMiddleware.slowDown({
  windowMs: 15 * 60 * 1000, // 15 minutes
  delayAfter: 20, // Allow 20 requests per window without delay
  delayMs: 500, // Add 500ms delay per request after delayAfter
  maxDelayMs: 20000, // Maximum delay of 20 seconds
}));

// Rate limiting for API routes
app.use('/api/', apiRateLimit);

// Request logging (after rate limiting to avoid logging rate limited requests)
if (config.app.env !== 'test') {
  app.use(requestLogger);
}

// Tenant isolation for all API routes
app.use('/api/', tenantIsolation);

// Health check routes (before authentication)
app.get('/health', (req: any, res: any) => {
  res.status(200).json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: config.app.version,
    environment: config.app.env,
    uptime: process.uptime(),
  });
});

app.get('/health/db', async (req: any, res: any) => {
  try {
    const isHealthy = await db.healthCheck();
    const stats = db.getPoolStats();
    
    if (isHealthy) {
      res.status(200).json({
        status: 'healthy',
        service: 'database',
        stats,
      });
    } else {
      res.status(503).json({
        status: 'unhealthy',
        service: 'database',
        error: 'Health check failed',
      });
    }
  } catch (error) {
    res.status(503).json({
      status: 'unhealthy',
      service: 'database',
      error: error instanceof Error ? error.message : 'Unknown error',
    });
  }
});

// API information endpoint
app.get('/api', (req: any, res: any) => {
  res.json({
    name: config.app.name,
    version: config.app.version,
    environment: config.app.env,
    documentation: '/api/docs',
    health: '/health',
    timestamp: new Date().toISOString(),
  });
});

// API routes with tenant extraction
import apiRoutes from './routes';

// Regular API routes with tenant extraction
app.use('/api', extractTenant, apiRoutes);

// 404 handler for unmatched routes
app.use(notFoundHandler);

// Global error handler (must be last)
app.use(errorHandler);

// Start server
const startServer = async () => {
  try {
    // Test database connection
    const dbHealthy = await db.healthCheck();
    if (!dbHealthy) {
      throw new Error('Database connection failed');
    }
    
    logger.info('Database connection established');
    
    // Start HTTP server
    const server = app.listen(config.app.port, () => {
      logger.info(`🚀 Server started successfully`, {
        name: config.app.name,
        version: config.app.version,
        environment: config.app.env,
        port: config.app.port,
        baseUrl: `http://localhost:${config.app.port}`,
        healthCheck: `http://localhost:${config.app.port}/health`,
        apiDocs: `http://localhost:${config.app.port}/api`,
      });
    });

    // Setup graceful shutdown
    gracefulShutdown(server);
    
    return server;
  } catch (error) {
    logger.error('Failed to start server', {
      error: error instanceof Error ? error.message : 'Unknown error',
    });
    process.exit(1);
  }
};

// Start server if running directly
if (require.main === module) {
  startServer();
}

export { app, startServer };