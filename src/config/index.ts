import dotenv from 'dotenv';
import { AppConfig } from '../types';

// Load environment variables
dotenv.config();

const config: AppConfig = {
  app: {
    name: process.env.APP_NAME || 'KAM Assessment Portal',
    version: process.env.APP_VERSION || '1.0.0',
    port: parseInt(process.env.PORT || '3000', 10),
    env: (process.env.NODE_ENV as AppConfig['app']['env']) || 'development',
  },
  database: {
    url: process.env.DATABASE_URL || 'postgresql://localhost:5432/kam_dev',
    poolSize: parseInt(process.env.DB_POOL_SIZE || '20', 10),
    timeout: parseInt(process.env.DB_TIMEOUT || '2000', 10),
  },
  jwt: {
    secret: process.env.JWT_SECRET || 'fallback-secret-change-in-production',
    expiresIn: process.env.JWT_EXPIRES_IN || '15m',
    refreshExpiresIn: process.env.JWT_REFRESH_EXPIRES_IN || '7d',
  },
  security: {
    bcryptRounds: parseInt(process.env.BCRYPT_ROUNDS || '12', 10),
    corsOrigins: process.env.CORS_ORIGINS?.split(',') || ['http://localhost:3000'],
  },
  rateLimit: {
    windowMs: parseInt(process.env.RATE_LIMIT_WINDOW_MS || '60000', 10),
    maxRequests: parseInt(process.env.RATE_LIMIT_MAX_REQUESTS || '100', 10),
    authMax: parseInt(process.env.RATE_LIMIT_AUTH_MAX || '5', 10),
  },
  logging: {
    level: process.env.LOG_LEVEL || 'info',
    dir: process.env.LOG_DIR || './logs',
  },
};

// Validation
const requiredEnvVars = ['DATABASE_URL', 'JWT_SECRET'];

if (config.app.env === 'production') {
  for (const envVar of requiredEnvVars) {
    if (!process.env[envVar]) {
      throw new Error(`Missing required environment variable: ${envVar}`);
    }
  }
}

// Warn about using fallback values in production
if (config.app.env === 'production') {
  if (config.jwt.secret === 'fallback-secret-change-in-production') {
    console.warn('WARNING: Using fallback JWT secret in production!');
  }
}

export default config;