// Jest test setup file
import { logger } from '../src/utils/logger';

// Set test environment variables
process.env.NODE_ENV = 'test';
process.env.LOG_LEVEL = 'error';
process.env.DATABASE_URL = 'postgresql://test:test@localhost:5432/kam_test';
process.env.JWT_SECRET = 'test-jwt-secret-for-testing-only';
process.env.JWT_EXPIRES_IN = '1h';
process.env.JWT_REFRESH_EXPIRES_IN = '7d';
process.env.BCRYPT_ROUNDS = '4'; // Lower rounds for faster tests
process.env.RATE_LIMIT_WINDOW_MS = '60000';
process.env.RATE_LIMIT_MAX_REQUESTS = '1000';
process.env.RATE_LIMIT_AUTH_MAX = '50';
process.env.CORS_ORIGINS = 'http://localhost:3000,http://localhost:3001';
process.env.PORT = '3001';

// Mock console methods for cleaner test output
global.console = {
  ...console,
  log: jest.fn(),
  debug: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  // Keep error for debugging failed tests
  error: console.error,
};

// Set test timeout
jest.setTimeout(30000);

// Global test setup
beforeAll(async () => {
  // Silence winston logger during tests
  logger.silent = true;
});

afterAll(async () => {
  // Re-enable winston logger
  logger.silent = false;
});

// Global test utilities and configurations
export const testConfig = {
  database: {
    url: 'postgresql://test:test@localhost:5432/kam_test',
    poolSize: 2, // Smaller pool for tests
    timeout: 5000
  },
  jwt: {
    secret: 'test-jwt-secret-for-testing-only',
    expiresIn: '1h',
    refreshExpiresIn: '7d'
  },
  security: {
    bcryptRounds: 4,
    corsOrigins: ['http://localhost:3000', 'http://localhost:3001']
  },
  rateLimit: {
    windowMs: 60000,
    maxRequests: 1000,
    authMax: 50
  },
  app: {
    name: 'KAM Assessment Portal Test',
    version: '1.0.0',
    port: 3001,
    env: 'test'
  },
  logging: {
    level: 'error',
    dir: './logs'
  }
};

// Mock data for tests
export const mockData = {
  validEmail: 'test@example.com',
  validPassword: 'TestPassword123!',
  validTenantDomain: 'test-company',
  validUserId: '123e4567-e89b-12d3-a456-426614174000',
  validTenantId: '123e4567-e89b-12d3-a456-426614174001',
  validAssessmentId: '123e4567-e89b-12d3-a456-426614174002',
  validQuestionId: '123e4567-e89b-12d3-a456-426614174003',
};

// Helper function to generate UUID
const generateUUID = () => {
  const { v4: uuidv4 } = require('uuid');
  return uuidv4();
};

// Test helper functions
export const testHelpers = {
  // Generate JWT token for testing
  generateTestToken: (payload: any) => {
    const jwt = require('jsonwebtoken');
    return jwt.sign(payload, testConfig.jwt.secret, { expiresIn: testConfig.jwt.expiresIn });
  },
  
  // Generate UUID for testing
  generateTestUUID: () => generateUUID(),
  
  // Create test user payload
  createTestUser: (overrides: any = {}) => ({
    id: generateUUID(),
    tenantId: generateUUID(),
    email: mockData.validEmail,
    firstName: 'Test',
    lastName: 'User',
    role: 'user',
    isActive: true,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  }),
  
  // Create test tenant payload
  createTestTenant: (overrides: any = {}) => ({
    id: generateUUID(),
    name: 'Test Company',
    domain: mockData.validTenantDomain,
    settings: {},
    subscriptionTier: 'basic',
    maxUsers: 100,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  })
};
