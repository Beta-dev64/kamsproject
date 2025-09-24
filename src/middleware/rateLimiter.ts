import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';
import config from '../config';
import { logger } from '../utils/logger';
import { AuthRequest } from '../types';

// Local IP key generator compatible across express-rate-limit versions
const ipKey = (req: AuthRequest): string => {
  const xff = (req.headers['x-forwarded-for'] as string | undefined)?.split(',')[0]?.trim();
  return req.ip || xff || req.socket?.remoteAddress || (req as any).connection?.remoteAddress || 'unknown';
};

// Use the secure ipKeyGenerator as a base
const baseKeyGenerator = (req: AuthRequest): string => {
  const ip = ipKey(req); // Correct way to handle IP
  const tenantId = req.tenantId || 'no-tenant';
  const userId = req.user?.id || 'anonymous';
  
  return `${ip}:${tenantId}:${userId}`;
};

// Custom rate limit handler
const rateLimitHandler = (req: AuthRequest, res: Response) => {
  const ip = req.ip || req.connection.remoteAddress || 'unknown';
  
  // Log rate limit violation
  logger.warn('Rate limit exceeded', {
    ip,
    tenantId: req.tenantId,
    userId: req.user?.id,
    endpoint: req.originalUrl,
    method: req.method,
    userAgent: req.get('User-Agent'),
    requestId: req.requestId,
  });

  res.status(429).json({
    error: 'Too many requests',
    message: 'Rate limit exceeded. Please try again later.',
    retryAfter: res.getHeader('Retry-After'),
  });
};

// General API rate limiter
export const apiRateLimit = rateLimit({
  windowMs: config.rateLimit.windowMs, // 1 minute
  max: config.rateLimit.maxRequests, // 100 requests per window
  keyGenerator: baseKeyGenerator,
  handler: rateLimitHandler,
  standardHeaders: true,
  legacyHeaders: false,
  message: {
    error: 'Too many requests',
    message: 'Rate limit exceeded for API calls',
  },
});

// Strict rate limiter for authentication endpoints
export const authRateLimit = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: config.rateLimit.authMax, // 5 attempts per window
  keyGenerator: (req: AuthRequest) => {
    const ip = ipKey(req); // Use the secure generator
    const email = req.body?.email || 'no-email';
    return `${ip}:${email}`;
  },
  handler: (req: AuthRequest, res: Response) => {
    const ip = req.ip || req.connection.remoteAddress || 'unknown';
    
    logger.warn('Auth rate limit exceeded', {
      ip,
      email: req.body?.email,
      endpoint: req.originalUrl,
      method: req.method,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
      attemptedCredentials: !!req.body?.password,
    });

    res.status(429).json({
      error: 'Too many authentication attempts',
      message: 'Account temporarily locked due to multiple failed login attempts. Please try again later.',
      retryAfter: res.getHeader('Retry-After'),
      lockoutDuration: '15 minutes',
    });
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
});

// Password reset rate limiter
export const passwordResetRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 password reset attempts per hour per email
  keyGenerator: (req: AuthRequest) => {
    const ip = ipKey(req); // Use the secure generator
    const email = req.body?.email || 'no-email';
    return `password-reset:${ip}:${email}`;
  },
  handler: rateLimitHandler,
  message: {
    error: 'Too many password reset attempts',
    message: 'Please wait before requesting another password reset',
  },
});

// Registration rate limiter
export const registrationRateLimit = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 registrations per hour per IP
  keyGenerator: ipKey, // Use the secure generator directly
  handler: rateLimitHandler,
  message: {
    error: 'Too many registration attempts',
    message: 'Registration limit exceeded. Please try again later.',
  },
});

// File upload rate limiter
export const uploadRateLimit = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 20, // 20 uploads per 10 minutes per user
  keyGenerator: baseKeyGenerator,
  handler: rateLimitHandler,
  message: {
    error: 'Too many file uploads',
    message: 'Upload limit exceeded. Please wait before uploading more files.',
  },
});

// Admin operations rate limiter
export const adminRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 50, // 50 admin operations per 5 minutes
  keyGenerator: baseKeyGenerator,
  handler: rateLimitHandler,
  message: {
    error: 'Too many administrative operations',
    message: 'Admin operation limit exceeded. Please slow down.',
  },
});

// Export a factory function to create custom rate limiters
export const createRateLimit = (
  windowMs: number,
  max: number,
  keyGen?: (req: AuthRequest) => string
) => {
  return rateLimit({
    windowMs,
    max,
    keyGenerator: keyGen || baseKeyGenerator, // Use the secure base generator as the default
    handler: rateLimitHandler,
    standardHeaders: true,
    legacyHeaders: false,
  });
};

// Assessment-specific rate limiters
export const assessmentSubmissionRateLimit = rateLimit({
  windowMs: 5 * 60 * 1000, // 5 minutes
  max: 10, // 10 assessment submissions per 5 minutes
  keyGenerator: baseKeyGenerator,
  handler: rateLimitHandler,
  message: {
    error: 'Too many assessment submissions',
    message: 'Assessment submission limit exceeded. Please wait before submitting again.',
  },
});

export const bulkOperationRateLimit = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // 5 bulk operations per 10 minutes
  keyGenerator: baseKeyGenerator,
  handler: rateLimitHandler,
  message: {
    error: 'Too many bulk operations',
    message: 'Bulk operation limit exceeded. Please wait before performing more bulk operations.',
  },
});

// Export all rate limiters as a single object for convenience
export const rateLimiters = {
  api: apiRateLimit,
  auth: authRateLimit,
  passwordReset: passwordResetRateLimit,
  registration: registrationRateLimit,
  uploads: uploadRateLimit,
  adminOperations: adminRateLimit,
  sensitiveOperations: adminRateLimit, // Alias for sensitive operations
  assessmentSubmission: assessmentSubmissionRateLimit,
  bulkOperation: bulkOperationRateLimit,
};

// Common rate limiters for different resource operations
export const rateLimiter = {
  // Standard CRUD operations
  createResource: createRateLimit(1 * 60 * 1000, 20), // 20 creates per minute
  readResource: apiRateLimit, // Use general API rate limit for reads
  updateResource: createRateLimit(1 * 60 * 1000, 30), // 30 updates per minute
  deleteResource: createRateLimit(1 * 60 * 1000, 10), // 10 deletes per minute
  
  // Specific operations
  submitScores: assessmentSubmissionRateLimit,
  bulkOperation: bulkOperationRateLimit,
  sensitiveOperation: adminRateLimit,
};