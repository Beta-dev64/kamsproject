import { Request, Response, NextFunction } from 'express';
import csurf from 'csurf';
import hpp from 'hpp';
import mongoSanitize from 'express-mongo-sanitize';
import slowDown from 'express-slow-down';
import { body, validationResult } from 'express-validator';
import DOMPurify from 'dompurify';
import { JSDOM } from 'jsdom';
import { AuthRequest } from '../types';
import { logger } from '../utils/logger';
import { ValidationError, ForbiddenError } from './errorHandler';

// Create DOMPurify instance for server-side XSS prevention
const window = new JSDOM('').window;
const purify = DOMPurify(window as any);

/**
 * CSRF Protection Configuration
 */
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict',
    maxAge: 3600000, // 1 hour
  },
  ignoreMethods: ['GET', 'HEAD', 'OPTIONS'],
  value: (req: any) => {
    // Look for token in multiple places
    return req.body._csrf || 
           req.query._csrf || 
           req.headers['csrf-token'] || 
           req.headers['x-csrf-token'];
  },
});

/**
 * Enhanced XSS Protection Middleware
 */
export const xssProtection = (req: Request, res: Response, next: NextFunction) => {
  try {
    // Sanitize request body
    if (req.body && typeof req.body === 'object') {
      req.body = sanitizeObject(req.body);
    }

    // Sanitize query parameters
    if (req.query && typeof req.query === 'object') {
      req.query = sanitizeObject(req.query);
    }

    // Sanitize URL parameters
    if (req.params && typeof req.params === 'object') {
      req.params = sanitizeObject(req.params);
    }

    // Set XSS protection headers
    res.setHeader('X-XSS-Protection', '1; mode=block');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    next();
  } catch (error) {
    logger.error('XSS protection error', {
      error: error instanceof Error ? error.message : String(error),
      url: req.originalUrl,
      method: req.method,
    });
    throw new ValidationError('Invalid input detected');
  }
};

/**
 * Deep sanitize object to prevent XSS
 */
function sanitizeObject(obj: any): any {
  if (obj === null || obj === undefined) {
    return obj;
  }

  if (typeof obj === 'string') {
    // Use DOMPurify for comprehensive XSS protection
    let cleaned = purify.sanitize(obj, { 
      ALLOWED_TAGS: [], // Remove all HTML tags
      ALLOWED_ATTR: [], // Remove all attributes
    });
    
    // Additional custom sanitization
    cleaned = cleaned
      .replace(/javascript:/gi, '') // Remove javascript: protocols
      .replace(/data:/gi, '') // Remove data: protocols
      .replace(/vbscript:/gi, '') // Remove vbscript: protocols
      .replace(/on\w+\s*=/gi, '') // Remove event handlers
      .replace(/<script[\s\S]*?<\/script>/gi, '') // Remove any remaining script tags
      .replace(/expression\s*\(/gi, '') // Remove CSS expressions
      .trim();
    
    return cleaned;
  }

  if (Array.isArray(obj)) {
    return obj.map(item => sanitizeObject(item));
  }

  if (typeof obj === 'object') {
    const sanitized: any = {};
    for (const key in obj) {
      if (obj.hasOwnProperty(key)) {
        // Sanitize both key and value
        const cleanKey = sanitizeObject(key);
        sanitized[cleanKey] = sanitizeObject(obj[key]);
      }
    }
    return sanitized;
  }

  return obj;
}

/**
 * SQL Injection Protection (for additional safety beyond parameterized queries)
 */
export const sqlInjectionProtection = (req: Request, res: Response, next: NextFunction) => {
  try {
    const suspiciousPatterns = [
      /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/gi,
      /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
      /(\b(OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/gi,
      /(UNION\s+SELECT)/gi,
      /(--|\*\/|\/\*)/g,
      /(\bEXEC\s*\()/gi,
      /(\bCHAR\s*\()/gi,
      /(\bCAST\s*\()/gi,
    ];

    const checkForSqlInjection = (value: string): boolean => {
      return suspiciousPatterns.some(pattern => pattern.test(value));
    };

    const validateObject = (obj: any, path: string = 'root'): void => {
      if (typeof obj === 'string') {
        if (checkForSqlInjection(obj)) {
          logger.warn('Potential SQL injection attempt detected', {
            path,
            value: '[REDACTED]',
            url: req.originalUrl,
            method: req.method,
            ip: req.ip,
            userAgent: req.get('User-Agent'),
          });
          throw new ValidationError('Invalid input detected');
        }
      } else if (Array.isArray(obj)) {
        obj.forEach((item, index) => validateObject(item, `${path}[${index}]`));
      } else if (obj && typeof obj === 'object') {
        for (const key in obj) {
          if (obj.hasOwnProperty(key)) {
            validateObject(obj[key], `${path}.${key}`);
          }
        }
      }
    };

    // Check all input sources
    if (req.body) validateObject(req.body, 'body');
    if (req.query) validateObject(req.query, 'query');
    if (req.params) validateObject(req.params, 'params');

    next();
  } catch (error) {
    if (error instanceof ValidationError) {
      throw error;
    }
    logger.error('SQL injection protection error', {
      error: error instanceof Error ? error.message : String(error),
      url: req.originalUrl,
    });
    throw new ValidationError('Input validation failed');
  }
};

/**
 * NoSQL Injection Protection (enhanced)
 */
export const noSqlInjectionProtection = mongoSanitize({
  replaceWith: '_',
  onSanitize: ({ req, key }: any) => {
    logger.warn('NoSQL injection attempt sanitized', {
      key,
      url: req.originalUrl,
      method: req.method,
      ip: req.ip,
    });
  },
});

/**
 * HTTP Parameter Pollution Protection
 */
export const httpParameterPollutionProtection: any = hpp({
  whitelist: ['tags', 'categories', 'roles', 'permissions'], // Allow arrays for these fields
});

/**
 * Advanced Rate Limiting with Slow Down
 */
export const createSlowDown: any = (options: {
  windowMs?: number;
  delayAfter?: number;
  delayMs?: number;
  maxDelayMs?: number;
  skipSuccessfulRequests?: boolean;
} = {}) => {
  return slowDown({
    windowMs: options.windowMs || 15 * 60 * 1000, // 15 minutes
    delayAfter: options.delayAfter || 5, // Allow 5 requests per windowMs without delay
    delayMs: options.delayMs || 500, // Add 500ms delay per request after delayAfter
    maxDelayMs: options.maxDelayMs || 20000, // Maximum delay of 20 seconds
    skipSuccessfulRequests: options.skipSuccessfulRequests || false,
    keyGenerator: (req: AuthRequest) => {
      // Create composite key with IP, tenant, and user for more precise limiting
      const ip = req.ip || req.connection.remoteAddress || 'unknown';
      const tenantId = req.tenantId || 'no-tenant';
      const userId = req.user?.id || 'anonymous';
      return `${ip}:${tenantId}:${userId}`;
    },
    // onLimitReached callback not available in express-slow-down
  });
};

/**
 * Content Security Policy Middleware
 */
export const contentSecurityPolicy = (req: Request, res: Response, next: NextFunction) => {
  const cspDirectives = [
    "default-src 'self'",
    "script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src 'self' https://fonts.gstatic.com",
    "img-src 'self' data: https:",
    "connect-src 'self' https://api.your-domain.com",
    "frame-ancestors 'none'",
    "base-uri 'self'",
    "object-src 'none'",
    "media-src 'self'",
  ].join('; ');

  res.setHeader('Content-Security-Policy', cspDirectives);
  next();
};

/**
 * Comprehensive Input Validation Chain
 */
export const createValidationChain = (validations: any[]) => {
  return [
    ...validations,
    (req: Request, res: Response, next: NextFunction) => {
      const errors = validationResult(req);
      if (!errors.isEmpty()) {
        const errorDetails = errors.array().map(error => ({
          field: error.type === 'field' ? error.path : 'unknown',
          message: error.msg,
          value: '[REDACTED]', // Don't expose actual values in errors
        }));

        logger.warn('Input validation failed', {
          errors: errorDetails,
          url: req.originalUrl,
          method: req.method,
          ip: req.ip,
        });

        throw new ValidationError('Input validation failed', errorDetails);
      }
      next();
    },
  ];
};

/**
 * Security Headers Middleware
 */
export const securityHeaders = (req: Request, res: Response, next: NextFunction) => {
  // Strict Transport Security
  if (process.env.NODE_ENV === 'production') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains; preload');
  }

  // Prevent MIME type sniffing
  res.setHeader('X-Content-Type-Options', 'nosniff');

  // XSS Protection
  res.setHeader('X-XSS-Protection', '1; mode=block');

  // Frame Options
  res.setHeader('X-Frame-Options', 'DENY');

  // Referrer Policy
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

  // Permissions Policy (formerly Feature Policy)
  res.setHeader('Permissions-Policy', 
    'camera=(), microphone=(), geolocation=(), magnetometer=(), gyroscope=(), speaker=(), vibrate=(), fullscreen=(), payment=()'
  );

  // Remove server information
  res.removeHeader('X-Powered-By');
  res.setHeader('Server', 'KAM-Portal');

  next();
};

/**
 * Request Size Limiting Middleware
 */
export const requestSizeLimit = (maxSize: number = 10 * 1024 * 1024) => { // 10MB default
  return (req: Request, res: Response, next: NextFunction) => {
    const contentLength = parseInt(req.get('content-length') || '0');
    
    if (contentLength > maxSize) {
      logger.warn('Request size too large', {
        contentLength,
        maxSize,
        url: req.originalUrl,
        method: req.method,
        ip: req.ip,
      });
      
      throw new ValidationError(`Request size too large. Maximum allowed: ${maxSize} bytes`);
    }
    
    next();
  };
};

/**
 * IP Whitelist/Blacklist Middleware
 */
export const createIpFilter = (options: {
  whitelist?: string[];
  blacklist?: string[];
  message?: string;
}) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const clientIp = req.ip || req.connection.remoteAddress || 'unknown';
    
    // Check blacklist first
    if (options.blacklist && options.blacklist.includes(clientIp)) {
      logger.warn('Blocked IP attempted access', {
        ip: clientIp,
        url: req.originalUrl,
        method: req.method,
        userAgent: req.get('User-Agent'),
      });
      
      throw new ForbiddenError(options.message || 'Access denied from this IP address');
    }
    
    // Check whitelist if provided
    if (options.whitelist && options.whitelist.length > 0) {
      if (!options.whitelist.includes(clientIp)) {
        logger.warn('Non-whitelisted IP attempted access', {
          ip: clientIp,
          url: req.originalUrl,
          method: req.method,
        });
        
        throw new ForbiddenError(options.message || 'Access denied from this IP address');
      }
    }
    
    next();
  };
};

/**
 * Request Timeout Middleware
 */
export const requestTimeout = (timeoutMs: number = 30000) => { // 30 seconds default
  return (req: Request, res: Response, next: NextFunction) => {
    const timeout = setTimeout(() => {
      if (!res.headersSent) {
        logger.warn('Request timeout', {
          url: req.originalUrl,
          method: req.method,
          ip: req.ip,
          timeout: timeoutMs,
        });
        
        res.status(408).json({
          error: 'Request Timeout',
          message: 'Request took too long to process',
          timeout: timeoutMs,
        });
      }
    }, timeoutMs);

    // Clear timeout when response finishes
    res.on('finish', () => clearTimeout(timeout));
    res.on('close', () => clearTimeout(timeout));

    next();
  };
};

/**
 * Export all security middleware
 */
export const securityMiddleware: any = {
  csrf: csrfProtection,
  xss: xssProtection,
  sqlInjection: sqlInjectionProtection,
  noSqlInjection: noSqlInjectionProtection,
  hpp: httpParameterPollutionProtection,
  slowDown: createSlowDown,
  csp: contentSecurityPolicy,
  headers: securityHeaders,
  requestSize: requestSizeLimit,
  ipFilter: createIpFilter,
  timeout: requestTimeout,
  validation: createValidationChain,
};

export default securityMiddleware;