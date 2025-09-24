import { Request, Response, NextFunction } from 'express';
import { z } from 'zod';
import { validationResult } from 'express-validator';
import { ValidationError } from './errorHandler';
import { logger } from '../utils/logger';
import { AuthRequest } from '../types';

/**
 * Validation middleware for express-validator
 */
export const validateInput = (req: AuthRequest, res: Response, next: NextFunction) => {
  const errors = validationResult(req);
  
  if (!errors.isEmpty()) {
    const validationErrors = errors.array().map(error => ({
      field: error.type === 'field' ? error.path : 'unknown',
      message: error.msg,
      value: error.type === 'field' ? error.value : undefined
    }));

    logger.warn('Input validation failed', {
      errors: validationErrors,
      requestId: req.requestId,
      endpoint: req.originalUrl,
      method: req.method,
      userId: req.user?.id,
      tenantId: req.tenantId,
    });

    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: validationErrors
    });
  }
  
  next();
};

/**
 * Validation middleware factory for Zod schemas
 */
export const validate = (schema: z.ZodSchema, source: 'body' | 'query' | 'params' = 'body') => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      let dataToValidate;
      
      switch (source) {
        case 'body':
          dataToValidate = req.body;
          break;
        case 'query':
          dataToValidate = req.query;
          break;
        case 'params':
          dataToValidate = req.params;
          break;
        default:
          dataToValidate = req.body;
      }

      // Parse and validate the data
      const result = schema.parse(dataToValidate);
      
      // Replace the original data with the validated/transformed data
      switch (source) {
        case 'body':
          req.body = result;
          break;
        case 'query':
          req.query = result;
          break;
        case 'params':
          req.params = result;
          break;
      }

      next();
    } catch (error) {
      if (error instanceof z.ZodError) {
        // Transform Zod errors into a more user-friendly format
        const validationErrors = error.errors.map(err => ({
          field: err.path.join('.'),
          message: err.message,
          code: err.code,
          received: 'received' in err ? err.received : 'undefined',
        }));

        logger.warn('Validation failed', {
          source,
          errors: validationErrors,
          requestId: req.requestId,
          endpoint: req.originalUrl,
          method: req.method,
          userId: req.user?.id,
          tenantId: req.tenantId,
        });

        throw new ValidationError('Request validation failed', validationErrors);
      }

      // Re-throw other errors
      throw error;
    }
  };
};

/**
 * Validate request body
 */
export const validateBody = (schema: z.ZodSchema) => validate(schema, 'body');

/**
 * Validate query parameters
 */
export const validateQuery = (schema: z.ZodSchema) => validate(schema, 'query');

/**
 * Validate URL parameters
 */
export const validateParams = (schema: z.ZodSchema) => validate(schema, 'params');

/**
 * Sanitize input to prevent XSS attacks
 */
export const sanitizeInput = (req: Request, res: Response, next: NextFunction) => {
  // Simple XSS prevention - remove/escape HTML tags from string fields
  const sanitizeObject = (obj: any): any => {
    if (obj === null || obj === undefined) {
      return obj;
    }

    if (typeof obj === 'string') {
      // Remove HTML tags and decode HTML entities
      return obj
        .replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, '') // Remove script tags
        .replace(/<[^>]*>/g, '') // Remove all HTML tags
        .replace(/&lt;/g, '<')
        .replace(/&gt;/g, '>')
        .replace(/&amp;/g, '&')
        .replace(/&quot;/g, '"')
        .replace(/&#x27;/g, "'")
        .trim();
    }

    if (Array.isArray(obj)) {
      return obj.map(sanitizeObject);
    }

    if (typeof obj === 'object') {
      const sanitized: any = {};
      for (const key in obj) {
        if (obj.hasOwnProperty(key)) {
          sanitized[key] = sanitizeObject(obj[key]);
        }
      }
      return sanitized;
    }

    return obj;
  };

  // Sanitize body, query, and params
  if (req.body) {
    req.body = sanitizeObject(req.body);
  }
  if (req.query) {
    req.query = sanitizeObject(req.query);
  }
  if (req.params) {
    req.params = sanitizeObject(req.params);
  }

  next();
};

/**
 * Middleware to validate file uploads
 */
export const validateFileUpload = (options: {
  maxSize?: number;
  allowedMimeTypes?: string[];
  maxFiles?: number;
} = {}) => {
  const {
    maxSize = 10 * 1024 * 1024, // 10MB default
    allowedMimeTypes = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/csv'],
    maxFiles = 5,
  } = options;

  return (req: AuthRequest, res: Response, next: NextFunction) => {
    // This would typically be used with multer or similar file upload middleware
    // For now, we'll add basic validation structure
    
    const files = (req as any).files as any[] || [];
    
    if (files.length > maxFiles) {
      throw new ValidationError(`Too many files. Maximum ${maxFiles} files allowed.`);
    }

    for (const file of files) {
      if (file.size > maxSize) {
        throw new ValidationError(`File ${file.originalname} is too large. Maximum size is ${maxSize / (1024 * 1024)}MB.`);
      }

      if (!allowedMimeTypes.includes(file.mimetype)) {
        throw new ValidationError(`File ${file.originalname} has invalid type. Allowed types: ${allowedMimeTypes.join(', ')}`);
      }
    }

    next();
  };
};

/**
 * Middleware to normalize phone numbers
 */
export const normalizePhoneNumbers = (req: Request, res: Response, next: NextFunction) => {
  const normalizePhone = (phone: string): string => {
    if (!phone) return phone;
    
    // Remove all non-digit characters
    const digits = phone.replace(/\D/g, '');
    
    // Add country code if missing (assuming US +1)
    if (digits.length === 10) {
      return `+1${digits}`;
    } else if (digits.length === 11 && digits.startsWith('1')) {
      return `+${digits}`;
    }
    
    return phone; // Return as-is if format is unclear
  };

  // Normalize phone numbers in request body
  if (req.body) {
    const normalizeObjectPhones = (obj: any): any => {
      if (typeof obj === 'object' && obj !== null) {
        for (const key in obj) {
          if (key.toLowerCase().includes('phone') && typeof obj[key] === 'string') {
            obj[key] = normalizePhone(obj[key]);
          } else if (typeof obj[key] === 'object') {
            obj[key] = normalizeObjectPhones(obj[key]);
          }
        }
      }
      return obj;
    };

    req.body = normalizeObjectPhones(req.body);
  }

  next();
};

/**
 * Middleware to validate pagination parameters
 */
export const validatePagination = (req: Request, res: Response, next: NextFunction) => {
  const query = req.query as any;
  
  // Default pagination values
  const page = parseInt(query.page as string) || 1;
  const limit = parseInt(query.limit as string) || 20;
  
  // Validate ranges
  if (page < 1) {
    throw new ValidationError('Page must be greater than 0');
  }
  
  if (limit < 1 || limit > 100) {
    throw new ValidationError('Limit must be between 1 and 100');
  }
  
  // Add validated pagination to query
  req.query = {
    ...req.query,
    page: page.toString(),
    limit: limit.toString(),
  };
  
  next();
};

/**
 * Middleware to validate tenant context exists
 */
export const requireValidTenant = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.tenantId) {
    throw new ValidationError('Tenant context is required for this operation');
  }
  
  if (!req.user?.tenantId) {
    throw new ValidationError('User tenant context is required');
  }
  
  if (req.tenantId !== req.user.tenantId) {
    throw new ValidationError('Tenant context mismatch');
  }
  
  next();
};

/**
 * Middleware to validate UUIDs in URL parameters
 */
export const validateUUIDs = (...paramNames: string[]) => {
  return (req: Request, res: Response, next: NextFunction) => {
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    
    for (const paramName of paramNames) {
      const value = req.params[paramName];
      if (value && !uuidRegex.test(value)) {
        throw new ValidationError(`Invalid ${paramName} format. Must be a valid UUID.`);
      }
    }
    
    next();
  };
};

/**
 * Middleware to validate date ranges
 */
export const validateDateRange = (req: Request, res: Response, next: NextFunction) => {
  const { dateFrom, dateTo } = req.query;
  
  if (dateFrom && dateTo) {
    const fromDate = new Date(dateFrom as string);
    const toDate = new Date(dateTo as string);
    
    if (isNaN(fromDate.getTime()) || isNaN(toDate.getTime())) {
      throw new ValidationError('Invalid date format. Use YYYY-MM-DD format.');
    }
    
    if (fromDate > toDate) {
      throw new ValidationError('Start date must be before end date.');
    }
    
    // Check for reasonable date range (not more than 2 years)
    const daysDiff = (toDate.getTime() - fromDate.getTime()) / (1000 * 60 * 60 * 24);
    if (daysDiff > 730) { // 2 years
      throw new ValidationError('Date range cannot exceed 2 years.');
    }
  }
  
  next();
};