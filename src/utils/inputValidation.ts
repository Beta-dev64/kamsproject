import { z } from 'zod';
import { body, query, param, ValidationChain } from 'express-validator';
import { logger } from './logger';

/**
 * Enhanced validation patterns for security
 */
export const securityPatterns = {
  // XSS patterns
  xss: [
    /<script[\s\S]*?<\/script>/gi,
    /javascript:/gi,
    /vbscript:/gi,
    /onload\s*=/gi,
    /onerror\s*=/gi,
    /onclick\s*=/gi,
    /onmouseover\s*=/gi,
    /<iframe[\s\S]*?<\/iframe>/gi,
    /<embed[\s\S]*?>/gi,
    /<object[\s\S]*?<\/object>/gi,
  ],
  
  // SQL Injection patterns (more comprehensive)
  sqlInjection: [
    /(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION|SCRIPT)\b)/gi,
    /(\b(OR|AND)\s+\d+\s*=\s*\d+)/gi,
    /(\b(OR|AND)\s+['"]?\w+['"]?\s*=\s*['"]?\w+['"]?)/gi,
    /(UNION\s+SELECT)/gi,
    /(--|\*\/|\/\*)/g,
    /(\bEXEC\s*\()/gi,
    /(\bCHAR\s*\()/gi,
    /(\bCAST\s*\()/gi,
    /(\bCONCAT\s*\()/gi,
    /(\bDECLARE\s+@)/gi,
    /(\bSHUTDOWN\b)/gi,
  ],
  
  // NoSQL Injection patterns
  noSqlInjection: [
    /\$where/gi,
    /\$regex/gi,
    /\$ne\b/gi,
    /\$gt\b/gi,
    /\$lt\b/gi,
    /\$in\b/gi,
    /\$nin\b/gi,
    /\$exists/gi,
    /\$or\b/gi,
    /\$and\b/gi,
  ],
  
  // Directory traversal
  pathTraversal: [
    /\.\.[\/\\]/g,
    /\.\.[\\\/]/g,
    /[\/\\]\.\.$/g,
    /^\.\.$/g,
  ],
  
  // Command injection
  commandInjection: [
    /[;&|`$(){}[\]]/g,
    /\b(rm|del|format|shutdown|reboot|halt)\b/gi,
    /\b(cat|type|more|less|head|tail)\b/gi,
    /\b(wget|curl|nc|netcat)\b/gi,
  ],
};

/**
 * Enhanced string validation with security checks
 */
export const createSecureStringSchema = (options: {
  minLength?: number;
  maxLength?: number;
  allowHtml?: boolean;
  allowSql?: boolean;
  allowScripts?: boolean;
  pattern?: RegExp;
  customMessage?: string;
} = {}) => {
  const {
    minLength = 1,
    maxLength = 1000,
    allowHtml = false,
    allowSql = false,
    allowScripts = false,
    pattern,
    customMessage = 'Invalid input format',
  } = options;

  return z.string()
    .min(minLength, `Must be at least ${minLength} characters`)
    .max(maxLength, `Must be at most ${maxLength} characters`)
    .refine((value) => {
      // Check for XSS
      if (!allowScripts && securityPatterns.xss.some(p => p.test(value))) {
        logger.warn('XSS pattern detected in input', { value: '[REDACTED]' });
        return false;
      }
      return true;
    }, { message: 'Potentially unsafe content detected' })
    .refine((value) => {
      // Check for SQL injection
      if (!allowSql && securityPatterns.sqlInjection.some(p => p.test(value))) {
        logger.warn('SQL injection pattern detected in input', { value: '[REDACTED]' });
        return false;
      }
      return true;
    }, { message: 'Potentially unsafe database query detected' })
    .refine((value) => {
      // Check for NoSQL injection
      if (!allowSql && securityPatterns.noSqlInjection.some(p => p.test(value))) {
        logger.warn('NoSQL injection pattern detected in input', { value: '[REDACTED]' });
        return false;
      }
      return true;
    }, { message: 'Potentially unsafe database query detected' })
    .refine((value) => {
      // Check for path traversal
      if (securityPatterns.pathTraversal.some(p => p.test(value))) {
        logger.warn('Path traversal pattern detected in input', { value: '[REDACTED]' });
        return false;
      }
      return true;
    }, { message: 'Potentially unsafe path detected' })
    .refine((value) => {
      // Check for command injection
      if (securityPatterns.commandInjection.some(p => p.test(value))) {
        logger.warn('Command injection pattern detected in input', { value: '[REDACTED]' });
        return false;
      }
      return true;
    }, { message: 'Potentially unsafe command detected' })
    .refine((value) => {
      // Check custom pattern if provided
      if (pattern && !pattern.test(value)) {
        return false;
      }
      return true;
    }, { message: customMessage });
};

/**
 * Secure email validation with additional checks
 */
export const secureEmailSchema = z.string()
  .email('Invalid email format')
  .max(254, 'Email too long') // RFC 5321 limit
  .refine((email) => {
    // Check for suspicious email patterns
    const suspiciousPatterns = [
      /[<>]/g, // Angle brackets
      /javascript:/gi,
      /data:/gi,
      /['"]/g, // Quotes
    ];
    
    return !suspiciousPatterns.some(pattern => pattern.test(email));
  }, { message: 'Email contains invalid characters' })
  .transform(email => email.toLowerCase().trim());

/**
 * Secure URL validation
 */
export const secureUrlSchema = z.string()
  .url('Invalid URL format')
  .refine((url) => {
    const allowedProtocols = ['http:', 'https:'];
    const urlObj = new URL(url);
    return allowedProtocols.includes(urlObj.protocol);
  }, { message: 'Only HTTP and HTTPS URLs are allowed' })
  .refine((url) => {
    // Prevent localhost/private IP access in production
    if (process.env.NODE_ENV === 'production') {
      const urlObj = new URL(url);
      const hostname = urlObj.hostname.toLowerCase();
      
      const blockedHosts = [
        'localhost',
        '127.0.0.1',
        '0.0.0.0',
        '::1',
      ];
      
      const privateIpRanges = [
        /^10\./,
        /^172\.(1[6-9]|2\d|3[01])\./,
        /^192\.168\./,
        /^169\.254\./, // Link-local
      ];
      
      if (blockedHosts.includes(hostname) || 
          privateIpRanges.some(range => range.test(hostname))) {
        logger.warn('Blocked private/local URL attempt', { hostname });
        return false;
      }
    }
    return true;
  }, { message: 'URL not allowed' });

/**
 * Secure filename validation
 */
export const secureFilenameSchema = createSecureStringSchema({
  minLength: 1,
  maxLength: 255,
  pattern: /^[a-zA-Z0-9._-]+$/,
  customMessage: 'Filename can only contain letters, numbers, dots, hyphens, and underscores',
});

/**
 * Secure UUID validation
 */
export const secureUuidSchema = z.string()
  .uuid('Invalid UUID format')
  .refine((uuid) => {
    // Additional UUID format validation
    const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
    return uuidRegex.test(uuid);
  }, { message: 'Invalid UUID format' });

/**
 * Secure password validation with comprehensive checks
 */
export const securePasswordSchema = z.string()
  .min(12, 'Password must be at least 12 characters long') // Increased from 8
  .max(128, 'Password too long')
  .refine((password) => {
    // Check for common patterns
    const commonPatterns = [
      /(.)\1{3,}/g, // Repeated characters (aaaa, 1111)
      /^(password|123456|qwerty|admin|root|user|guest)/gi,
      /(password|123456|qwerty|admin|root|user|guest)$/gi,
    ];
    
    return !commonPatterns.some(pattern => pattern.test(password));
  }, { message: 'Password contains common or repeated patterns' })
  .refine((password) => {
    // Comprehensive character requirements
    const requirements = [
      /[a-z]/, // Lowercase
      /[A-Z]/, // Uppercase
      /[0-9]/, // Numbers
      /[^a-zA-Z0-9]/, // Special characters
    ];
    
    const metCount = requirements.reduce((count, req) => {
      return count + (req.test(password) ? 1 : 0);
    }, 0);
    
    return metCount >= 3; // Must meet at least 3 of 4 requirements
  }, { message: 'Password must contain at least 3 of: lowercase, uppercase, numbers, special characters' })
  .refine((password) => {
    // Check entropy/complexity
    const uniqueChars = new Set(password).size;
    const entropy = uniqueChars / password.length;
    return entropy >= 0.3; // At least 30% unique characters
  }, { message: 'Password lacks complexity' });

/**
 * Create express-validator chains for common validations
 */
export const createExpressValidators = {
  /**
   * Secure string validation for express-validator
   */
  secureString: (field: string, options: {
    minLength?: number;
    maxLength?: number;
    isOptional?: boolean;
  } = {}) => {
    const validator = body(field);
    
    if (options.isOptional) {
      validator.optional();
    }
    
    return validator
      .isString()
      .withMessage(`${field} must be a string`)
      .isLength({ 
        min: options.minLength || 1, 
        max: options.maxLength || 1000 
      })
      .withMessage(`${field} must be between ${options.minLength || 1} and ${options.maxLength || 1000} characters`)
      .custom((value) => {
        // Run security checks
        if (securityPatterns.xss.some(p => p.test(value))) {
          throw new Error(`${field} contains potentially unsafe content`);
        }
        if (securityPatterns.sqlInjection.some(p => p.test(value))) {
          throw new Error(`${field} contains potentially unsafe database query`);
        }
        return true;
      })
      .trim()
      .escape(); // HTML escape
  },

  /**
   * Secure email validation for express-validator
   */
  secureEmail: (field: string = 'email', isOptional: boolean = false) => {
    const validator = body(field);
    
    if (isOptional) {
      validator.optional();
    }
    
    return validator
      .isEmail()
      .withMessage('Invalid email format')
      .isLength({ max: 254 })
      .withMessage('Email too long')
      .custom((email) => {
        const suspiciousPatterns = [/[<>'"]/g, /javascript:/gi, /data:/gi];
        if (suspiciousPatterns.some(pattern => pattern.test(email))) {
          throw new Error('Email contains invalid characters');
        }
        return true;
      })
      .normalizeEmail()
      .toLowerCase();
  },

  /**
   * Secure UUID validation for express-validator
   */
  secureUuid: (field: string, location: 'body' | 'query' | 'param' = 'param') => {
    const validator = location === 'body' ? body(field) : 
                     location === 'query' ? query(field) : 
                     param(field);
    
    return validator
      .isUUID(4)
      .withMessage(`${field} must be a valid UUID`)
      .custom((uuid) => {
        const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
        if (!uuidRegex.test(uuid)) {
          throw new Error(`${field} has invalid UUID format`);
        }
        return true;
      });
  },

  /**
   * Secure integer validation for express-validator
   */
  secureInteger: (field: string, options: {
    min?: number;
    max?: number;
    isOptional?: boolean;
  } = {}) => {
    const validator = body(field);
    
    if (options.isOptional) {
      validator.optional();
    }
    
    return validator
      .isInt({ 
        min: options.min, 
        max: options.max 
      })
      .withMessage(`${field} must be an integer${options.min !== undefined ? ` >= ${options.min}` : ''}${options.max !== undefined ? ` <= ${options.max}` : ''}`)
      .toInt();
  },
};

/**
 * Data sanitization utilities
 */
export const sanitizers = {
  /**
   * Sanitize string for database storage
   */
  forDatabase: (input: string): string => {
    return input
      .trim()
      .replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, '') // Remove control characters
      .replace(/\s+/g, ' '); // Normalize whitespace
  },

  /**
   * Sanitize for display (prevent XSS)
   */
  forDisplay: (input: string): string => {
    return input
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#x27;')
      .replace(/\//g, '&#x2F;');
  },

  /**
   * Sanitize for JSON
   */
  forJson: (input: string): string => {
    return input
      .replace(/\\/g, '\\\\')
      .replace(/"/g, '\\"')
      .replace(/\n/g, '\\n')
      .replace(/\r/g, '\\r')
      .replace(/\t/g, '\\t');
  },

  /**
   * Remove null bytes and control characters
   */
  removeNullBytes: (input: string): string => {
    return input.replace(/\x00/g, '');
  },
};

/**
 * Content validation utilities
 */
export const contentValidators = {
  /**
   * Validate JSON structure
   */
  isValidJson: (input: string): boolean => {
    try {
      JSON.parse(input);
      return true;
    } catch {
      return false;
    }
  },

  /**
   * Validate base64 content
   */
  isValidBase64: (input: string): boolean => {
    const base64Regex = /^[A-Za-z0-9+/]*={0,2}$/;
    return base64Regex.test(input) && input.length % 4 === 0;
  },

  /**
   * Check for binary content
   */
  isBinaryContent: (input: string): boolean => {
    // Check for null bytes or high percentage of non-printable characters
    const nullBytes = (input.match(/\x00/g) || []).length;
    const nonPrintable = (input.match(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g) || []).length;
    
    return nullBytes > 0 || (nonPrintable / input.length) > 0.3;
  },

  /**
   * Validate file extension
   */
  hasAllowedExtension: (filename: string, allowedExtensions: string[]): boolean => {
    const extension = filename.split('.').pop()?.toLowerCase();
    return extension ? allowedExtensions.includes(extension) : false;
  },
};

/**
 * Rate limiting helpers
 */
export const rateLimitHelpers = {
  /**
   * Create composite rate limit key
   */
  createKey: (components: string[]): string => {
    return components.filter(Boolean).join(':');
  },

  /**
   * Check if IP is in whitelist/blacklist format
   */
  isValidIpList: (ips: string[]): boolean => {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/(?:[0-9]|[1-2][0-9]|3[0-2])$/;
    
    return ips.every(ip => ipRegex.test(ip) || cidrRegex.test(ip));
  },
};

export default {
  securityPatterns,
  createSecureStringSchema,
  secureEmailSchema,
  secureUrlSchema,
  secureFilenameSchema,
  secureUuidSchema,
  securePasswordSchema,
  createExpressValidators,
  sanitizers,
  contentValidators,
  rateLimitHelpers,
};