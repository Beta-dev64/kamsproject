import { Request, Response, NextFunction } from 'express';
import { logger } from '../utils/logger';
import { AuthRequest, ApiError } from '../types';
import config from '../config';

// Custom error classes
export class AppError extends Error implements ApiError {
  public readonly statusCode: number;
  public readonly code: string;
  public readonly isOperational: boolean;
  public readonly details?: any;

  constructor(message: string, statusCode: number = 500, code: string = 'INTERNAL_ERROR', details?: any) {
    super(message);
    
    this.statusCode = statusCode;
    this.code = code;
    this.details = details;
    this.isOperational = true;
    
    Error.captureStackTrace(this, this.constructor);
  }
}

export class ValidationError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 400, 'VALIDATION_ERROR', details);
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR');
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR');
  }
}

export class ForbiddenError extends AppError {
  constructor(message: string = 'Access forbidden') {
    super(message, 403, 'FORBIDDEN_ERROR');
  }
}

export class NotFoundError extends AppError {
  constructor(message: string = 'Resource not found') {
    super(message, 404, 'NOT_FOUND_ERROR');
  }
}

export class ConflictError extends AppError {
  constructor(message: string) {
    super(message, 409, 'CONFLICT_ERROR');
  }
}

export class TenantError extends AppError {
  constructor(message: string) {
    super(message, 400, 'TENANT_ERROR');
  }
}

export class DatabaseError extends AppError {
  constructor(message: string, details?: any) {
    super(message, 500, 'DATABASE_ERROR', details);
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Rate limit exceeded') {
    super(message, 429, 'RATE_LIMIT_ERROR');
  }
}

// Error response interface
interface ErrorResponse {
  error: {
    code: string;
    message: string;
    details?: any;
    requestId?: string;
    timestamp: string;
    path: string;
    method: string;
  };
}

// Main error handler middleware
export const errorHandler = (
  error: Error | AppError,
  req: AuthRequest,
  res: Response,
  next: NextFunction
): void => {
  let statusCode = 500;
  let code = 'INTERNAL_ERROR';
  let message = 'Internal server error';
  let details: any = undefined;

  // Handle known error types
  if (error instanceof AppError) {
    statusCode = error.statusCode;
    code = error.code;
    message = error.message;
    details = error.details;
  } else {
    // Handle specific built-in error types
    if (error.name === 'ValidationError') {
      statusCode = 400;
      code = 'VALIDATION_ERROR';
      message = error.message;
    } else if (error.name === 'CastError') {
      statusCode = 400;
      code = 'INVALID_DATA_FORMAT';
      message = 'Invalid data format provided';
    } else if (error.name === 'MongoError' || error.name === 'MongooseError') {
      statusCode = 500;
      code = 'DATABASE_ERROR';
      message = 'Database operation failed';
    } else if (error.message.includes('JWT')) {
      statusCode = 401;
      code = 'AUTHENTICATION_ERROR';
      message = 'Invalid or expired token';
    } else if (error.message.includes('ENOTFOUND') || error.message.includes('ECONNREFUSED')) {
      statusCode = 503;
      code = 'SERVICE_UNAVAILABLE';
      message = 'External service unavailable';
    }
  }

  // Log error with appropriate level
  const logData = {
    error: {
      name: error.name,
      message: error.message,
      stack: config.app.env === 'development' ? error.stack : undefined,
      code,
      statusCode,
      details,
    },
    request: {
      id: req.requestId,
      method: req.method,
      url: req.url,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      tenantId: req.tenantId,
    },
  };

  if (statusCode >= 500) {
    logger.error('Server Error', logData);
  } else if (statusCode >= 400) {
    logger.warn('Client Error', logData);
  }

  // Prepare error response
  const errorResponse: ErrorResponse = {
    error: {
      code,
      message,
      details: config.app.env === 'development' ? details : undefined,
      requestId: req.requestId,
      timestamp: new Date().toISOString(),
      path: req.path,
      method: req.method,
    },
  };

  // Add stack trace in development mode
  if (config.app.env === 'development' && error.stack) {
    (errorResponse.error as any).stack = error.stack;
  }

  res.status(statusCode).json(errorResponse);
};

// Async error wrapper to catch async route handler errors
export const asyncHandler = (fn: Function) => {
  return (req: Request, res: Response, next: NextFunction) => {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
};

// 404 handler for unmatched routes
export const notFoundHandler = (req: AuthRequest, res: Response, next: NextFunction): void => {
  const error = new NotFoundError(`Route ${req.method} ${req.path} not found`);
  next(error);
};

// Validation error handler for Zod
export const validationErrorHandler = (error: any) => {
  if (error.name === 'ZodError') {
    const details = error.errors.map((err: any) => ({
      field: err.path.join('.'),
      message: err.message,
      value: err.received,
    }));
    
    throw new ValidationError('Validation failed', details);
  }
  throw error;
};

// Database connection error handler
export const handleDatabaseError = (error: any) => {
  logger.error('Database Error', { error: error.message, code: error.code });
  
  if (error.code === 'ECONNREFUSED') {
    throw new DatabaseError('Database connection refused');
  } else if (error.code === '23505') { // PostgreSQL unique violation
    throw new ConflictError('Resource already exists');
  } else if (error.code === '23503') { // PostgreSQL foreign key violation
    throw new ValidationError('Referenced resource does not exist');
  } else if (error.code === '23502') { // PostgreSQL not null violation
    throw new ValidationError('Required field is missing');
  }
  
  throw new DatabaseError('Database operation failed');
};

// Graceful shutdown handler
export const gracefulShutdown = (server: any) => {
  const shutdown = (signal: string) => {
    logger.info(`Received ${signal}. Graceful shutdown starting...`);
    
    server.close(() => {
      logger.info('HTTP server closed');
      process.exit(0);
    });
    
    // Force exit after 30 seconds
    setTimeout(() => {
      logger.error('Forced shutdown due to timeout');
      process.exit(1);
    }, 30000);
  };

  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGINT', () => shutdown('SIGINT'));
};