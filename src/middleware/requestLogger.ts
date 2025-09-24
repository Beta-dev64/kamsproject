import morgan from 'morgan';
import { Request, Response } from 'express';
import { v4 as uuidv4 } from 'uuid';
import { logRequest } from '../utils/logger';
import { AuthRequest } from '../types';

// Custom token to add request ID
morgan.token('id', (req: AuthRequest) => req.requestId || 'unknown');
morgan.token('user', (req: AuthRequest) => req.user?.id || 'anonymous');
morgan.token('tenant', (req: AuthRequest) => req.tenantId || 'no-tenant');

// Request ID middleware
export const requestIdMiddleware = (req: AuthRequest, res: Response, next: Function) => {
  req.requestId = uuidv4();
  res.setHeader('X-Request-ID', req.requestId);
  next();
};

// Custom Morgan format with request ID, user, and tenant info
const morganFormat = ':id :tenant :user :method :url :status :res[content-length] - :response-time ms';

// Morgan middleware with custom logging
export const requestLogger: any = morgan(morganFormat, {
  stream: {
    write: (message: string) => {
      // Parse the morgan message to extract structured data
      const parts = message.trim().split(' ');
      const [requestId, tenantId, userId, method, url, status, contentLength, , responseTime] = parts;
      
      // Log using our structured logger
      if (responseTime) {
        logRequest(
          { 
            method, 
            url, 
            get: (header: string) => header === 'User-Agent' ? 'Morgan Logger' : undefined,
            ip: 'unknown',
            user: userId !== 'anonymous' ? { id: userId } : undefined,
            requestId,
          },
          { statusCode: parseInt(status, 10) },
          parseFloat(responseTime)
        );
      }
    },
  },
  skip: (req: Request, res: Response) => {
    // Skip logging for health check endpoints in production
    return process.env.NODE_ENV === 'production' && req.url?.startsWith('/health');
  },
});

// Performance monitoring middleware
export const performanceMiddleware = (req: AuthRequest, res: Response, next: Function) => {
  const start = Date.now();
  
  // Override res.end to capture response time
  const originalEnd = res.end;
  res.end = function(chunk?: any, encoding?: any, cb?: any) {
    const duration = Date.now() - start;
    
    // Log slow requests
    if (duration > 2000) { // 2 seconds threshold
      logRequest(req, res, duration);
    }
    
    // Call original end method
    return originalEnd.call(this, chunk, encoding, cb);
  };
  
  next();
};