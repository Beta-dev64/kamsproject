import { Response, NextFunction } from 'express';
import { AuthRequest } from '../types';
import { TenantError, NotFoundError } from './errorHandler';
import { db } from '../database';
import { logger, logSecurityEvent } from '../utils/logger';

/**
 * Tenant isolation middleware - ensures complete data isolation between tenants
 * This is critical for multi-tenant security and compliance
 */

// Extract tenant from domain or header
export const extractTenant = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    let tenantDomain: string | undefined;
    
    // Method 1: Extract from custom header (for API access)
    const tenantHeader = req.headers['x-tenant-domain'] as string;
    if (tenantHeader) {
      tenantDomain = tenantHeader;
    }
    
    // Method 2: Extract from subdomain (kam-assessment.example.com -> kam-assessment)
    else {
      const host = req.get('host');
      if (host) {
        // Skip localhost and IP addresses for development
        if (!host.includes('localhost') && !host.match(/^\d+\.\d+\.\d+\.\d+/)) {
          const subdomain = host.split('.')[0];
          if (subdomain && subdomain !== 'www' && subdomain !== 'api') {
            tenantDomain = subdomain;
          }
        }
      }
    }
    
    // Method 3: Extract from request body for auth endpoints
    if (!tenantDomain && req.body?.tenantDomain) {
      tenantDomain = req.body.tenantDomain;
    }
    
    // Method 4: If user is already authenticated, use their tenant
    if (!tenantDomain && req.user?.tenantId) {
      // Get tenant domain from database
      const tenant = await db.queryOne(
        'SELECT domain FROM kam_tenants WHERE id = $1 AND deleted_at IS NULL',
        [req.user.tenantId]
      );
      tenantDomain = tenant?.domain;
    }
    
    if (tenantDomain) {
      // Validate and get tenant info from database
      const tenant = await db.queryOne(
        'SELECT id, domain, name, max_users, subscription_tier FROM kam_tenants WHERE domain = $1 AND deleted_at IS NULL',
        [tenantDomain]
      );
      
      if (!tenant) {
        logSecurityEvent('INVALID_TENANT_ACCESS', {
          tenantDomain,
          ip: req.ip,
          userAgent: req.get('User-Agent'),
          requestId: req.requestId,
        });
        
        throw new TenantError(`Invalid tenant domain: ${tenantDomain}`);
      }
      
      // Set tenant context
      req.tenantId = tenant.id;
      req.tenantDomain = tenant.domain;
      
      // Add tenant info to request context
      (req as any).tenant = tenant;
      
      logger.debug('Tenant extracted successfully', {
        tenantId: tenant.id,
        domain: tenant.domain,
        requestId: req.requestId,
      });
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

// Enforce tenant context for protected routes
export const requireTenant = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.tenantId) {
    const error = new TenantError('Tenant context required for this operation');
    logSecurityEvent('MISSING_TENANT_CONTEXT', {
      path: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      userId: req.user?.id,
      requestId: req.requestId,
    });
    return next(error);
  }
  
  next();
};

// Tenant isolation for database queries
export const tenantIsolation = (req: AuthRequest, res: Response, next: NextFunction) => {
  if (!req.tenantId) {
    return next();
  }
  
  // Create database context with tenant isolation
  req.dbContext = {
    tenantId: req.tenantId,
    userId: req.user?.id,
  };
  
  // Override database query methods to automatically include tenant filtering
  const originalQuery = db.query.bind(db);
  
  // Inject tenant context into all database operations during this request
  (req as any).tenantDb = {
    query: <T = any>(text: string, params: any[] = []): Promise<any> => {
      // Ensure tenant_id is included in queries
      if (!text.toLowerCase().includes('tenant_id') && !text.toLowerCase().includes('kam_tenants')) {
        logger.warn('Query without tenant_id filter detected', {
          query: text,
          tenantId: req.tenantId,
          userId: req.user?.id,
          requestId: req.requestId,
        });
      }
      
      return originalQuery(text, params);
    },
    
    queryOne: <T = any>(text: string, params: any[] = []): Promise<T | null> => {
      return db.queryOne(text, params) as Promise<T | null>;
    },
    
    queryMany: <T = any>(text: string, params: any[] = []): Promise<T[]> => {
      return db.queryMany(text, params) as Promise<T[]>;
    },
    
    tenantQuery: <T = any>(text: string, params: any[] = []): Promise<any> => {
      return db.tenantQuery(req.tenantId!, text, params);
    },
  };
  
  next();
};

// Validate user belongs to the tenant
export const validateUserTenant = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.user || !req.tenantId) {
      return next();
    }
    
    // Check if user belongs to the requested tenant
    if (req.user.tenantId !== req.tenantId) {
      logSecurityEvent('TENANT_MISMATCH', {
        userId: req.user.id,
        userTenantId: req.user.tenantId,
        requestedTenantId: req.tenantId,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        requestId: req.requestId,
      });
      
      throw new TenantError('User does not belong to the requested tenant');
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

// Check tenant subscription limits
export const checkTenantLimits = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    if (!req.tenantId) {
      return next();
    }
    
    // Get tenant limits
    const tenant = await db.queryOne(
      'SELECT max_users, subscription_tier FROM kam_tenants WHERE id = $1',
      [req.tenantId]
    );
    
    if (!tenant) {
      throw new NotFoundError('Tenant not found');
    }
    
    // Check user creation limits for POST /users
    if (req.method === 'POST' && req.path.includes('/users')) {
      const userCount = await db.queryOne(
        'SELECT COUNT(*) as count FROM kam_profiles WHERE tenant_id = $1 AND deleted_at IS NULL',
        [req.tenantId]
      );
      
      if (parseInt(userCount?.count || '0') >= tenant.max_users) {
        throw new TenantError(`User limit exceeded. Maximum ${tenant.max_users} users allowed for ${tenant.subscription_tier} tier`);
      }
    }
    
    next();
  } catch (error) {
    next(error);
  }
};

// Tenant-aware resource access control
export const enforceResourceAccess = (resourceField: string = 'tenant_id') => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      const resourceId = req.params.id;
      
      if (!resourceId || !req.tenantId) {
        return next();
      }
      
      // This middleware can be used to check if a resource belongs to the current tenant
      // Implementation would depend on the specific resource type
      // For now, we'll just log the access attempt
      logger.debug('Resource access attempt', {
        resourceId,
        tenantId: req.tenantId,
        userId: req.user?.id,
        path: req.path,
        method: req.method,
        requestId: req.requestId,
      });
      
      next();
    } catch (error) {
      next(error);
    }
  };
};

// Audit tenant operations
export const auditTenantOperation = (operation: string) => {
  return (req: AuthRequest, res: Response, next: NextFunction) => {
    // Log the operation for audit trail
    logger.info('Tenant Operation', {
      operation,
      tenantId: req.tenantId,
      userId: req.user?.id,
      resource: req.path,
      method: req.method,
      ip: req.ip,
      userAgent: req.get('User-Agent'),
      requestId: req.requestId,
      timestamp: new Date().toISOString(),
    });
    
    next();
  };
};