import { Response, NextFunction } from 'express';
import { AuthRequest, User, UserRole, Permission } from '../types';
import { jwtService } from '../utils/jwt';
import { dbHelpers, db } from '../database';
import { AuthenticationError, AuthorizationError } from './errorHandler';
import { logger } from '../utils/logger';

/**
 * Authentication middleware - verifies JWT token and loads user
 */
export const authenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);

    if (!token) {
      logger.warn('Authentication missing token', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        requestId: req.requestId,
      });

      throw new AuthenticationError('Authorization token required');
    }

    // Verify and decode token
    const payload = jwtService.verifyAccessToken(token);

    // Load user from database
    const result = await dbHelpers.queryWithTenant(`
      SELECT u.*, p.first_name, p.last_name, p.department, p.manager_id
      FROM users u
      LEFT JOIN user_profiles p ON u.id = p.user_id
      WHERE u.id = $1 AND u.is_active = true AND u.deleted_at IS NULL
    `, [payload.userId], payload.tenantId);
    
    const dbUser = result.rows[0];

    if (!dbUser) {
      logger.warn('Authentication user not found', {
        userId: payload.userId,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        requestId: req.requestId,
      });

      throw new AuthenticationError('Invalid or inactive user');
    }

    // Check if user's tenant matches token's tenant (additional security)
    if (dbUser.tenant_id !== payload.tenantId) {
      logger.warn('Authentication tenant mismatch', {
        userId: dbUser.id,
        userTenantId: dbUser.tenant_id,
        tokenTenantId: payload.tenantId,
        ip: req.ip,
        requestId: req.requestId,
      });

      throw new AuthenticationError('Token tenant mismatch');
    }

    // Map database user to our User type
    const mappedUser: User = {
      id: dbUser.id,
      tenantId: dbUser.tenant_id,
      email: dbUser.email,
      firstName: dbUser.first_name,
      lastName: dbUser.last_name,
      role: dbUser.role as UserRole,
      department: dbUser.department,
      managerId: dbUser.manager_id,
      isActive: dbUser.is_active,
      emailVerified: dbUser.email_verified,
      avatarUrl: dbUser.avatar_url,
      phone: dbUser.phone,
      hireDate: dbUser.hire_date,
      lastLoginAt: dbUser.last_login_at ? new Date(dbUser.last_login_at) : undefined,
      createdAt: new Date(dbUser.created_at),
      updatedAt: new Date(dbUser.updated_at),
    };

    // Attach user to request
    req.user = mappedUser;

    // Also set tenantId if not already set
    if (!req.tenantId) {
      req.tenantId = dbUser.tenant_id;
    }

    // Log successful authentication
    logger.info('Authentication success', {
      userId: dbUser.id,
      tenantId: dbUser.tenant_id,
      role: dbUser.role,
      ip: req.ip,
      endpoint: req.originalUrl,
      requestId: req.requestId,
    });

    next();
  } catch (error) {
    next(error);
  }
};

export const authenticateAdmin = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    // Extract token from Authorization header
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);

    if (!token) {
      logger.warn('Authentication missing token', {
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        method: req.method,
        requestId: req.requestId,
      });

      throw new AuthenticationError('Authorization token required');
    }

    // Verify and decode token
    const payload = jwtService.verifyAccessToken(token);

    console.log('payload', payload);

    // Load user from database based on user ID from the token
    const dbUser = await db.queryOne(`
      SELECT id, email, password_hash, first_name, last_name, role, department, 
             manager_id, is_active, email_verified, last_login, created_at, updated_at
      FROM kam_profiles 
      WHERE id = $1 AND is_active = true AND deleted_at IS NULL
    `, [payload.userId]);

    console.log('dbUser', dbUser);

    if (!dbUser) {
      logger.warn('Authentication user not found or inactive', {
        userId: payload.userId,
        ip: req.ip,
        userAgent: req.get('User-Agent'),
        endpoint: req.originalUrl,
        requestId: req.requestId,
      });

      throw new AuthenticationError('Invalid or inactive user');
    }

    // Map database user to our User type
    const mappedUser: User = {
      id: dbUser.id,
      tenantId: dbUser.tenant_id, // This will be null if not used
      email: dbUser.email,
      firstName: dbUser.first_name,
      lastName: dbUser.last_name,
      role: dbUser.role as UserRole,
      department: dbUser.department,
      managerId: dbUser.manager_id,
      isActive: dbUser.is_active,
      emailVerified: dbUser.email_verified,
      avatarUrl: dbUser.avatar_url,
      phone: dbUser.phone,
      hireDate: dbUser.hire_date,
      lastLoginAt: dbUser.last_login ? new Date(dbUser.last_login) : undefined,
      createdAt: new Date(dbUser.created_at),
      updatedAt: new Date(dbUser.updated_at),
    };

    // Attach user to request
    req.user = mappedUser;

    // Log successful authentication
    logger.info('Authentication success', {
      userId: dbUser.id,
      role: dbUser.role,
      ip: req.ip,
      endpoint: req.originalUrl,
      requestId: req.requestId,
    });

    next();
  } catch (error) {
    // Handle JWT verification errors and other exceptions
    if (error instanceof AuthenticationError) {
      // Re-throw known authentication errors
      return next(error);
    }

    // Log the error and pass a generic authentication error
    logger.error('Authentication failed', {
      error: error instanceof Error ? error.message : 'Unknown error',
      ip: req.ip,
      endpoint: req.originalUrl,
      requestId: req.requestId,
    });
    next(new AuthenticationError('Invalid token'));
  }
};

/**
 * Optional authentication - doesn't throw if no token is provided
 */
export const optionalAuthenticate = async (req: AuthRequest, res: Response, next: NextFunction) => {
  try {
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);

    if (!token) {
      // No token provided, continue without authentication
      return next();
    }

    // If token is provided, validate it
    await authenticate(req, res, next);
  } catch (error) {
    // If authentication fails but was optional, continue without user
    next();
  }
};

/**
 * Role-based authorization middleware
 */
export const requireRole = (roles: UserRole | UserRole[]) => {
  const requiredRoles = Array.isArray(roles) ? roles : [roles];

  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AuthenticationError('Authentication required');
    }

    if (!requiredRoles.includes(req.user.role)) {
      logger.warn('Authorization role denied', {
        userId: req.user.id,
        userRole: req.user.role,
        requiredRoles,
        endpoint: req.originalUrl,
        method: req.method,
        requestId: req.requestId,
      });

      throw new AuthorizationError(`Role '${req.user.role}' not authorized. Required: ${requiredRoles.join(', ')}`);
    }

    next();
  };
};

/**
 * Permission-based authorization middleware
 */
export const requirePermission = (permission: Permission) => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        throw new AuthenticationError('Authentication required');
      }

      const hasPermission = await checkUserPermission(req.user, permission);

      if (!hasPermission) {
        logger.warn('Authorization permission denied', {
          userId: req.user.id,
          userRole: req.user.role,
          requiredPermission: permission,
          endpoint: req.originalUrl,
          method: req.method,
          requestId: req.requestId,
        });

        throw new AuthorizationError(`Permission '${permission}' required`);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Check if user has specific permission based on their role
 */
export const checkUserPermission = async (user: User, permission: Permission): Promise<boolean> => {
  const rolePermissions = getRolePermissions(user.role);
  return rolePermissions.includes(permission);
};

/**
 * Get permissions for a specific role
 */
export const getRolePermissions = (role: UserRole): Permission[] => {
  switch (role) {
    case UserRole.SUPER_ADMIN:
      return [
        // All permissions for super admin
        Permission.TENANT_CREATE,
        Permission.TENANT_READ,
        Permission.TENANT_UPDATE,
        Permission.TENANT_DELETE,
        Permission.USER_CREATE,
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.ASSESSMENT_CREATE,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_UPDATE,
        Permission.ASSESSMENT_DELETE,
        Permission.ASSESSMENT_READ_ALL,
        Permission.SETTINGS_READ,
        Permission.SETTINGS_UPDATE,
      ];

    case UserRole.ADMIN:
      return [
        Permission.TENANT_READ,
        Permission.TENANT_UPDATE,
        Permission.USER_CREATE,
        Permission.USER_READ,
        Permission.USER_UPDATE,
        Permission.USER_DELETE,
        Permission.ASSESSMENT_CREATE,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_UPDATE,
        Permission.ASSESSMENT_DELETE,
        Permission.ASSESSMENT_READ_ALL,
        Permission.SETTINGS_READ,
        Permission.SETTINGS_UPDATE,
      ];

    case UserRole.MANAGER:
      return [
        Permission.USER_READ,
        Permission.ASSESSMENT_CREATE,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_UPDATE,
        Permission.ASSESSMENT_READ_ALL, // Managers can read all assessments for their reports
        Permission.SETTINGS_READ,
      ];

    case UserRole.USER:
      return [
        Permission.ASSESSMENT_CREATE, // Can create self-assessments
        Permission.ASSESSMENT_READ,   // Can read their own assessments
        Permission.SETTINGS_READ,     // Can read basic settings
      ];

    default:
      return [];
  }
};

/**
 * Middleware to ensure user can only access their own resources
 */
export const requireSelfOrRole = (roles: UserRole | UserRole[], userIdParam: string = 'id') => {
  const requiredRoles = Array.isArray(roles) ? roles : [roles];

  return (req: AuthRequest, res: Response, next: NextFunction) => {
    if (!req.user) {
      throw new AuthenticationError('Authentication required');
    }

    const resourceUserId = req.params[userIdParam];

    // Allow if user is accessing their own resource
    if (resourceUserId === req.user.id) {
      return next();
    }

    // Allow if user has required role
    if (requiredRoles.includes(req.user.role)) {
      return next();
    }

    logger.warn('Authorization self or role denied', {
      userId: req.user.id,
      resourceUserId,
      userRole: req.user.role,
      requiredRoles,
      endpoint: req.originalUrl,
      requestId: req.requestId,
    });

    throw new AuthorizationError('Access denied: insufficient permissions');
  };
};

/**
 * Middleware to check if user is manager of the resource owner
 */
export const requireManagerOf = (userIdParam: string = 'employeeId') => {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        throw new AuthenticationError('Authentication required');
      }

      const resourceUserId = req.params[userIdParam];

      // Get the resource owner's manager
      const result = await dbHelpers.queryWithTenant(`
        SELECT p.manager_id FROM user_profiles p
        JOIN users u ON p.user_id = u.id
        WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
      `, [resourceUserId, req.user.tenantId], req.user.tenantId);
      
      const resourceOwner = result.rows[0];

      if (!resourceOwner) {
        throw new AuthorizationError('Resource not found or access denied');
      }

      // Allow if user is the manager or has admin role
      if (resourceOwner.manager_id === req.user.id || 
          [UserRole.ADMIN, UserRole.SUPER_ADMIN].includes(req.user.role)) {
        return next();
      }

      logger.warn('Authorization manager denied', {
        userId: req.user.id,
        resourceUserId,
        resourceManagerId: resourceOwner.manager_id,
        endpoint: req.originalUrl,
        requestId: req.requestId,
      });

      throw new AuthorizationError('Access denied: manager permission required');
    } catch (error) {
      next(error);
    }
  };
};

/**
 * Authorization middleware for multiple permissions (OR logic)
 */
export const authorize = (permissions: Permission | Permission[]) => {
  const requiredPermissions = Array.isArray(permissions) ? permissions : [permissions];
  
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    try {
      if (!req.user) {
        throw new AuthenticationError('Authentication required');
      }

      // Check if user has any of the required permissions
      const userPermissions = getRolePermissions(req.user.role);
      const hasPermission = requiredPermissions.some(permission => 
        userPermissions.includes(permission)
      );

      if (!hasPermission) {
        logger.warn('Authorization permission denied', {
          userId: req.user.id,
          userRole: req.user.role,
          requiredPermissions,
          userPermissions,
          endpoint: req.originalUrl,
          method: req.method,
          requestId: req.requestId,
        });

        throw new AuthorizationError(`Insufficient permissions. Required: ${requiredPermissions.join(' or ')}`);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};

// Alias for backward compatibility
export const authenticateToken = authenticate;
