import express from 'express';
import { SystemAdminController } from '../controllers/systemAdminController';
import { authenticate, authenticateAdmin } from '../middleware/auth';
import { validateBody, validateQuery, validateParams, sanitizeInput } from '../middleware/validation';
import { apiRateLimit, adminRateLimit, authRateLimit } from '../middleware/rateLimiter';
import { z } from 'zod';
import { 
  createTenantSchema, 
  updateTenantSchema,
  uuidSchema,
  loginSchema 
} from '../utils/validation';
import { UserRole } from '../types';
import { AuthController } from '../controllers/authController';

const router: any = express.Router();
const systemAdminController = new SystemAdminController();
const authController = new AuthController();

// Middleware to ensure only super admins can access these routes
const requireSuperAdmin = (req: any, res: any, next: any) => {
  if (!req.user || req.user.role !== UserRole.SUPER_ADMIN) {
    return res.status(403).json({
      success: false,
      message: 'Access denied. Super admin privileges required.',
      error: 'INSUFFICIENT_PRIVILEGES'
    });
  }
  next();
};

// Apply authentication and super admin check to all routes
router.use(authenticateAdmin);
router.use(requireSuperAdmin);
router.use(apiRateLimit);

/**
 * System Overview Routes
 */

// GET /api/v1/system/dashboard - Get system-wide dashboard stats
router.get('/dashboard',
  systemAdminController.getSystemDashboard.bind(systemAdminController)
);

// GET /api/v1/system/health - Get detailed system health status
router.get('/health',
  systemAdminController.getSystemHealth.bind(systemAdminController)
);

/**
 * Tenant Management Routes
 */

// GET /api/v1/system/tenants - Get all tenants with pagination and filtering
const tenantsFilterSchema = z.object({
  page: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional().default('1'),
  limit: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional().default('20'),
  search: z.string().max(100).optional(),
  status: z.enum(['active', 'inactive', 'all']).optional().default('all'),
  subscriptionTier: z.enum(['basic', 'pro', 'enterprise']).optional(),
  sortBy: z.enum(['name', 'domain', 'createdAt', 'userCount']).optional().default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc')
});

router.get('/tenants',
  validateQuery(tenantsFilterSchema),
  systemAdminController.getAllTenants.bind(systemAdminController)
);

// POST /api/v1/system/tenants - Create new tenant
router.post('/tenants',
  adminRateLimit,
  sanitizeInput,
  validateBody(createTenantSchema),
  systemAdminController.createTenant.bind(systemAdminController)
);

// GET /api/v1/system/tenants/:tenantId - Get specific tenant details
router.get('/tenants/:tenantId',
  validateParams(z.object({ tenantId: uuidSchema })),
  systemAdminController.getTenantDetails.bind(systemAdminController)
);

// PUT /api/v1/system/tenants/:tenantId - Update tenant
router.put('/tenants/:tenantId',
  adminRateLimit,
  validateParams(z.object({ tenantId: uuidSchema })),
  sanitizeInput,
  validateBody(updateTenantSchema),
  systemAdminController.updateTenant.bind(systemAdminController)
);

// DELETE /api/v1/system/tenants/:tenantId - Delete/deactivate tenant
router.delete('/tenants/:tenantId',
  adminRateLimit,
  validateParams(z.object({ tenantId: uuidSchema })),
  systemAdminController.deleteTenant.bind(systemAdminController)
);

// POST /api/v1/system/tenants/:tenantId/activate - Activate tenant
router.post('/tenants/:tenantId/activate',
  adminRateLimit,
  validateParams(z.object({ tenantId: uuidSchema })),
  systemAdminController.activateTenant.bind(systemAdminController)
);

// POST /api/v1/system/tenants/:tenantId/deactivate - Deactivate tenant
router.post('/tenants/:tenantId/deactivate',
  adminRateLimit,
  validateParams(z.object({ tenantId: uuidSchema })),
  systemAdminController.deactivateTenant.bind(systemAdminController)
);


/**
 * User Management Routes (Cross-tenant)
 */

// GET /api/v1/system/users - Get all users across all tenants
const usersFilterSchema = z.object({
  page: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional().default('1'),
  limit: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional().default('20'),
  tenantId: uuidSchema.optional(),
  role: z.nativeEnum(UserRole).optional(),
  isActive: z.enum(['true', 'false']).optional(),
  search: z.string().max(100).optional(),
  sortBy: z.enum(['email', 'firstName', 'createdAt', 'lastLoginAt']).optional().default('createdAt'),
  sortOrder: z.enum(['asc', 'desc']).optional().default('desc')
});

router.get('/users',
  validateQuery(usersFilterSchema),
  systemAdminController.getAllUsers.bind(systemAdminController)
);

// GET /api/v1/system/users/:userId - Get specific user details (cross-tenant)
router.get('/users/:userId',
  validateParams(z.object({ userId: uuidSchema })),
  systemAdminController.getUserDetails.bind(systemAdminController)
);

// PUT /api/v1/system/users/:userId - Update user (cross-tenant)
const updateUserSchema = z.object({
  firstName: z.string().min(1).max(50).optional(),
  lastName: z.string().min(1).max(50).optional(),
  role: z.nativeEnum(UserRole).optional(),
  isActive: z.boolean().optional(),
  department: z.string().max(100).optional(),
  managerId: uuidSchema.nullable().optional()
});

router.put('/users/:userId',
  adminRateLimit,
  validateParams(z.object({ userId: uuidSchema })),
  sanitizeInput,
  validateBody(updateUserSchema),
  systemAdminController.updateUser.bind(systemAdminController)
);

// POST /api/v1/system/users/:userId/reset-password - Reset user password
router.post('/users/:userId/reset-password',
  adminRateLimit,
  validateParams(z.object({ userId: uuidSchema })),
  systemAdminController.resetUserPassword.bind(systemAdminController)
);

/**
 * Analytics Routes (System-wide)
 */

// GET /api/v1/system/analytics/overview - System-wide analytics
const analyticsFilterSchema = z.object({
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  tenantId: uuidSchema.optional()
});

router.get('/analytics/overview',
  validateQuery(analyticsFilterSchema),
  systemAdminController.getSystemAnalytics.bind(systemAdminController)
);

// GET /api/v1/system/analytics/tenants - Tenant usage analytics
router.get('/analytics/tenants',
  validateQuery(analyticsFilterSchema),
  systemAdminController.getTenantAnalytics.bind(systemAdminController)
);

/**
 * System Maintenance Routes
 */

// POST /api/v1/system/maintenance/cleanup - Run system cleanup tasks
router.post('/maintenance/cleanup',
  adminRateLimit,
  systemAdminController.runSystemCleanup.bind(systemAdminController)
);

// GET /api/v1/system/logs - Get system logs
const logsFilterSchema = z.object({
  level: z.enum(['error', 'warn', 'info', 'debug']).optional(),
  service: z.string().max(50).optional(),
  startDate: z.string().datetime().optional(),
  endDate: z.string().datetime().optional(),
  page: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional().default('1'),
  limit: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional().default('50')
});

router.get('/logs',
  validateQuery(logsFilterSchema),
  systemAdminController.getSystemLogs.bind(systemAdminController)
);

/**
 * Impersonation Routes (for debugging/support)
 */

// POST /api/v1/system/impersonate/:userId - Generate token to impersonate user
router.post('/impersonate/:userId',
  adminRateLimit,
  validateParams(z.object({ userId: uuidSchema })),
  systemAdminController.impersonateUser.bind(systemAdminController)
);

export default router;