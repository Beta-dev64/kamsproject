import express from 'express';
import { tenantController } from '../controllers/tenantController';
import { authenticateToken, requireRole } from '../middleware/auth';
import { rateLimiters } from '../middleware/rateLimiter';
import { requireValidTenant } from '../middleware/validation';
import { validateBody, validateQuery, validateParams, sanitizeInput } from '../middleware/validation';
import { z } from 'zod';
import { 
  createTenantSchema, 
  updateTenantSchema,
  updateSettingsSchema,
  uuidSchema 
} from '../utils/validation';
import { UserRole } from '../types';

const router: any = express.Router();

// Apply rate limiting
router.use(rateLimiters.api);

/**
 * Tenant Information Routes
 */

// GET /api/v1/tenants/current - Get current tenant information
router.get('/current',
  authenticateToken,
  requireValidTenant,
  tenantController.getCurrentTenant.bind(tenantController)
);

// GET /api/v1/tenants/:tenantId - Get tenant by ID (super admin only)
router.get('/:tenantId',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN]),
  validateParams(z.object({ tenantId: uuidSchema })),
  tenantController.getTenantById.bind(tenantController)
);

// POST /api/v1/tenants - Create new tenant (super admin only)
router.post('/',
  rateLimiters.adminOperations,
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN]),
  sanitizeInput,
  validateBody(createTenantSchema),
  tenantController.createTenant.bind(tenantController)
);

// PUT /api/v1/tenants/:tenantId - Update tenant (admin only)
router.put('/:tenantId',
  rateLimiters.sensitiveOperations,
  authenticateToken,
  validateParams(z.object({ tenantId: uuidSchema })),
  sanitizeInput,
  validateBody(updateTenantSchema),
  tenantController.updateTenant.bind(tenantController)
);

/**
 * Tenant Settings Routes
 */

// GET /api/v1/tenants/settings - Get tenant settings
router.get('/settings',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  requireValidTenant,
  tenantController.getTenantSettings.bind(tenantController)
);

// PUT /api/v1/tenants/settings - Update tenant settings
router.put('/settings',
  rateLimiters.sensitiveOperations,
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  requireValidTenant,
  sanitizeInput,
  validateBody(updateSettingsSchema),
  tenantController.updateTenantSettings.bind(tenantController)
);

/**
 * User Invitation Routes
 */

// Define invitation validation schema
const inviteUserSchema = z.object({
  email: z.string().email('Invalid email format'),
  role: z.nativeEnum(UserRole, { errorMap: () => ({ message: 'Invalid role' }) }),
  customMessage: z.string().max(500, 'Custom message too long').optional(),
});

// POST /api/v1/tenants/invitations - Send user invitation
router.post('/invitations',
  rateLimiters.sensitiveOperations,
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  requireValidTenant,
  sanitizeInput,
  validateBody(inviteUserSchema),
  tenantController.inviteUser.bind(tenantController)
);

// GET /api/v1/tenants/invitations - Get tenant invitations
const invitationFilterSchema = z.object({
  pending: z.enum(['true', 'false']).optional(),
  email: z.string().max(100).optional(),
  role: z.nativeEnum(UserRole).optional(),
  page: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional(),
  limit: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).optional(),
});

router.get('/invitations',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  requireValidTenant,
  validateQuery(invitationFilterSchema),
  tenantController.getTenantInvitations.bind(tenantController)
);

// POST /api/v1/tenants/invitations/:invitationId/resend - Resend invitation
router.post('/invitations/:invitationId/resend',
  rateLimiters.sensitiveOperations,
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  requireValidTenant,
  validateParams(z.object({ invitationId: uuidSchema })),
  tenantController.resendInvitation.bind(tenantController)
);

// DELETE /api/v1/tenants/invitations/:invitationId - Cancel invitation
router.delete('/invitations/:invitationId',
  rateLimiters.adminOperations,
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  requireValidTenant,
  validateParams(z.object({ invitationId: uuidSchema })),
  tenantController.cancelInvitation.bind(tenantController)
);

/**
 * Tenant Statistics Routes
 */

// GET /api/v1/tenants/stats - Get tenant statistics
router.get('/stats',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  requireValidTenant,
  tenantController.getTenantStats.bind(tenantController)
);

export default router;