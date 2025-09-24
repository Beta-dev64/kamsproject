import express from 'express';
import { userController } from '../controllers/userController';
import { authenticateToken, requireRole, requireManagerOf, requireSelfOrRole } from '../middleware/auth';
import { rateLimiters } from '../middleware/rateLimiter';
import { requireValidTenant } from '../middleware/validation';
import { validateBody, validateQuery, validateParams, sanitizeInput } from '../middleware/validation';
import { z } from 'zod';
import { 
  createUserSchema, 
  updateUserSchema, 
  updateProfileSchema,
  userFilterSchema,
  uuidSchema 
} from '../utils/validation';
import { UserRole } from '../types';

const router: any = express.Router();

// Apply tenant validation to all routes
router.use(requireValidTenant);

// Apply rate limiting
router.use(rateLimiters.api);

/**
 * Profile Management Routes (User can manage their own profile)
 */

// GET /api/v1/users/profile - Get current user profile
router.get('/profile', 
  authenticateToken,
  userController.getProfile.bind(userController)
);

// PUT /api/v1/users/profile - Update current user profile
router.put('/profile',
  rateLimiters.sensitiveOperations,
  authenticateToken,
  sanitizeInput,
  validateBody(updateProfileSchema),
  userController.updateProfile.bind(userController)
);

/**
 * User Management Routes (Admin/Manager only)
 */

// GET /api/v1/users - Get users with filtering and pagination
router.get('/',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER]),
  validateQuery(userFilterSchema),
  userController.getUsers.bind(userController)
);

// POST /api/v1/users - Create new user (Admin only)
router.post('/',
  rateLimiters.adminOperations,
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  sanitizeInput,
  validateBody(createUserSchema),
  userController.createUser.bind(userController)
);

// GET /api/v1/users/:userId - Get user by ID (with permission check)
router.get('/:userId',
  authenticateToken,
  validateParams(z.object({ userId: uuidSchema })),
  userController.getUserById.bind(userController)
);

// PUT /api/v1/users/:userId - Update user (with permission check)
router.put('/:userId',
  rateLimiters.sensitiveOperations,
  authenticateToken,
  validateParams(z.object({ userId: uuidSchema })),
  sanitizeInput,
  validateBody(updateUserSchema),
  userController.updateUser.bind(userController)
);

// DELETE /api/v1/users/:userId - Delete user (Admin only)
router.delete('/:userId',
  rateLimiters.adminOperations,
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN]),
  validateParams(z.object({ userId: uuidSchema })),
  userController.deleteUser.bind(userController)
);

/**
 * Role-based User Retrieval Routes
 */

// GET /api/v1/users/role/:role - Get users by role
router.get('/role/:role',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER]),
  userController.getUsersByRole.bind(userController)
);

/**
 * Hierarchical User Management Routes
 */

// GET /api/v1/users/reports/:managerId? - Get direct reports
// If managerId is not provided, returns current user's reports
router.get('/reports/:managerId?',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER]),
  userController.getDirectReports.bind(userController)
);

// GET /api/v1/users/department/:department - Get users in department
router.get('/department/:department',
  authenticateToken,
  requireRole([UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER]),
  userController.getDepartmentUsers.bind(userController)
);

export default router;