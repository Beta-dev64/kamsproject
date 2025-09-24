import { Router } from 'express';
import { AuthController } from '../controllers/authController';
import { authenticate, optionalAuthenticate } from '../middleware/auth';
import { 
  authRateLimit, 
  passwordResetRateLimit, 
  registrationRateLimit 
} from '../middleware/rateLimiter';
import { 
  requireTenant, 
  validateUserTenant 
} from '../middleware/tenantIsolation';
import { validateBody, sanitizeInput } from '../middleware/validation';
import { 
  registerSchema, 
  loginSchema, 
  refreshTokenSchema,
  changePasswordSchema 
} from '../utils/validation';

const router: any = Router();
const authController = new AuthController();

// Public routes (no authentication required)

/**
 * @route   POST /api/v1/auth/register
 * @desc    Register a new user
 * @access  Public
 * @rateLimit 5 registrations per hour per IP
 */
router.post('/register', 
  registrationRateLimit,
  sanitizeInput,
  validateBody(registerSchema),
  authController.register
);

/**
 * @route   POST /api/v1/auth/login
 * @desc    Login user
 * @access  Public
 * @rateLimit 5 attempts per 15 minutes per IP+email
 */
router.post('/login', 
  authRateLimit,
  sanitizeInput,
  validateBody(loginSchema),
  authController.login
);

// Public auth route for super admins (no tenant required)
router.post('/admin-login',
  authRateLimit,
  sanitizeInput,
  validateBody(loginSchema),
  authController.adminLogin
);

/**
 * @route   POST /api/v1/auth/refresh
 * @desc    Refresh access token
 * @access  Public (but requires refresh token)
 * @rateLimit Standard API rate limit
 */
router.post('/refresh', 
  authController.refresh
);

/**
 * @route   GET /api/v1/auth/validate
 * @desc    Validate access token (for external services)
 * @access  Public (but requires access token)
 * @rateLimit Standard API rate limit
 */
router.get('/validate', 
  authController.validate
);

/**
 * @route   POST /api/v1/auth/forgot-password
 * @desc    Request password reset
 * @access  Public
 * @rateLimit 3 attempts per hour per IP+email
 */
router.post('/forgot-password', 
  passwordResetRateLimit,
  authController.forgotPassword
);

/**
 * @route   POST /api/v1/auth/reset-password
 * @desc    Reset password with token
 * @access  Public
 * @rateLimit 3 attempts per hour per IP+email
 */
router.post('/reset-password', 
  passwordResetRateLimit,
  authController.resetPassword
);

/**
 * @route   POST /api/v1/auth/verify-email
 * @desc    Verify email address
 * @access  Public
 */
router.post('/verify-email', 
  authController.verifyEmail
);

/**
 * @route   POST /api/v1/auth/resend-verification
 * @desc    Resend email verification
 * @access  Public
 * @rateLimit 3 attempts per hour per IP+email
 */
router.post('/resend-verification', 
  passwordResetRateLimit, // Reuse password reset rate limiter
  authController.resendVerification
);

// Protected routes (authentication required)

/**
 * @route   GET /api/v1/auth/me
 * @desc    Get current user profile
 * @access  Private
 * @middleware Authenticate user, validate tenant
 */
router.get('/me', 
  authenticate,
  requireTenant,
  validateUserTenant,
  authController.me
);

/**
 * @route   POST /api/v1/auth/logout
 * @desc    Logout user (invalidate refresh token)
 * @access  Private
 * @middleware Authenticate user
 */
router.post('/logout', 
  authenticate,
  authController.logout
);

/**
 * @route   POST /api/v1/auth/logout-all
 * @desc    Logout from all devices (invalidate all refresh tokens)
 * @access  Private
 * @middleware Authenticate user
 */
router.post('/logout-all', 
  authenticate,
  authController.logoutAll
);

/**
 * @route   POST /api/v1/auth/change-password
 * @desc    Change user password
 * @access  Private
 * @middleware Authenticate user, validate tenant, rate limit
 */
router.post('/change-password', 
  authRateLimit, // Use auth rate limiter for password changes
  authenticate,
  requireTenant,
  validateUserTenant,
  sanitizeInput,
  validateBody(changePasswordSchema),
  authController.changePassword
);

/**
 * @route   GET /api/v1/auth/sessions
 * @desc    Get user active sessions
 * @access  Private
 * @middleware Authenticate user, validate tenant
 */
router.get('/sessions', 
  authenticate,
  requireTenant,
  validateUserTenant,
  authController.getSessions
);

/**
 * @route   DELETE /api/v1/auth/sessions/:sessionId
 * @desc    Revoke specific session
 * @access  Private
 * @middleware Authenticate user, validate tenant
 */
router.delete('/sessions/:sessionId', 
  authenticate,
  requireTenant,
  validateUserTenant,
  authController.revokeSession
);

export default router;