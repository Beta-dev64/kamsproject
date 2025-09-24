import { Response } from 'express';
import { AuthRequest, LoginRequest, RegisterRequest } from '../types';
import { AuthService } from '../services/authService';
import { asyncHandler } from '../middleware/errorHandler';
import { jwtService } from '../utils/jwt';
import { logger } from '../utils/logger';

export class AuthController {
  private authService: AuthService;

  constructor() {
    this.authService = new AuthService();
  }

  /**
   * Register a new user
   * POST /api/v1/auth/register
   */
  register = asyncHandler(async (req: AuthRequest, res: Response) => {
    const userData: RegisterRequest = req.body;

    // Get request info for logging
    const requestInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    const result = await this.authService.register(userData, requestInfo);

    res.status(201).json({
      success: true,
      message: 'User registered successfully. Please verify your email.',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        expiresIn: result.expiresIn,
      },
    });
  });

  /**
   * Login user
   * POST /api/v1/auth/login
   */
  login = asyncHandler(async (req: AuthRequest, res: Response) => {
    const credentials: LoginRequest = req.body;

    // Get request info for logging
    const requestInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    const result = await this.authService.login(credentials, requestInfo);

    // Set refresh token in httpOnly cookie for additional security
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken, // Also include in response body
        expiresIn: result.expiresIn,
      },
    });
  });

   /**
   * Admin Login user
   * POST /api/v1/auth/login
   */
   adminLogin = asyncHandler(async (req: AuthRequest, res: Response) => {
    const credentials: LoginRequest = req.body;

    // Get request info for logging
    const requestInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    const result = await this.authService.adminLogin(credentials, requestInfo);

    // Set refresh token in httpOnly cookie for additional security
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      success: true,
      message: 'Login successful',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken, // Also include in response body
        expiresIn: result.expiresIn,
      },
    });
  });

  /**
   * Refresh access token
   * POST /api/v1/auth/refresh
   */
  refresh = asyncHandler(async (req: AuthRequest, res: Response) => {
    // Try to get refresh token from body, cookie, or header
    let refreshToken = req.body.refreshToken || req.cookies?.refreshToken;

    if (!refreshToken) {
      const authHeader = req.headers.authorization;
      refreshToken = jwtService.extractTokenFromHeader(authHeader);
    }

    if (!refreshToken) {
      return res.status(401).json({
        success: false,
        error: 'Refresh token required',
        code: 'REFRESH_TOKEN_REQUIRED',
      });
    }

    // Get request info for logging
    const requestInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    const result = await this.authService.refreshToken(refreshToken, requestInfo);

    // Update refresh token in cookie
    res.cookie('refreshToken', result.refreshToken, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'strict',
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    res.status(200).json({
      success: true,
      message: 'Token refreshed successfully',
      data: {
        user: result.user,
        accessToken: result.accessToken,
        refreshToken: result.refreshToken,
        expiresIn: result.expiresIn,
      },
    });
  });

  /**
   * Logout user
   * POST /api/v1/auth/logout
   */
  logout = asyncHandler(async (req: AuthRequest, res: Response) => {
    const userId = req.user?.id;

    if (!userId) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED',
      });
    }

    // Get refresh token from various sources
    const refreshToken = req.body.refreshToken || req.cookies?.refreshToken;

    // Get request info for logging
    const requestInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    await this.authService.logout(userId, refreshToken, requestInfo);

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    res.status(200).json({
      success: true,
      message: 'Logout successful',
    });
  });

  /**
   * Get current user profile
   * GET /api/v1/auth/me
   */
  me = asyncHandler(async (req: AuthRequest, res: Response) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED',
      });
    }

    res.status(200).json({
      success: true,
      data: {
        user: req.user,
      },
    });
  });

  /**
   * Validate token (for external services)
   * GET /api/v1/auth/validate
   */
  validate = asyncHandler(async (req: AuthRequest, res: Response) => {
    const authHeader = req.headers.authorization;
    const token = jwtService.extractTokenFromHeader(authHeader);

    if (!token) {
      return res.status(401).json({
        success: false,
        error: 'Token required',
        code: 'TOKEN_REQUIRED',
      });
    }

    try {
      const payload = jwtService.verifyAccessToken(token);
      
      res.status(200).json({
        success: true,
        message: 'Token is valid',
        data: {
          userId: payload.userId,
          tenantId: payload.tenantId,
          email: payload.email,
          role: payload.role,
          expiresAt: payload.exp ? new Date(payload.exp * 1000) : null,
        },
      });
    } catch (error) {
      res.status(401).json({
        success: false,
        error: 'Invalid token',
        code: 'INVALID_TOKEN',
        details: error instanceof Error ? error.message : 'Token validation failed',
      });
    }
  });

  /**
   * Change password
   * POST /api/v1/auth/change-password
   */
  changePassword = asyncHandler(async (req: AuthRequest, res: Response) => {
    // TODO: Implement password change functionality
    res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Password change functionality will be implemented in the next phase',
    });
  });

  /**
   * Forgot password
   * POST /api/v1/auth/forgot-password
   */
  forgotPassword = asyncHandler(async (req: AuthRequest, res: Response) => {
    // TODO: Implement forgot password functionality
    res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Forgot password functionality will be implemented in the next phase',
    });
  });

  /**
   * Reset password
   * POST /api/v1/auth/reset-password
   */
  resetPassword = asyncHandler(async (req: AuthRequest, res: Response) => {
    // TODO: Implement password reset functionality
    res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Password reset functionality will be implemented in the next phase',
    });
  });

  /**
   * Verify email
   * POST /api/v1/auth/verify-email
   */
  verifyEmail = asyncHandler(async (req: AuthRequest, res: Response) => {
    // TODO: Implement email verification functionality
    res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Email verification functionality will be implemented in the next phase',
    });
  });

  /**
   * Resend verification email
   * POST /api/v1/auth/resend-verification
   */
  resendVerification = asyncHandler(async (req: AuthRequest, res: Response) => {
    // TODO: Implement resend verification functionality
    res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Resend verification functionality will be implemented in the next phase',
    });
  });

  /**
   * Get user sessions (refresh tokens)
   * GET /api/v1/auth/sessions
   */
  getSessions = asyncHandler(async (req: AuthRequest, res: Response) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED',
      });
    }

    // TODO: Implement session management
    res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Session management will be implemented in the next phase',
    });
  });

  /**
   * Revoke session (specific refresh token)
   * DELETE /api/v1/auth/sessions/:sessionId
   */
  revokeSession = asyncHandler(async (req: AuthRequest, res: Response) => {
    // TODO: Implement session revocation
    res.status(501).json({
      success: false,
      error: 'Not implemented',
      message: 'Session revocation will be implemented in the next phase',
    });
  });

  /**
   * Logout from all devices
   * POST /api/v1/auth/logout-all
   */
  logoutAll = asyncHandler(async (req: AuthRequest, res: Response) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        error: 'Authentication required',
        code: 'AUTHENTICATION_REQUIRED',
      });
    }

    // Get request info for logging
    const requestInfo = {
      ip: req.ip,
      userAgent: req.get('User-Agent'),
    };

    // Logout from all devices (invalidate all refresh tokens)
    await this.authService.logout(req.user.id, undefined, requestInfo);

    // Clear refresh token cookie
    res.clearCookie('refreshToken');

    res.status(200).json({
      success: true,
      message: 'Logged out from all devices successfully',
    });
  });
}