import bcrypt from 'bcryptjs';
import { db } from '../database';
import { jwtService } from '../utils/jwt';
import { logger, logSecurityEvent, logAuditEvent } from '../utils/logger';
import config from '../config';
import {
  User,
  UserRole,
  AuthResponse,
  LoginRequest,
  RegisterRequest,
  CreateUserDTO,
} from '../types';
import {
  ValidationError,
  AuthenticationError,
  ConflictError,
  NotFoundError,
  TenantError,
} from '../middleware/errorHandler';

interface RefreshTokenRecord {
  id: string;
  user_id: string;
  token_hash: string;
  expires_at: Date;
  is_active: boolean;
}

export class AuthService {
  /**
   * Register a new user
   */
  async register(userData: RegisterRequest, requestInfo?: any): Promise<AuthResponse> {
    try {
      // Validate tenant exists
      const tenant = await db.queryOne(`
        SELECT id, name, max_users, subscription_tier 
        FROM kam_tenants 
        WHERE domain = $1 AND is_active = true AND deleted_at IS NULL
      `, [userData.tenantDomain]);

      if (!tenant) {
        throw new TenantError(`Invalid tenant domain: ${userData.tenantDomain}`);
      }

      // Check user limits for tenant
      const userCount = await db.queryOne(`
        SELECT COUNT(*) as count 
        FROM kam_profiles 
        WHERE tenant_id = $1 AND deleted_at IS NULL
      `, [tenant.id]);

      if (parseInt(userCount.count) >= tenant.max_users) {
        throw new ValidationError(`User limit reached for tenant. Maximum ${tenant.max_users} users allowed.`);
      }

      // Check if email already exists
      const existingUser = await db.queryOne(`
        SELECT id FROM kam_profiles 
        WHERE email = $1 AND deleted_at IS NULL
      `, [userData.email]);

      if (existingUser) {
        throw new ConflictError('Email address already registered');
      }

      // Validate password strength
      this.validatePassword(userData.password);

      // Hash password
      const passwordHash = await bcrypt.hash(userData.password, config.security.bcryptRounds);

      // Generate email verification token
      const emailVerificationToken = jwtService.generateSecureToken(32);

      // Create user within a transaction
      const user = await db.transaction(async (client) => {
        // Insert user
        const newUser = await client.query(`
          INSERT INTO kam_profiles (
            tenant_id, email, password_hash, first_name, last_name, 
            role, email_verification_token
          )
          VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING id, tenant_id, email, first_name, last_name, role, 
                    is_active, mfa_enabled, created_at, updated_at
        `, [
          tenant.id,
          userData.email,
          passwordHash,
          userData.firstName,
          userData.lastName,
          UserRole.USER, // Default role for registered users
          emailVerificationToken,
        ]);

        // Log audit event
        await client.query(`
          INSERT INTO kam_audit_logs (tenant_id, user_id, action, resource_type, resource_id, new_values, ip_address)
          VALUES ($1, $2, $3, $4, $5, $6, $7)
        `, [
          tenant.id,
          newUser.rows[0].id,
          'USER_REGISTERED',
          'user',
          newUser.rows[0].id,
          JSON.stringify({ email: userData.email, role: UserRole.USER }),
          requestInfo?.ip || null,
        ]);

        return newUser.rows[0];
      });

      // Map database user to User type
      const mappedUser: User = {
        id: user.id,
        tenantId: user.tenant_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role as UserRole,
        isActive: user.is_active,
        emailVerified: user.email_verified || false,
        createdAt: new Date(user.created_at),
        updatedAt: new Date(user.updated_at),
      };

      // Generate JWT tokens
      const tokenPair = jwtService.generateTokenPair(mappedUser);

      // Store refresh token
      await this.storeRefreshToken(user.id, tokenPair.refreshToken);

      // Log successful registration
      logSecurityEvent('USER_REGISTERED', {
        userId: user.id,
        tenantId: user.tenant_id,
        email: userData.email,
        ip: requestInfo?.ip,
        userAgent: requestInfo?.userAgent,
      });

      // TODO: Send welcome email with verification link

      return {
        user: mappedUser,
        accessToken: tokenPair.accessToken,
        refreshToken: tokenPair.refreshToken,
        expiresIn: tokenPair.expiresIn,
      };
    } catch (error) {
      logger.error('User registration failed', {
        email: userData.email,
        tenantDomain: userData.tenantDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Login user
   */
  async login(credentials: LoginRequest, requestInfo?: any): Promise<AuthResponse> {
    try {
      let user;
      let tenantId: string | null = null;

      if (credentials.tenantDomain) {
        // Login with tenant domain
        const tenant = await db.queryOne(`
          SELECT id FROM kam_tenants 
          WHERE domain = $1 AND is_active = true AND deleted_at IS NULL
        `, [credentials.tenantDomain]);

        if (!tenant) {
          throw new AuthenticationError('Invalid tenant domain');
        }

        tenantId = tenant.id;

        user = await db.queryOne(`
          SELECT id, tenant_id, email, password_hash, first_name, last_name, role, 
                 department, manager_id, is_active, last_login, mfa_enabled, 
                 email_verified, created_at, updated_at
          FROM kam_profiles 
          WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL
        `, [credentials.email, tenantId]);
      } else {
        // Login without tenant (for super admin)
        user = await db.queryOne(`
          SELECT id, tenant_id, email, password_hash, first_name, last_name, role, 
                 department, manager_id, is_active, last_login, mfa_enabled, 
                 email_verified, created_at, updated_at
          FROM kam_profiles 
          WHERE email = $1 AND (tenant_id IS NULL OR role = 'super_admin') AND deleted_at IS NULL
        `, [credentials.email]);
      }

      if (!user) {
        logSecurityEvent('LOGIN_FAILED_USER_NOT_FOUND', {
          email: credentials.email,
          tenantDomain: credentials.tenantDomain,
          ip: requestInfo?.ip,
          userAgent: requestInfo?.userAgent,
        });
        throw new AuthenticationError('Invalid email or password');
      }

      // Check if user is active
      if (!user.is_active) {
        logSecurityEvent('LOGIN_FAILED_USER_INACTIVE', {
          userId: user.id,
          email: credentials.email,
          ip: requestInfo?.ip,
          userAgent: requestInfo?.userAgent,
        });
        throw new AuthenticationError('Account is inactive. Please contact support.');
      }

      // Verify password
      const isPasswordValid = await bcrypt.compare(credentials.password, user.password_hash);

      if (!isPasswordValid) {
        logSecurityEvent('LOGIN_FAILED_INVALID_PASSWORD', {
          userId: user.id,
          email: credentials.email,
          ip: requestInfo?.ip,
          userAgent: requestInfo?.userAgent,
        });
        throw new AuthenticationError('Invalid email or password');
      }

      // Check email verification for non-admin users
      if (!user.email_verified && user.role !== UserRole.SUPER_ADMIN) {
        logSecurityEvent('LOGIN_FAILED_EMAIL_NOT_VERIFIED', {
          userId: user.id,
          email: credentials.email,
          ip: requestInfo?.ip,
        });
        throw new AuthenticationError('Please verify your email address before logging in');
      }

      // TODO: Check MFA if enabled

      // Map database user to User type
      const mappedUser: User = {
        id: user.id,
        tenantId: user.tenant_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role as UserRole,
        department: user.department,
        managerId: user.manager_id,
        isActive: user.is_active,
        emailVerified: user.email_verified || false,
        lastLoginAt: user.last_login ? new Date(user.last_login) : undefined,
        createdAt: new Date(user.created_at),
        updatedAt: new Date(user.updated_at),
      };

      // Generate JWT tokens
      const tokenPair = jwtService.generateTokenPair(mappedUser);

      // Store refresh token and update last login
      await db.transaction(async (client) => {
        // Update last login
        await client.query(`
          UPDATE kam_profiles 
          SET last_login = NOW() 
          WHERE id = $1
        `, [user.id]);

        // Store refresh token
        await this.storeRefreshToken(user.id, tokenPair.refreshToken);

        // Log audit event
        await client.query(`
          INSERT INTO kam_audit_logs (tenant_id, user_id, action, resource_type, resource_id, ip_address)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [
          user.tenant_id,
          user.id,
          'USER_LOGIN',
          'user',
          user.id,
          requestInfo?.ip || null,
        ]);
      });

      // Log successful login
      logSecurityEvent('LOGIN_SUCCESS', {
        userId: user.id,
        tenantId: user.tenant_id,
        role: user.role,
        ip: requestInfo?.ip,
        userAgent: requestInfo?.userAgent,
      });

      return {
        user: mappedUser,
        accessToken: tokenPair.accessToken,
        refreshToken: tokenPair.refreshToken,
        expiresIn: tokenPair.expiresIn,
      };
    } catch (error) {
      logger.error('User login failed', {
        email: credentials.email,
        tenantDomain: credentials.tenantDomain,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /***
   * Admin Login
   */

  async adminLogin(credentials: LoginRequest, requestInfo?: any): Promise<AuthResponse> {
    try {
      const user = await db.queryOne(`
        SELECT id, tenant_id, email, password_hash, first_name, last_name, role,
               department, manager_id, is_active, last_login, mfa_enabled,
               email_verified, created_at, updated_at
        FROM kam_profiles
        WHERE email = $1 AND deleted_at IS NULL
      `, [credentials.email]);
  
      if (!user) {
        logSecurityEvent('LOGIN_FAILED_USER_NOT_FOUND', {
          email: credentials.email,
          ip: requestInfo?.ip,
          userAgent: requestInfo?.userAgent,
        });
        throw new AuthenticationError('Invalid email or password');
      }
  
      // Check if user is active
      if (!user.is_active) {
        logSecurityEvent('LOGIN_FAILED_USER_INACTIVE', {
          userId: user.id,
          email: credentials.email,
          ip: requestInfo?.ip,
          userAgent: requestInfo?.userAgent,
        });
        throw new AuthenticationError('Account is inactive. Please contact support.');
      }
  
      // Verify password
      const isPasswordValid = await bcrypt.compare(credentials.password, user.password_hash);
  
      if (!isPasswordValid) {
        logSecurityEvent('LOGIN_FAILED_INVALID_PASSWORD', {
          userId: user.id,
          email: credentials.email,
          ip: requestInfo?.ip,
          userAgent: requestInfo?.userAgent,
        });
        throw new AuthenticationError('Invalid email or password');
      }
  
      // Check email verification for non-admin users
      if (!user.email_verified && user.role !== UserRole.SUPER_ADMIN) {
        logSecurityEvent('LOGIN_FAILED_EMAIL_NOT_VERIFIED', {
          userId: user.id,
          email: credentials.email,
          ip: requestInfo?.ip,
        });
        throw new AuthenticationError('Please verify your email address before logging in');
      }
  
      // TODO: Check MFA if enabled
  
      // Map database user to User type
      const mappedUser: User = {
        id: user.id,
        tenantId: user.tenant_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role as UserRole,
        department: user.department,
        managerId: user.manager_id,
        isActive: user.is_active,
        emailVerified: user.email_verified || false,
        lastLoginAt: user.last_login ? new Date(user.last_login) : undefined,
        createdAt: new Date(user.created_at),
        updatedAt: new Date(user.updated_at),
      };
  
      // Generate JWT tokens
      const tokenPair = jwtService.generateTokenPair(mappedUser);
  
      // Store refresh token and update last login
      await db.transaction(async (client) => {
        // Update last login
        await client.query(`
          UPDATE kam_profiles
          SET last_login = NOW()
          WHERE id = $1
        `, [user.id]);
  
        // Store refresh token
        await this.storeRefreshToken(user.id, tokenPair.refreshToken);
  
        // Log audit event
        await client.query(`
          INSERT INTO kam_audit_logs (tenant_id, user_id, action, resource_type, resource_id, ip_address)
          VALUES ($1, $2, $3, $4, $5, $6)
        `, [
          user.tenant_id,
          user.id,
          'USER_LOGIN',
          'user',
          user.id,
          requestInfo?.ip || null,
        ]);
      });
  
      // Log successful login
      logSecurityEvent('LOGIN_SUCCESS', {
        userId: user.id,
        tenantId: user.tenant_id,
        role: user.role,
        ip: requestInfo?.ip,
        userAgent: requestInfo?.userAgent,
      });
  
      return {
        user: mappedUser,
        accessToken: tokenPair.accessToken,
        refreshToken: tokenPair.refreshToken,
        expiresIn: tokenPair.expiresIn,
      };
    } catch (error) {
      logger.error('User login failed', {
        email: credentials.email,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Refresh access token
   */
  async refreshToken(refreshToken: string, requestInfo?: any): Promise<AuthResponse> {
    try {
      // Verify refresh token
      const tokenPayload = jwtService.verifyRefreshToken(refreshToken);

      // Check if refresh token exists in database
      const tokenHash = jwtService.hashRefreshToken(refreshToken);
      const storedToken = await db.queryOne<RefreshTokenRecord>(`
        SELECT id, user_id, expires_at, is_active 
        FROM kam_refresh_tokens 
        WHERE token_hash = $1 AND is_active = true
      `, [tokenHash]);

      if (!storedToken || storedToken.user_id !== tokenPayload.userId) {
        throw new AuthenticationError('Invalid refresh token');
      }

      // Check if token is expired
      if (new Date() > new Date(storedToken.expires_at)) {
        // Clean up expired token
        await db.query(`
          UPDATE kam_refresh_tokens 
          SET is_active = false 
          WHERE id = $1
        `, [storedToken.id]);

        throw new AuthenticationError('Refresh token expired');
      }

      // Load user
      const user = await db.queryOne(`
        SELECT id, tenant_id, email, first_name, last_name, role, 
               department, manager_id, is_active, last_login, mfa_enabled, 
               created_at, updated_at
        FROM kam_profiles 
        WHERE id = $1 AND is_active = true AND deleted_at IS NULL
      `, [tokenPayload.userId]);

      if (!user) {
        throw new AuthenticationError('User not found or inactive');
      }

      // Map to User type
      const mappedUser: User = {
        id: user.id,
        tenantId: user.tenant_id,
        email: user.email,
        firstName: user.first_name,
        lastName: user.last_name,
        role: user.role as UserRole,
        department: user.department,
        managerId: user.manager_id,
        isActive: user.is_active,
        emailVerified: user.email_verified || false,
        lastLoginAt: user.last_login ? new Date(user.last_login) : undefined,
        createdAt: new Date(user.created_at),
        updatedAt: new Date(user.updated_at),
      };

      // Generate new token pair
      const newTokenPair = jwtService.generateTokenPair(mappedUser);

      // Update refresh token in database
      await db.transaction(async (client) => {
        // Deactivate old token
        await client.query(`
          UPDATE kam_refresh_tokens 
          SET is_active = false 
          WHERE id = $1
        `, [storedToken.id]);

        // Store new refresh token
        await this.storeRefreshToken(user.id, newTokenPair.refreshToken);
      });

      // Log token refresh
      logSecurityEvent('TOKEN_REFRESHED', {
        userId: user.id,
        tenantId: user.tenant_id,
        ip: requestInfo?.ip,
        userAgent: requestInfo?.userAgent,
      });

      return {
        user: mappedUser,
        accessToken: newTokenPair.accessToken,
        refreshToken: newTokenPair.refreshToken,
        expiresIn: newTokenPair.expiresIn,
      };
    } catch (error) {
      logger.error('Token refresh failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Logout user (invalidate refresh token)
   */
  async logout(userId: string, refreshToken?: string, requestInfo?: any): Promise<void> {
    try {
      if (refreshToken) {
        const tokenHash = jwtService.hashRefreshToken(refreshToken);
        await db.query(`
          UPDATE kam_refresh_tokens 
          SET is_active = false 
          WHERE token_hash = $1 AND user_id = $2
        `, [tokenHash, userId]);
      } else {
        // Invalidate all refresh tokens for user
        await db.query(`
          UPDATE kam_refresh_tokens 
          SET is_active = false 
          WHERE user_id = $1
        `, [userId]);
      }

      // Log logout
      logSecurityEvent('USER_LOGOUT', {
        userId,
        ip: requestInfo?.ip,
        userAgent: requestInfo?.userAgent,
      });
    } catch (error) {
      logger.error('Logout failed', {
        userId,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  /**
   * Validate password strength
   */
  private validatePassword(password: string): void {
    if (password.length < 8) {
      throw new ValidationError('Password must be at least 8 characters long');
    }

    if (!/(?=.*[a-z])/.test(password)) {
      throw new ValidationError('Password must contain at least one lowercase letter');
    }

    if (!/(?=.*[A-Z])/.test(password)) {
      throw new ValidationError('Password must contain at least one uppercase letter');
    }

    if (!/(?=.*\d)/.test(password)) {
      throw new ValidationError('Password must contain at least one number');
    }

    if (!/(?=.*[@$!%*?&])/.test(password)) {
      throw new ValidationError('Password must contain at least one special character (@$!%*?&)');
    }
  }

  /**
   * Store refresh token in database
   */
  private async storeRefreshToken(userId: string, refreshToken: string): Promise<void> {
    const tokenHash = jwtService.hashRefreshToken(refreshToken);
    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 7); // 7 days from now

    await db.query(`
      INSERT INTO kam_refresh_tokens (user_id, token_hash, expires_at)
      VALUES ($1, $2, $3)
    `, [userId, tokenHash, expiresAt]);
  }

  /**
   * Clean up expired refresh tokens
   */
  async cleanupExpiredTokens(): Promise<void> {
    try {
      const result = await db.query(`
        UPDATE kam_refresh_tokens 
        SET is_active = false 
        WHERE expires_at < NOW() AND is_active = true
      `);

      logger.info('Cleaned up expired refresh tokens', {
        count: result.rowCount,
      });
    } catch (error) {
      logger.error('Failed to cleanup expired tokens', {
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }
}