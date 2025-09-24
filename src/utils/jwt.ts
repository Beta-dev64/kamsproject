import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import config from '../config';
import { User } from '../types';
import { logger } from './logger';

export interface JWTPayload {
  userId: string;
  tenantId: string;
  email: string;
  role: string;
  iat?: number;
  exp?: number;
}

export interface TokenPair {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

class JWTService {
  private readonly accessTokenSecret: string;
  private readonly refreshTokenSecret: string;
  private readonly accessTokenExpiry: string;
  private readonly refreshTokenExpiry: string;

  constructor() {
    this.accessTokenSecret = config.jwt.secret;
    this.refreshTokenSecret = config.jwt.secret + '_refresh'; // Different secret for refresh tokens
    this.accessTokenExpiry = config.jwt.expiresIn;
    this.refreshTokenExpiry = config.jwt.refreshExpiresIn;
  }

  /**
   * Generate access token
   */
  generateAccessToken(user: User): string {
    const payload: JWTPayload = {
      userId: user.id,
      tenantId: user.tenantId,
      email: user.email,
      role: user.role,
    };

    return jwt.sign(payload, this.accessTokenSecret, {
      expiresIn: this.accessTokenExpiry,
      issuer: config.app.name,
      subject: user.id,
      audience: 'kam-portal-api',
    } as jwt.SignOptions);
  }

  /**
   * Generate refresh token
   */
  generateRefreshToken(userId: string): string {
    const payload = {
      userId,
      tokenType: 'refresh',
    };

    return jwt.sign(payload, this.refreshTokenSecret, {
      expiresIn: this.refreshTokenExpiry,
      issuer: config.app.name,
      subject: userId,
      audience: 'kam-portal-api',
    } as jwt.SignOptions);
  }

  /**
   * Generate both access and refresh tokens
   */
  generateTokenPair(user: User): TokenPair {
    const accessToken = this.generateAccessToken(user);
    const refreshToken = this.generateRefreshToken(user.id);
    
    // Calculate expiry time in seconds
    const expiresIn = this.parseExpiryToSeconds(this.accessTokenExpiry);

    return {
      accessToken,
      refreshToken,
      expiresIn,
    };
  }

  /**
   * Verify and decode access token
   */
  verifyAccessToken(token: string): JWTPayload {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret, {
        issuer: config.app.name,
        audience: 'kam-portal-api',
      }) as JWTPayload;

      return decoded;
    } catch (error) {
      logger.warn('Access token verification failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        token: token.substring(0, 20) + '...',
      });
      throw new Error('Invalid access token');
    }
  }

  /**
   * Verify and decode refresh token
   */
  verifyRefreshToken(token: string): { userId: string; tokenType: string } {
    try {
      const decoded = jwt.verify(token, this.refreshTokenSecret, {
        issuer: config.app.name,
        audience: 'kam-portal-api',
      }) as any;

      if (decoded.tokenType !== 'refresh') {
        throw new Error('Invalid token type');
      }

      return decoded;
    } catch (error) {
      logger.warn('Refresh token verification failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        token: token.substring(0, 20) + '...',
      });
      throw new Error('Invalid refresh token');
    }
  }

  /**
   * Generate password reset token
   */
  generatePasswordResetToken(userId: string, email: string): string {
    const payload = {
      userId,
      email,
      tokenType: 'password_reset',
      timestamp: Date.now(),
    };

    return jwt.sign(payload, this.accessTokenSecret + userId, {
      expiresIn: '1h', // Password reset tokens expire in 1 hour
      issuer: config.app.name,
      subject: userId,
    });
  }

  /**
   * Verify password reset token
   */
  verifyPasswordResetToken(token: string, userId: string): { userId: string; email: string } {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret + userId, {
        issuer: config.app.name,
        subject: userId,
      }) as any;

      if (decoded.tokenType !== 'password_reset') {
        throw new Error('Invalid token type');
      }

      return {
        userId: decoded.userId,
        email: decoded.email,
      };
    } catch (error) {
      logger.warn('Password reset token verification failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        userId,
      });
      throw new Error('Invalid or expired password reset token');
    }
  }

  /**
   * Generate email verification token
   */
  generateEmailVerificationToken(userId: string, email: string): string {
    const payload = {
      userId,
      email,
      tokenType: 'email_verification',
      timestamp: Date.now(),
    };

    return jwt.sign(payload, this.accessTokenSecret + email, {
      expiresIn: '24h', // Email verification tokens expire in 24 hours
      issuer: config.app.name,
      subject: userId,
    });
  }

  /**
   * Verify email verification token
   */
  verifyEmailVerificationToken(token: string, email: string): { userId: string; email: string } {
    try {
      const decoded = jwt.verify(token, this.accessTokenSecret + email, {
        issuer: config.app.name,
      }) as any;

      if (decoded.tokenType !== 'email_verification') {
        throw new Error('Invalid token type');
      }

      return {
        userId: decoded.userId,
        email: decoded.email,
      };
    } catch (error) {
      logger.warn('Email verification token verification failed', {
        error: error instanceof Error ? error.message : 'Unknown error',
        email,
      });
      throw new Error('Invalid or expired email verification token');
    }
  }

  /**
   * Extract token from Authorization header
   */
  extractTokenFromHeader(authHeader?: string): string | null {
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return null;
    }

    return authHeader.substring(7); // Remove 'Bearer ' prefix
  }

  /**
   * Generate secure random token (for additional security)
   */
  generateSecureToken(length: number = 32): string {
    return crypto.randomBytes(length).toString('hex');
  }

  /**
   * Hash refresh token for database storage
   */
  hashRefreshToken(token: string): string {
    return crypto.createHash('sha256').update(token).digest('hex');
  }

  /**
   * Parse expiry string to seconds
   */
  private parseExpiryToSeconds(expiry: string): number {
    const match = expiry.match(/^(\d+)([smhd])$/);
    if (!match) {
      return 15 * 60; // Default to 15 minutes
    }

    const value = parseInt(match[1], 10);
    const unit = match[2];

    switch (unit) {
      case 's':
        return value;
      case 'm':
        return value * 60;
      case 'h':
        return value * 60 * 60;
      case 'd':
        return value * 24 * 60 * 60;
      default:
        return 15 * 60; // Default to 15 minutes
    }
  }

  /**
   * Check if token is expired (without verification)
   */
  isTokenExpired(token: string): boolean {
    try {
      const decoded = jwt.decode(token) as any;
      if (!decoded || !decoded.exp) {
        return true;
      }

      const currentTime = Math.floor(Date.now() / 1000);
      return decoded.exp < currentTime;
    } catch {
      return true;
    }
  }

  /**
   * Get token expiration time
   */
  getTokenExpiration(token: string): Date | null {
    try {
      const decoded = jwt.decode(token) as any;
      if (!decoded || !decoded.exp) {
        return null;
      }

      return new Date(decoded.exp * 1000);
    } catch {
      return null;
    }
  }
}

// Export singleton instance
export const jwtService = new JWTService();
export { JWTService };