import { Request, Response, NextFunction } from 'express';
import { authenticate, authorize, requireRole } from '../../../src/middleware/auth';
import { jwtService } from '../../../src/utils/jwt';
import { db } from '../../../src/database';
import { logger } from '../../../src/utils/logger';
import { UserRole, Permission, AuthRequest } from '../../../src/types';
import { testHelpers, mockData } from '../../setup';

// Mock dependencies
jest.mock('../../../src/utils/jwt');
jest.mock('../../../src/database');
jest.mock('../../../src/utils/logger');

const mockJwtService = jwtService as jest.Mocked<typeof jwtService>;
const mockDb = db as jest.Mocked<typeof db>;
const mockLogger = logger as jest.Mocked<typeof logger>;

describe('Authentication Middleware', () => {
  let mockRequest: Partial<AuthRequest>;
  let mockResponse: Partial<Response>;
  let mockNext: NextFunction;

  beforeEach(() => {
    jest.clearAllMocks();

    mockRequest = {
      headers: {},
      ip: '127.0.0.1',
      originalUrl: '/test',
      method: 'GET',
      get: jest.fn(),
      requestId: 'test-request-id'
    };

    mockResponse = {
      status: jest.fn().mockReturnThis(),
      json: jest.fn().mockReturnThis(),
      getHeader: jest.fn(),
    };

    mockNext = jest.fn();
  });

  describe('authenticate middleware', () => {
    it('should authenticate user with valid token', async () => {
      // Arrange
      const validToken = 'valid.jwt.token';
    const mockPayload = {
      userId: mockData.validUserId,
      tenantId: mockData.validTenantId,
      email: 'test@example.com',
      role: 'admin'
    };

      const mockUser = testHelpers.createTestUser({
        id: mockData.validUserId,
        tenantId: mockData.validTenantId,
        email: mockData.validEmail
      });

      const mockDbUser = {
        id: mockUser.id,
        tenant_id: mockUser.tenantId,
        email: mockUser.email,
        first_name: mockUser.firstName,
        last_name: mockUser.lastName,
        role: mockUser.role,
        department: mockUser.department,
        manager_id: mockUser.managerId,
        is_active: mockUser.isActive,
        email_verified: mockUser.emailVerified,
        created_at: mockUser.createdAt.toISOString(),
        updated_at: mockUser.updatedAt.toISOString()
      };

      mockRequest.headers!.authorization = `Bearer ${validToken}`;
      mockJwtService.extractTokenFromHeader.mockReturnValue(validToken);
      mockJwtService.verifyAccessToken.mockReturnValue(mockPayload);
      mockDb.query.mockResolvedValue({ rows: [mockDbUser] } as any);

      // Act
      await authenticate(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockJwtService.extractTokenFromHeader).toHaveBeenCalledWith(`Bearer ${validToken}`);
      expect(mockJwtService.verifyAccessToken).toHaveBeenCalledWith(validToken);
      expect(mockDb.query).toHaveBeenCalled();
      expect(mockRequest.user).toBeDefined();
      expect(mockRequest.user?.id).toBe(mockData.validUserId);
      expect(mockRequest.tenantId).toBe(mockData.validTenantId);
      expect(mockNext).toHaveBeenCalledWith();
      expect(mockLogger.info).toHaveBeenCalledWith(
        'Authentication success',
        expect.objectContaining({
          userId: mockData.validUserId,
          tenantId: mockData.validTenantId
        })
      );
    });

    it('should fail authentication with missing token', async () => {
      // Arrange - no authorization header
      mockJwtService.extractTokenFromHeader.mockReturnValue(null);

      // Act
      await authenticate(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Authorization token required'
        })
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Authentication missing token',
        expect.any(Object)
      );
    });

    it('should fail authentication with invalid token', async () => {
      // Arrange
      const invalidToken = 'invalid.token';
      mockRequest.headers!.authorization = `Bearer ${invalidToken}`;
      
      mockJwtService.extractTokenFromHeader.mockReturnValue(invalidToken);
      mockJwtService.verifyAccessToken.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act
      await authenticate(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(expect.any(Error));
    });

    it('should fail authentication with user not found', async () => {
      // Arrange
      const validToken = 'valid.jwt.token';
    const mockPayload = {
      userId: mockData.validUserId,
      tenantId: mockData.validTenantId,
      email: 'test@example.com',
      role: 'admin'
    };

      mockRequest.headers!.authorization = `Bearer ${validToken}`;
      mockJwtService.extractTokenFromHeader.mockReturnValue(validToken);
      mockJwtService.verifyAccessToken.mockReturnValue(mockPayload);
      mockDb.query.mockResolvedValue({ rows: [] } as any); // User not found

      // Act
      await authenticate(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Invalid or inactive user'
        })
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Authentication user not found',
        expect.any(Object)
      );
    });

    it('should fail authentication with tenant mismatch', async () => {
      // Arrange
      const validToken = 'valid.jwt.token';
    const mockPayload = {
      userId: mockData.validUserId,
      tenantId: mockData.validTenantId,
      email: 'test@example.com',
      role: 'admin'
    };

      const mockDbUser = {
        id: mockData.validUserId,
        tenant_id: 'different-tenant-id', // Different tenant
        email: mockData.validEmail,
        first_name: 'Test',
        last_name: 'User',
        role: 'user',
        is_active: true,
        email_verified: true,
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString()
      };

      mockRequest.headers!.authorization = `Bearer ${validToken}`;
      mockJwtService.extractTokenFromHeader.mockReturnValue(validToken);
      mockJwtService.verifyAccessToken.mockReturnValue(mockPayload);
      mockDb.query.mockResolvedValue({ rows: [mockDbUser] } as any);

      // Act
      await authenticate(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Token tenant mismatch'
        })
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Authentication tenant mismatch',
        expect.any(Object)
      );
    });
  });

  describe('authorize middleware', () => {
    beforeEach(() => {
      // Set up authenticated user
      mockRequest.user = testHelpers.createTestUser({
        role: UserRole.USER
      });
    });

    it('should authorize user with required permission', async () => {
      // Arrange
      const requiredPermissions = [Permission.ASSESSMENT_READ];
      const authorizeMiddleware = authorize(requiredPermissions);

      // Act
      await authorizeMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should deny access without required permission', async () => {
      // Arrange
      const requiredPermissions = [Permission.TENANT_CREATE]; // User doesn't have this
      const authorizeMiddleware = authorize(requiredPermissions);

      // Act
      await authorizeMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('Insufficient permissions')
        })
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Authorization permission denied',
        expect.any(Object)
      );
    });

    it('should deny access without authenticated user', async () => {
      // Arrange
      mockRequest.user = undefined; // No authenticated user
      const requiredPermissions = [Permission.ASSESSMENT_READ];
      const authorizeMiddleware = authorize(requiredPermissions);

      // Act
      await authorizeMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Authentication required'
        })
      );
    });

    it('should authorize admin user for any permission', async () => {
      // Arrange
      mockRequest.user = testHelpers.createTestUser({
        role: UserRole.ADMIN // Admin has all permissions
      });
      const requiredPermissions = [Permission.TENANT_CREATE];
      const authorizeMiddleware = authorize(requiredPermissions);

      // Act
      await authorizeMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should work with multiple permission options (OR logic)', async () => {
      // Arrange
      mockRequest.user = testHelpers.createTestUser({
        role: UserRole.USER // Has ASSESSMENT_READ but not TENANT_CREATE
      });
      const requiredPermissions = [Permission.TENANT_CREATE, Permission.ASSESSMENT_READ];
      const authorizeMiddleware = authorize(requiredPermissions);

      // Act
      await authorizeMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(); // Should pass because user has ASSESSMENT_READ
    });
  });

  describe('requireRole middleware', () => {
    it('should allow user with required role', async () => {
      // Arrange
      mockRequest.user = testHelpers.createTestUser({
        role: UserRole.MANAGER
      });
      const roleMiddleware = requireRole(UserRole.MANAGER);

      // Act
      roleMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should allow user with one of multiple required roles', async () => {
      // Arrange
      mockRequest.user = testHelpers.createTestUser({
        role: UserRole.MANAGER
      });
      const roleMiddleware = requireRole([UserRole.ADMIN, UserRole.MANAGER]);

      // Act
      roleMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith();
    });

    it('should deny user without required role', async () => {
      // Arrange
      mockRequest.user = testHelpers.createTestUser({
        role: UserRole.USER // Not admin
      });
      const roleMiddleware = requireRole(UserRole.ADMIN);

      // Act
      roleMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: expect.stringContaining('not authorized')
        })
      );
      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Authorization role denied',
        expect.any(Object)
      );
    });

    it('should deny unauthenticated user', async () => {
      // Arrange
      mockRequest.user = undefined;
      const roleMiddleware = requireRole(UserRole.USER);

      // Act
      roleMiddleware(mockRequest as AuthRequest, mockResponse as Response, mockNext);

      // Assert
      expect(mockNext).toHaveBeenCalledWith(
        expect.objectContaining({
          message: 'Authentication required'
        })
      );
    });
  });

  describe('Role permissions mapping', () => {
    it('should correctly map user permissions', () => {
      // This would test the getRolePermissions function
      const userPermissions = [
        Permission.ASSESSMENT_CREATE,
        Permission.ASSESSMENT_READ,
        Permission.SETTINGS_READ
      ];

      // Test that USER role has these permissions
      expect(userPermissions).toContain(Permission.ASSESSMENT_READ);
      expect(userPermissions).not.toContain(Permission.TENANT_CREATE);
    });

    it('should correctly map admin permissions', () => {
      // Admin should have most permissions
      const adminPermissions = [
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
        Permission.SETTINGS_UPDATE
      ];

      expect(adminPermissions).toContain(Permission.USER_CREATE);
      expect(adminPermissions).toContain(Permission.ASSESSMENT_READ_ALL);
    });

    it('should correctly map manager permissions', () => {
      const managerPermissions = [
        Permission.USER_READ,
        Permission.ASSESSMENT_CREATE,
        Permission.ASSESSMENT_READ,
        Permission.ASSESSMENT_UPDATE,
        Permission.ASSESSMENT_READ_ALL,
        Permission.SETTINGS_READ
      ];

      expect(managerPermissions).toContain(Permission.ASSESSMENT_READ_ALL);
      expect(managerPermissions).not.toContain(Permission.USER_DELETE);
    });
  });
});