import { AuthService } from '../../../src/services/authService';
import { db } from '../../../src/database';
import { logger } from '../../../src/utils/logger';
import { jwtService } from '../../../src/utils/jwt';
import bcrypt from 'bcryptjs';
// Mock UUID generator for tests
const mockUUID = () => `mock-uuid-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;

// Inline test configuration and mock data
const testConfig = {
  security: {
    bcryptRounds: 4
  }
};

const mockData = {
  validEmail: 'test@example.com',
  validPassword: 'TestPassword123!',
  validTenantDomain: 'test-company',
  validUserId: '123e4567-e89b-12d3-a456-426614174000',
  validTenantId: '123e4567-e89b-12d3-a456-426614174001'
};

const testHelpers = {
  generateTestUUID: () => mockUUID(),
  createTestUser: (overrides: any = {}) => ({
    id: mockUUID(),
    tenantId: mockUUID(),
    email: mockData.validEmail,
    firstName: 'Test',
    lastName: 'User',
    role: 'user',
    isActive: true,
    emailVerified: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  }),
  createTestTenant: (overrides: any = {}) => ({
    id: mockUUID(),
    name: 'Test Company',
    domain: mockData.validTenantDomain,
    settings: {},
    subscriptionTier: 'basic',
    maxUsers: 100,
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    ...overrides
  })
};

// Mock dependencies
jest.mock('../../../src/database');
jest.mock('../../../src/utils/logger');
jest.mock('../../../src/utils/jwt');
jest.mock('bcryptjs');

const mockDb = db as jest.Mocked<typeof db>;
const mockLogger = logger as jest.Mocked<typeof logger>;
const mockJwtService = jwtService as jest.Mocked<typeof jwtService>;
const mockBcrypt = bcrypt as jest.Mocked<typeof bcrypt>;

describe('AuthService', () => {
  let authService: AuthService;

  beforeAll(() => {
    authService = new AuthService();
  });
  beforeEach(() => {
    jest.clearAllMocks();
  });

  describe('register', () => {
    it('should register a new user successfully', async () => {
      // Arrange
      const registrationData = {
        email: mockData.validEmail,
        password: mockData.validPassword,
        firstName: 'John',
        lastName: 'Doe',
        tenantDomain: mockData.validTenantDomain
      };

      const mockTenant = testHelpers.createTestTenant({
        domain: mockData.validTenantDomain
      });

      const mockUser = testHelpers.createTestUser({
        email: mockData.validEmail,
        firstName: 'John',
        lastName: 'Doe',
        tenantId: mockTenant.id
      });

      const hashedPassword = 'hashedPassword123';
      const accessToken = 'access.jwt.token';
      const refreshToken = 'refresh.jwt.token';

      // Mock database responses
      mockDb.queryOne
        .mockResolvedValueOnce(mockTenant) // Tenant lookup
        .mockResolvedValueOnce(null) // User doesn't exist
        .mockResolvedValueOnce(mockUser); // User creation

      (mockBcrypt.hash as jest.MockedFunction<any>).mockResolvedValue(hashedPassword);
      mockJwtService.generateAccessToken.mockReturnValue(accessToken);
      mockJwtService.generateRefreshToken.mockReturnValue(refreshToken);

      // Act
      const result = await authService.register(registrationData);

      // Assert
      expect(result).toEqual({
        user: expect.objectContaining({
          email: mockData.validEmail,
          firstName: 'John',
          lastName: 'Doe'
        }),
        accessToken,
        refreshToken,
        expiresIn: expect.any(Number)
      });

      expect(mockDb.queryOne).toHaveBeenCalledTimes(3);
      expect(mockBcrypt.hash).toHaveBeenCalledWith(
        mockData.validPassword,
        testConfig.security.bcryptRounds
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        'User registration successful',
        expect.objectContaining({
          userId: mockUser.id,
          email: mockData.validEmail
        })
      );
    });

    it('should throw error if tenant not found', async () => {
      // Arrange
      const registrationData = {
        email: mockData.validEmail,
        password: mockData.validPassword,
        firstName: 'John',
        lastName: 'Doe',
        tenantDomain: 'non-existent-tenant'
      };

      mockDb.queryOne.mockResolvedValue(null); // Tenant not found

      // Act & Assert
      await expect(authService.register(registrationData))
        .rejects.toThrow('Tenant not found or inactive');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Registration failed - tenant not found',
        expect.objectContaining({
          tenantDomain: 'non-existent-tenant'
        })
      );
    });

    it('should throw error if user already exists', async () => {
      // Arrange
      const registrationData = {
        email: mockData.validEmail,
        password: mockData.validPassword,
        firstName: 'John',
        lastName: 'Doe',
        tenantDomain: mockData.validTenantDomain
      };

      const mockTenant = testHelpers.createTestTenant();
      const existingUser = testHelpers.createTestUser();

      mockDb.queryOne
        .mockResolvedValueOnce(mockTenant) // Tenant lookup
        .mockResolvedValueOnce(existingUser); // User already exists

      // Act & Assert
      await expect(authService.register(registrationData))
        .rejects.toThrow('User with this email already exists');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Registration failed - user already exists',
        expect.objectContaining({
          email: mockData.validEmail
        })
      );
    });
  });

  describe('login', () => {
    it('should login user successfully with valid credentials', async () => {
      // Arrange
      const loginData = {
        email: mockData.validEmail,
        password: mockData.validPassword,
        tenantDomain: mockData.validTenantDomain
      };

      const mockTenant = testHelpers.createTestTenant({
        domain: mockData.validTenantDomain
      });

      const mockUser = testHelpers.createTestUser({
        email: mockData.validEmail,
        tenantId: mockTenant.id
      });

      const mockDbUser = {
        ...mockUser,
        password_hash: 'hashedPassword123'
      };

      const accessToken = 'access.jwt.token';
      const refreshToken = 'refresh.jwt.token';
      const refreshTokenHash = 'hashedRefreshToken';

      mockDb.queryOne
        .mockResolvedValueOnce(mockTenant) // Tenant lookup
        .mockResolvedValueOnce(mockDbUser) // User lookup
        .mockResolvedValueOnce({ id: 'refresh-token-id' }); // Refresh token creation

      (mockBcrypt.compare as jest.MockedFunction<any>).mockResolvedValue(true);
      mockJwtService.generateAccessToken.mockReturnValue(accessToken);
      mockJwtService.generateRefreshToken.mockReturnValue(refreshToken);
      mockJwtService.hashRefreshToken.mockReturnValue(refreshTokenHash);

      // Act
      const result = await authService.login(loginData);

      // Assert
      expect(result).toEqual({
        user: expect.objectContaining({
          email: mockData.validEmail,
          id: mockUser.id
        }),
        accessToken,
        refreshToken,
        expiresIn: expect.any(Number)
      });

      expect(mockBcrypt.compare).toHaveBeenCalledWith(
        mockData.validPassword,
        'hashedPassword123'
      );

      expect(mockLogger.info).toHaveBeenCalledWith(
        'User login successful',
        expect.objectContaining({
          userId: mockUser.id,
          email: mockData.validEmail
        })
      );
    });

    it('should throw error with invalid credentials', async () => {
      // Arrange
      const loginData = {
        email: mockData.validEmail,
        password: 'wrongpassword',
        tenantDomain: mockData.validTenantDomain
      };

      const mockTenant = testHelpers.createTestTenant();
      const mockUser = testHelpers.createTestUser();
      const mockDbUser = {
        ...mockUser,
        password_hash: 'hashedPassword123'
      };

      mockDb.queryOne
        .mockResolvedValueOnce(mockTenant) // Tenant lookup
        .mockResolvedValueOnce(mockDbUser); // User lookup

      (mockBcrypt.compare as jest.MockedFunction<any>).mockResolvedValue(false); // Password doesn't match

      // Act & Assert
      await expect(authService.login(loginData))
        .rejects.toThrow('Invalid email or password');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Login failed - invalid credentials',
        expect.objectContaining({
          email: mockData.validEmail
        })
      );
    });

    it('should throw error if user not found', async () => {
      // Arrange
      const loginData = {
        email: 'nonexistent@example.com',
        password: mockData.validPassword,
        tenantDomain: mockData.validTenantDomain
      };

      const mockTenant = testHelpers.createTestTenant();

      mockDb.queryOne
        .mockResolvedValueOnce(mockTenant) // Tenant lookup
        .mockResolvedValueOnce(null); // User not found

      // Act & Assert
      await expect(authService.login(loginData))
        .rejects.toThrow('Invalid email or password');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Login failed - user not found',
        expect.objectContaining({
          email: 'nonexistent@example.com'
        })
      );
    });

    it('should throw error if tenant not found', async () => {
      // Arrange
      const loginData = {
        email: mockData.validEmail,
        password: mockData.validPassword,
        tenantDomain: 'nonexistent-tenant'
      };

      mockDb.queryOne.mockResolvedValue(null); // Tenant not found

      // Act & Assert
      await expect(authService.login(loginData))
        .rejects.toThrow('Invalid tenant domain');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Login failed - invalid tenant',
        expect.objectContaining({
          tenantDomain: 'nonexistent-tenant'
        })
      );
    });
  });

  describe('refreshToken', () => {
    it('should refresh token successfully', async () => {
      // Arrange
      const oldRefreshToken = 'old.refresh.token';
      const newAccessToken = 'new.access.token';
      const newRefreshToken = 'new.refresh.token';
      const tokenHash = 'hashedToken';

      const mockPayload = {
        userId: mockData.validUserId,
        tokenType: 'refresh'
      };

      const mockUser = testHelpers.createTestUser({
        id: mockData.validUserId,
        tenantId: mockData.validTenantId
      });

      const mockStoredToken = {
        id: 'stored-token-id',
        userId: mockData.validUserId,
        tokenHash,
        isActive: true,
        expiresAt: new Date(Date.now() + 86400000) // 1 day from now
      };

      mockJwtService.verifyRefreshToken.mockReturnValue(mockPayload);
      mockJwtService.hashRefreshToken.mockReturnValue(tokenHash);
      mockJwtService.generateAccessToken.mockReturnValue(newAccessToken);
      mockJwtService.generateRefreshToken.mockReturnValue(newRefreshToken);

      mockDb.queryOne
        .mockResolvedValueOnce(mockStoredToken) // Token lookup
        .mockResolvedValueOnce(mockUser) // User lookup
        .mockResolvedValueOnce({ id: 'new-token-id' }); // New token creation

      mockDb.query.mockResolvedValue({ rowCount: 1 } as any); // Invalidate old tokens

      // Act
      const result = await authService.refreshToken(oldRefreshToken);

      // Assert
      expect(result).toEqual({
        user: expect.objectContaining({
          id: mockData.validUserId,
          tenantId: mockData.validTenantId
        }),
        accessToken: newAccessToken,
        refreshToken: newRefreshToken,
        expiresIn: expect.any(Number)
      });

      expect(mockJwtService.verifyRefreshToken).toHaveBeenCalledWith(oldRefreshToken);
      expect(mockDb.query).toHaveBeenCalledWith(
        expect.stringContaining('UPDATE kam_refresh_tokens SET is_active = false'),
        [mockData.validUserId]
      );
    });

    it('should throw error with invalid refresh token', async () => {
      // Arrange
      const invalidToken = 'invalid.refresh.token';
      
      mockJwtService.verifyRefreshToken.mockImplementation(() => {
        throw new Error('Invalid token');
      });

      // Act & Assert
      await expect(authService.refreshToken(invalidToken))
        .rejects.toThrow('Invalid token');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Token refresh failed - invalid token',
        expect.any(Object)
      );
    });

    it('should throw error if stored token not found', async () => {
      // Arrange
      const refreshToken = 'valid.but.not.stored.token';
      const tokenHash = 'hashedToken';

      const mockPayload = {
        userId: mockData.validUserId,
        tokenType: 'refresh'
      };

      mockJwtService.verifyRefreshToken.mockReturnValue(mockPayload);
      mockJwtService.hashRefreshToken.mockReturnValue(tokenHash);
      mockDb.queryOne.mockResolvedValue(null); // Token not found in DB

      // Act & Assert
      await expect(authService.refreshToken(refreshToken))
        .rejects.toThrow('Invalid refresh token');

      expect(mockLogger.warn).toHaveBeenCalledWith(
        'Token refresh failed - token not found in database',
        expect.objectContaining({
          userId: mockData.validUserId
        })
      );
    });
  });

  describe('logout', () => {
    it('should logout user successfully', async () => {
      // Arrange
      const userId = mockData.validUserId;

      mockDb.query.mockResolvedValue({ rowCount: 2 } as any); // Invalidated 2 tokens

      // Act
      const result = await authService.logout(userId);

      // Assert
      expect(result).toBe(true);
      expect(mockDb.query).toHaveBeenCalledWith(
        'UPDATE kam_refresh_tokens SET is_active = false WHERE user_id = $1',
        [userId]
      );
      expect(mockLogger.info).toHaveBeenCalledWith(
        'User logout successful',
        { userId, tokensInvalidated: 2 }
      );
    });

    it('should handle logout gracefully even if no tokens found', async () => {
      // Arrange
      const userId = mockData.validUserId;

      mockDb.query.mockResolvedValue({ rowCount: 0 } as any); // No tokens to invalidate

      // Act
      const result = await authService.logout(userId);

      // Assert
      expect(result).toBe(true);
      expect(mockLogger.info).toHaveBeenCalledWith(
        'User logout successful',
        { userId, tokensInvalidated: 0 }
      );
    });

    it('should handle database errors during logout', async () => {
      // Arrange
      const userId = mockData.validUserId;

      mockDb.query.mockRejectedValue(new Error('Database error'));

      // Act & Assert
      await expect(authService.logout(userId))
        .rejects.toThrow('Logout failed');

      expect(mockLogger.error).toHaveBeenCalledWith(
        'Logout failed',
        expect.objectContaining({
          userId,
          error: 'Database error'
        })
      );
    });
  });

});