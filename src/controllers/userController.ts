import { Response } from 'express';
import { AuthRequest, UserRole } from '../types';
import { userService } from '../services/userService';
import { logger } from '../utils/logger';
import { ValidationError, NotFoundError, ConflictError, ForbiddenError } from '../middleware/errorHandler';
import {
  CreateUserRequest,
  UpdateUserRequest,
  UserFilterRequest,
} from '../utils/validation';

/**
 * User controller handling user management endpoints
 */
export class UserController {
  /**
   * Get current user profile
   */
  async getProfile(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const user = await userService.getUserById(req.user.id, req.tenantId!);
      
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Remove sensitive data
      const { passwordHash, ...userProfile } = user as any;

      res.json({
        success: true,
        data: userProfile,
      });

      logger.info('User profile retrieved', {
        userId: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving user profile', {
        error: error instanceof Error ? error.message : String(error),
        userId: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Update current user profile
   */
  async updateProfile(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const profileData = req.body;
      
      const updatedUser = await userService.updateProfile(
        req.user.id,
        profileData,
        req.tenantId!
      );

      // Remove sensitive data
      const { passwordHash, ...userProfile } = updatedUser as any;

      res.json({
        success: true,
        message: 'Profile updated successfully',
        data: userProfile,
      });

      logger.info('User profile updated', {
        userId: req.user.id,
        tenantId: req.tenantId,
        changes: profileData,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error updating user profile', {
        error: error instanceof Error ? error.message : String(error),
        userId: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get user by ID (admin/manager only)
   */
  async getUserById(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { userId } = req.params;
      
      // Check if user can view this user
      const canManage = await userService.canManageUser(req.user.id, userId, req.tenantId!);
      if (!canManage) {
        throw new ForbiddenError('You do not have permission to view this user');
      }

      const user = await userService.getUserById(userId, req.tenantId!);
      
      if (!user) {
        throw new NotFoundError('User not found');
      }

      // Remove sensitive data
      const { passwordHash, ...userProfile } = user as any;

      res.json({
        success: true,
        data: userProfile,
      });

      logger.info('User retrieved by ID', {
        targetUserId: userId,
        requesterId: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving user by ID', {
        error: error instanceof Error ? error.message : String(error),
        targetUserId: req.params.userId,
        requesterId: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get users with filtering and pagination
   */
  async getUsers(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      // Only allow admin and manager roles to list users
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to view users');
      }

      const filters = req.query as any;
      
      // Convert string pagination params to numbers
      const processedFilters = {
        ...filters,
        page: filters.page ? parseInt(String(filters.page)) : undefined,
        limit: filters.limit ? parseInt(String(filters.limit)) : undefined,
        sortOrder: (filters.order?.toUpperCase() as 'ASC' | 'DESC') || 'DESC',
      };

      const result = await userService.getUsers(req.tenantId!, processedFilters);

      // Remove sensitive data from all users
      const sanitizedUsers = result.users.map(user => {
        const { passwordHash, ...userProfile } = user as any;
        return userProfile;
      });

      res.json({
        success: true,
        data: {
          ...result,
          users: sanitizedUsers,
        },
      });

      logger.info('Users retrieved with filters', {
        filters: processedFilters,
        resultCount: result.users.length,
        requesterId: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving users', {
        error: error instanceof Error ? error.message : String(error),
        filters: req.query,
        requesterId: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Create a new user (admin only)
   */
  async createUser(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      // Only allow admin roles to create users
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to create users');
      }

      const userData: CreateUserRequest = req.body;

      // Validate role assignment permissions
      if (userData.role === UserRole.SUPER_ADMIN && req.user.role !== UserRole.SUPER_ADMIN) {
        throw new ForbiddenError('Only super admins can create super admin users');
      }

      if (userData.role === UserRole.ADMIN && req.user.role !== UserRole.SUPER_ADMIN) {
        throw new ForbiddenError('Only super admins can create admin users');
      }

      const newUser = await userService.createUser(userData, req.tenantId!, req.user.id);

      // Remove sensitive data
      const { passwordHash, ...userProfile } = newUser as any;

      res.status(201).json({
        success: true,
        message: 'User created successfully',
        data: userProfile,
      });

      logger.info('User created', {
        newUserId: newUser.id,
        email: newUser.email,
        role: newUser.role,
        createdBy: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error creating user', {
        error: error instanceof Error ? error.message : String(error),
        userData: req.body,
        createdBy: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Update user (admin/manager only)
   */
  async updateUser(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { userId } = req.params;
      const updateData: UpdateUserRequest = req.body;

      // Check if user can manage this user
      const canManage = await userService.canManageUser(req.user.id, userId, req.tenantId!);
      if (!canManage) {
        throw new ForbiddenError('You do not have permission to update this user');
      }

      // Additional role change validation
      if (updateData.role) {
        const targetUser = await userService.getUserById(userId, req.tenantId!);
        if (!targetUser) {
          throw new NotFoundError('User not found');
        }

        // Prevent role escalation
        if (updateData.role === UserRole.SUPER_ADMIN && req.user.role !== UserRole.SUPER_ADMIN) {
          throw new ForbiddenError('Only super admins can assign super admin role');
        }

        if (updateData.role === UserRole.ADMIN && req.user.role !== UserRole.SUPER_ADMIN) {
          throw new ForbiddenError('Only super admins can assign admin role');
        }

        // Prevent demoting super admin by non-super admin
        if (targetUser.role === UserRole.SUPER_ADMIN && req.user.role !== UserRole.SUPER_ADMIN) {
          throw new ForbiddenError('Only super admins can modify super admin users');
        }
      }

      const updatedUser = await userService.updateUser(
        userId,
        updateData,
        req.tenantId!,
        req.user.id
      );

      // Remove sensitive data
      const { passwordHash, ...userProfile } = updatedUser as any;

      res.json({
        success: true,
        message: 'User updated successfully',
        data: userProfile,
      });

      logger.info('User updated', {
        targetUserId: userId,
        updatedBy: req.user.id,
        changes: updateData,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error updating user', {
        error: error instanceof Error ? error.message : String(error),
        targetUserId: req.params.userId,
        updateData: req.body,
        updatedBy: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Delete user (admin only)
   */
  async deleteUser(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { userId } = req.params;

      // Only allow admin roles to delete users
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to delete users');
      }

      // Additional validation for super admin deletion
      const targetUser = await userService.getUserById(userId, req.tenantId!);
      if (!targetUser) {
        throw new NotFoundError('User not found');
      }

      if (targetUser.role === UserRole.SUPER_ADMIN && req.user.role !== UserRole.SUPER_ADMIN) {
        throw new ForbiddenError('Only super admins can delete super admin users');
      }

      await userService.deleteUser(userId, req.tenantId!, req.user.id);

      res.json({
        success: true,
        message: 'User deleted successfully',
      });

      logger.info('User deleted', {
        targetUserId: userId,
        deletedBy: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error deleting user', {
        error: error instanceof Error ? error.message : String(error),
        targetUserId: req.params.userId,
        deletedBy: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get users by role (manager/admin only)
   */
  async getUsersByRole(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      // Only allow admin and manager roles
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to view users by role');
      }

      const { role } = req.params;
      
      // Validate role parameter
      if (!Object.values(UserRole).includes(role as UserRole)) {
        throw new ValidationError('Invalid role specified');
      }

      const users = await userService.getUsersByRole(role as UserRole, req.tenantId!);

      // Remove sensitive data from all users
      const sanitizedUsers = users.map(user => {
        const { passwordHash, ...userProfile } = user as any;
        return userProfile;
      });

      res.json({
        success: true,
        data: sanitizedUsers,
      });

      logger.info('Users retrieved by role', {
        role,
        userCount: users.length,
        requesterId: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving users by role', {
        error: error instanceof Error ? error.message : String(error),
        role: req.params.role,
        requesterId: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get user's direct reports (manager only)
   */
  async getDirectReports(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      // Only allow manager and admin roles
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to view direct reports');
      }

      const managerId = req.params.managerId || req.user.id;
      
      // Non-admin users can only view their own direct reports
      if (managerId !== req.user.id && req.user.role === UserRole.MANAGER) {
        throw new ForbiddenError('You can only view your own direct reports');
      }

      const result = await userService.getUsers(req.tenantId!, {
        managerId,
        isActive: true,
      });

      // Remove sensitive data from all users
      const sanitizedUsers = result.users.map(user => {
        const { passwordHash, ...userProfile } = user as any;
        return userProfile;
      });

      res.json({
        success: true,
        data: sanitizedUsers,
      });

      logger.info('Direct reports retrieved', {
        managerId,
        userCount: result.users.length,
        requesterId: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving direct reports', {
        error: error instanceof Error ? error.message : String(error),
        managerId: req.params.managerId,
        requesterId: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get department users (manager/admin only)
   */
  async getDepartmentUsers(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      // Only allow manager and admin roles
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN, UserRole.MANAGER].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to view department users');
      }

      const { department } = req.params;
      
      // Managers can only view their own department unless they're admin
      if (req.user.role === UserRole.MANAGER && req.user.department !== department) {
        throw new ForbiddenError('You can only view users in your own department');
      }

      const result = await userService.getUsers(req.tenantId!, {
        department,
        isActive: true,
      });

      // Remove sensitive data from all users
      const sanitizedUsers = result.users.map(user => {
        const { passwordHash, ...userProfile } = user as any;
        return userProfile;
      });

      res.json({
        success: true,
        data: sanitizedUsers,
      });

      logger.info('Department users retrieved', {
        department,
        userCount: result.users.length,
        requesterId: req.user.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving department users', {
        error: error instanceof Error ? error.message : String(error),
        department: req.params.department,
        requesterId: req.user?.id,
        tenantId: req.tenantId,
        requestId: req.requestId,
      });
      throw error;
    }
  }
}

// Export singleton instance
export const userController = new UserController();