import { Response } from 'express';
import { AuthRequest, UserRole } from '../types';
import { systemAdminService } from '../services/systemAdminService';
import { tenantService } from '../services/tenantService';
import { userService } from '../services/userService';
import { logger } from '../utils/logger';
import { ValidationError, NotFoundError, ConflictError, ForbiddenError } from '../middleware/errorHandler';
import { db } from '../database';

/**
 * System Admin Controller - Handles system-wide administration
 * Only accessible by SUPER_ADMIN role users
 */
export class SystemAdminController {
  
  /**
   * Get system-wide dashboard statistics
   */
  async getSystemDashboard(req: AuthRequest, res: Response): Promise<void> {
    try {
      const stats = await systemAdminService.getSystemDashboard();
      
      res.json({
        success: true,
        data: stats
      });

      logger.info('System dashboard retrieved', {
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving system dashboard', {
        error: error instanceof Error ? error.message : String(error),
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get detailed system health status
   */
  async getSystemHealth(req: AuthRequest, res: Response): Promise<void> {
    try {
      const health = await systemAdminService.getSystemHealth();
      
      res.json({
        success: true,
        data: health
      });

      logger.info('System health retrieved', {
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving system health', {
        error: error instanceof Error ? error.message : String(error),
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get all tenants with pagination and filtering
   */
  async getAllTenants(req: AuthRequest, res: Response): Promise<void> {
    try {
      const {
        page = 1,
        limit = 20,
        search,
        status = 'all',
        subscriptionTier,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query as any;

      const filters = {
        search,
        status: status !== 'all' ? status : undefined,
        subscriptionTier,
        sortBy,
        sortOrder
      };

      const result = await systemAdminService.getAllTenants(
        page,
        limit,
        filters
      );

      res.json({
        success: true,
        data: result.tenants,
        pagination: {
          page,
          limit,
          total: result.total,
          pages: Math.ceil(result.total / limit)
        },
        summary: result.summary
      });

      logger.info('All tenants retrieved', {
        page,
        limit,
        totalTenants: result.total,
        filters,
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving all tenants', {
        error: error instanceof Error ? error.message : String(error),
        filters: req.query,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Create new tenant
   */
  async createTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const tenantData = req.body;
      const newTenant = await tenantService.createTenant(tenantData, req.user.id);

      res.status(201).json({
        success: true,
        message: 'Tenant created successfully',
        data: newTenant
      });

      logger.info('Tenant created by system admin', {
        tenantId: newTenant.id,
        domain: newTenant.domain,
        createdBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error creating tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantData: req.body,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get specific tenant details with enhanced information
   */
  async getTenantDetails(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { tenantId } = req.params;
      
      const tenantDetails = await systemAdminService.getTenantDetails(tenantId);
      
      if (!tenantDetails) {
        throw new NotFoundError('Tenant not found');
      }

      res.json({
        success: true,
        data: tenantDetails
      });

      logger.info('Tenant details retrieved', {
        tenantId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving tenant details', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.params.tenantId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Update tenant
   */
  async updateTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { tenantId } = req.params;
      const updateData = req.body;

      const updatedTenant = await tenantService.updateTenant(
        tenantId,
        updateData,
        req.user.id
      );

      res.json({
        success: true,
        message: 'Tenant updated successfully',
        data: updatedTenant
      });

      logger.info('Tenant updated by system admin', {
        tenantId,
        changes: updateData,
        updatedBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error updating tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.params.tenantId,
        updateData: req.body,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Delete/deactivate tenant (soft delete)
   */
  async deleteTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { tenantId } = req.params;
      
      await systemAdminService.deleteTenant(tenantId, req.user.id);

      res.json({
        success: true,
        message: 'Tenant deleted successfully'
      });

      logger.warn('Tenant deleted by system admin', {
        tenantId,
        deletedBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error deleting tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.params.tenantId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Activate tenant
   */
  async activateTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { tenantId } = req.params;
      
      await systemAdminService.updateTenantStatus(tenantId, true, req.user.id);

      res.json({
        success: true,
        message: 'Tenant activated successfully'
      });

      logger.info('Tenant activated', {
        tenantId,
        activatedBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error activating tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.params.tenantId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Deactivate tenant
   */
  async deactivateTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { tenantId } = req.params;
      
      await systemAdminService.updateTenantStatus(tenantId, false, req.user.id);

      res.json({
        success: true,
        message: 'Tenant deactivated successfully'
      });

      logger.warn('Tenant deactivated', {
        tenantId,
        deactivatedBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error deactivating tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.params.tenantId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get all users across all tenants
   */
  async getAllUsers(req: AuthRequest, res: Response): Promise<void> {
    try {
      const {
        page = 1,
        limit = 20,
        tenantId,
        role,
        isActive,
        search,
        sortBy = 'createdAt',
        sortOrder = 'desc'
      } = req.query as any;

      const filters = {
        tenantId,
        role,
        isActive: isActive ? isActive === 'true' : undefined,
        search,
        sortBy,
        sortOrder
      };

      const result = await systemAdminService.getAllUsers(
        page,
        limit,
        filters
      );

      res.json({
        success: true,
        data: result.users,
        pagination: {
          page,
          limit,
          total: result.total,
          pages: Math.ceil(result.total / limit)
        },
        summary: result.summary
      });

      logger.info('All users retrieved', {
        page,
        limit,
        totalUsers: result.total,
        filters,
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving all users', {
        error: error instanceof Error ? error.message : String(error),
        filters: req.query,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get specific user details (cross-tenant)
   */
  async getUserDetails(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { userId } = req.params;
      
      const userDetails = await systemAdminService.getUserDetails(userId);
      
      if (!userDetails) {
        throw new NotFoundError('User not found');
      }

      res.json({
        success: true,
        data: userDetails
      });

      logger.info('User details retrieved', {
        userId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving user details', {
        error: error instanceof Error ? error.message : String(error),
        userId: req.params.userId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Update user (cross-tenant)
   */
  async updateUser(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { userId } = req.params;
      const updateData = req.body;

      const updatedUser = await systemAdminService.updateUser(
        userId,
        updateData,
        req.user.id
      );

      res.json({
        success: true,
        message: 'User updated successfully',
        data: updatedUser
      });

      logger.info('User updated by system admin', {
        userId,
        changes: updateData,
        updatedBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error updating user', {
        error: error instanceof Error ? error.message : String(error),
        userId: req.params.userId,
        updateData: req.body,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Reset user password
   */
  async resetUserPassword(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { userId } = req.params;
      
      const newPassword = await systemAdminService.resetUserPassword(userId, req.user.id);

      res.json({
        success: true,
        message: 'Password reset successfully',
        data: {
          temporaryPassword: newPassword,
          mustChangePassword: true
        }
      });

      logger.warn('User password reset by system admin', {
        userId,
        resetBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error resetting user password', {
        error: error instanceof Error ? error.message : String(error),
        userId: req.params.userId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get system-wide analytics
   */
  async getSystemAnalytics(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { startDate, endDate, tenantId } = req.query as any;
      
      const analytics = await systemAdminService.getSystemAnalytics({
        startDate: startDate ? new Date(startDate) : undefined,
        endDate: endDate ? new Date(endDate) : undefined,
        tenantId
      });

      res.json({
        success: true,
        data: analytics
      });

      logger.info('System analytics retrieved', {
        filters: { startDate, endDate, tenantId },
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving system analytics', {
        error: error instanceof Error ? error.message : String(error),
        filters: req.query,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get tenant usage analytics
   */
  async getTenantAnalytics(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { startDate, endDate, tenantId } = req.query as any;
      
      const analytics = await systemAdminService.getTenantAnalytics({
        startDate: startDate ? new Date(startDate) : undefined,
        endDate: endDate ? new Date(endDate) : undefined,
        tenantId
      });

      res.json({
        success: true,
        data: analytics
      });

      logger.info('Tenant analytics retrieved', {
        filters: { startDate, endDate, tenantId },
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving tenant analytics', {
        error: error instanceof Error ? error.message : String(error),
        filters: req.query,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Run system cleanup tasks
   */
  async runSystemCleanup(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const result = await systemAdminService.runSystemCleanup(req.user.id);

      res.json({
        success: true,
        message: 'System cleanup completed',
        data: result
      });

      logger.info('System cleanup completed', {
        result,
        initiatedBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error running system cleanup', {
        error: error instanceof Error ? error.message : String(error),
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Get system logs
   */
  async getSystemLogs(req: AuthRequest, res: Response): Promise<void> {
    try {
      const {
        level,
        service,
        startDate,
        endDate,
        page = 1,
        limit = 50
      } = req.query as any;

      const filters = {
        level,
        service,
        startDate: startDate ? new Date(startDate) : undefined,
        endDate: endDate ? new Date(endDate) : undefined
      };

      const result = await systemAdminService.getSystemLogs(
        page,
        limit,
        filters
      );

      res.json({
        success: true,
        data: result.logs,
        pagination: {
          page,
          limit,
          total: result.total,
          pages: Math.ceil(result.total / limit)
        }
      });

      logger.info('System logs retrieved', {
        page,
        limit,
        totalLogs: result.total,
        filters,
        adminId: req.user?.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error retrieving system logs', {
        error: error instanceof Error ? error.message : String(error),
        filters: req.query,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }

  /**
   * Generate token to impersonate user (for support/debugging)
   */
  async impersonateUser(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      const { userId } = req.params;
      
      const impersonationToken = await systemAdminService.createImpersonationToken(
        userId,
        req.user.id
      );

      res.json({
        success: true,
        message: 'Impersonation token generated',
        data: {
          impersonationToken,
          expiresIn: 3600, // 1 hour
          warning: 'This token allows full access as the target user. Use responsibly.'
        }
      });

      logger.warn('User impersonation token generated', {
        targetUserId: userId,
        impersonatedBy: req.user.id,
        requestId: req.requestId
      });
    } catch (error) {
      logger.error('Error generating impersonation token', {
        error: error instanceof Error ? error.message : String(error),
        targetUserId: req.params.userId,
        adminId: req.user?.id,
        requestId: req.requestId
      });
      throw error;
    }
  }
}