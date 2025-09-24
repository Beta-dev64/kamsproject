import { Response } from 'express';
import { AuthRequest, UserRole } from '../types';
import { tenantService, TenantSettings } from '../services/tenantService';
import { logger } from '../utils/logger';
import { ValidationError, NotFoundError, ConflictError, ForbiddenError } from '../middleware/errorHandler';
import {
  CreateTenantRequest,
  UpdateTenantRequest,
} from '../utils/validation';

/**
 * Tenant controller handling tenant management endpoints
 */
export class TenantController {
  /**
   * Get current tenant information
   */
  async getCurrentTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      const tenant = await tenantService.getTenantById(req.tenantId);
      
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }

      res.json({
        success: true,
        data: tenant,
      });

      logger.info('Current tenant retrieved', {
        tenantId: req.tenantId,
        userId: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving current tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        userId: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get tenant by ID (super admin only)
   */
  async getTenantById(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      // Only super admin can view other tenants
      if (req.user.role !== UserRole.SUPER_ADMIN) {
        throw new ForbiddenError('Only super admins can view tenant details');
      }

      const { tenantId } = req.params;
      
      const tenant = await tenantService.getTenantById(tenantId);
      
      if (!tenant) {
        throw new NotFoundError('Tenant not found');
      }

      res.json({
        success: true,
        data: tenant,
      });

      logger.info('Tenant retrieved by ID', {
        targetTenantId: tenantId,
        requesterId: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving tenant by ID', {
        error: error instanceof Error ? error.message : String(error),
        targetTenantId: req.params.tenantId,
        requesterId: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Create new tenant (super admin only)
   */
  async createTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user) {
        throw new ValidationError('User not authenticated');
      }

      // Only super admin can create tenants
      if (req.user.role !== UserRole.SUPER_ADMIN) {
        throw new ForbiddenError('Only super admins can create tenants');
      }

      const tenantData: CreateTenantRequest = req.body;

      const newTenant = await tenantService.createTenant(tenantData, req.user.id);

      res.status(201).json({
        success: true,
        message: 'Tenant created successfully',
        data: newTenant,
      });

      logger.info('Tenant created', {
        newTenantId: newTenant.id,
        domain: newTenant.domain,
        createdBy: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error creating tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantData: req.body,
        createdBy: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Update tenant (admin only)
   */
  async updateTenant(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      const { tenantId } = req.params;
      const updateData: UpdateTenantRequest = req.body;

      // Check permission: super admin can update any tenant, admin can only update own tenant
      if (req.user.role === UserRole.SUPER_ADMIN) {
        // Super admin can update any tenant
      } else if (req.user.role === UserRole.ADMIN && tenantId === req.tenantId) {
        // Admin can only update their own tenant
      } else {
        throw new ForbiddenError('You do not have permission to update this tenant');
      }

      const updatedTenant = await tenantService.updateTenant(
        tenantId,
        updateData,
        req.user.id
      );

      res.json({
        success: true,
        message: 'Tenant updated successfully',
        data: updatedTenant,
      });

      logger.info('Tenant updated', {
        tenantId,
        updatedBy: req.user.id,
        changes: updateData,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error updating tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.params.tenantId,
        updateData: req.body,
        updatedBy: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get tenant settings
   */
  async getTenantSettings(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      // Only admin and super admin can view tenant settings
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to view tenant settings');
      }

      const settings = await tenantService.getTenantSettings(req.tenantId);

      res.json({
        success: true,
        data: settings,
      });

      logger.info('Tenant settings retrieved', {
        tenantId: req.tenantId,
        userId: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving tenant settings', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        userId: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Update tenant settings
   */
  async updateTenantSettings(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      // Only admin and super admin can update tenant settings
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to update tenant settings');
      }

      const settings: Partial<TenantSettings> = req.body;

      const updatedSettings = await tenantService.updateTenantSettings(
        req.tenantId,
        settings,
        req.user.id
      );

      res.json({
        success: true,
        message: 'Tenant settings updated successfully',
        data: updatedSettings,
      });

      logger.info('Tenant settings updated', {
        tenantId: req.tenantId,
        updatedBy: req.user.id,
        changedFields: Object.keys(settings),
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error updating tenant settings', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        settings: req.body,
        updatedBy: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Send user invitation
   */
  async inviteUser(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      // Only admin and super admin can invite users
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to invite users');
      }

      const { email, role, customMessage } = req.body;

      // Validate role assignment permissions
      if (role === UserRole.SUPER_ADMIN) {
        throw new ForbiddenError('Cannot invite super admin users');
      }

      if (role === UserRole.ADMIN && req.user.role !== UserRole.SUPER_ADMIN) {
        throw new ForbiddenError('Only super admins can invite admin users');
      }

      const invitation = await tenantService.inviteUser(
        req.tenantId,
        email,
        role,
        req.user.id,
        customMessage
      );

      res.status(201).json({
        success: true,
        message: 'User invitation sent successfully',
        data: {
          id: invitation.id,
          email: invitation.email,
          role: invitation.role,
          expiresAt: invitation.expiresAt,
          createdAt: invitation.createdAt,
        },
      });

      logger.info('User invitation sent', {
        tenantId: req.tenantId,
        email,
        role,
        invitedBy: req.user.id,
        invitationId: invitation.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error sending user invitation', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        inviteData: req.body,
        invitedBy: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get tenant invitations
   */
  async getTenantInvitations(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      // Only admin and super admin can view invitations
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to view invitations');
      }

      const filters = req.query as any;
      
      // Convert string parameters to appropriate types
      const processedFilters = {
        ...filters,
        pending: filters.pending === 'true' ? true : filters.pending === 'false' ? false : undefined,
        page: filters.page ? parseInt(String(filters.page)) : undefined,
        limit: filters.limit ? parseInt(String(filters.limit)) : undefined,
      };

      const result = await tenantService.getTenantInvitations(req.tenantId, processedFilters);

      // Remove sensitive invitation tokens from response
      const sanitizedInvitations = result.invitations.map(invitation => {
        const { invitationToken, ...sanitizedInvitation } = invitation;
        return sanitizedInvitation;
      });

      res.json({
        success: true,
        data: {
          ...result,
          invitations: sanitizedInvitations,
        },
      });

      logger.info('Tenant invitations retrieved', {
        tenantId: req.tenantId,
        filters: processedFilters,
        resultCount: result.invitations.length,
        userId: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving tenant invitations', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        filters: req.query,
        userId: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Resend invitation
   */
  async resendInvitation(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      // Only admin and super admin can resend invitations
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to resend invitations');
      }

      const { invitationId } = req.params;

      // Get the existing invitation
      const invitations = await tenantService.getTenantInvitations(req.tenantId, {
        page: 1,
        limit: 1000, // High limit to search through all invitations
      });

      const invitation = invitations.invitations.find(inv => inv.id === invitationId);
      
      if (!invitation) {
        throw new NotFoundError('Invitation not found');
      }

      if (invitation.acceptedAt) {
        throw new ValidationError('Invitation has already been accepted');
      }

      // Create a new invitation (this will replace the old one)
      const newInvitation = await tenantService.inviteUser(
        req.tenantId,
        invitation.email,
        invitation.role,
        req.user.id
      );

      res.json({
        success: true,
        message: 'Invitation resent successfully',
        data: {
          id: newInvitation.id,
          email: newInvitation.email,
          role: newInvitation.role,
          expiresAt: newInvitation.expiresAt,
          createdAt: newInvitation.createdAt,
        },
      });

      logger.info('Invitation resent', {
        tenantId: req.tenantId,
        originalInvitationId: invitationId,
        newInvitationId: newInvitation.id,
        email: invitation.email,
        resentBy: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error resending invitation', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        invitationId: req.params.invitationId,
        resentBy: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Cancel invitation
   */
  async cancelInvitation(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      // Only admin and super admin can cancel invitations
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to cancel invitations');
      }

      const { invitationId } = req.params;

      // For now, we'll implement cancellation by setting expiry to past
      // In a real implementation, you might add a 'cancelled' status
      const query = `
        UPDATE tenant_invitations 
        SET expires_at = CURRENT_TIMESTAMP - INTERVAL '1 day'
        WHERE id = $1 AND tenant_id = $2 AND accepted_at IS NULL
      `;

      // Use the database module directly
      const { db } = await import('../database');
      const result = await db.query(query, [invitationId, req.tenantId]);

      if (result.rowCount === 0) {
        throw new NotFoundError('Invitation not found or already processed');
      }

      res.json({
        success: true,
        message: 'Invitation cancelled successfully',
      });

      logger.info('Invitation cancelled', {
        tenantId: req.tenantId,
        invitationId,
        cancelledBy: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error cancelling invitation', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        invitationId: req.params.invitationId,
        cancelledBy: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }

  /**
   * Get tenant statistics (admin only)
   */
  async getTenantStats(req: AuthRequest, res: Response): Promise<void> {
    try {
      if (!req.user || !req.tenantId) {
        throw new ValidationError('User or tenant context not found');
      }

      // Only admin and super admin can view tenant stats
      if (![UserRole.SUPER_ADMIN, UserRole.ADMIN].includes(req.user.role)) {
        throw new ForbiddenError('You do not have permission to view tenant statistics');
      }

      // TODO: Implement comprehensive tenant statistics
      const stats = {
        users: {
          total: 0,
          active: 0,
          inactive: 0,
          byRole: {},
        },
        invitations: {
          pending: 0,
          accepted: 0,
          expired: 0,
        },
        assessments: {
          total: 0,
          completed: 0,
          inProgress: 0,
        },
      };

      res.json({
        success: true,
        data: stats,
      });

      logger.info('Tenant statistics retrieved', {
        tenantId: req.tenantId,
        userId: req.user.id,
        requestId: req.requestId,
      });
    } catch (error) {
      logger.error('Error retrieving tenant statistics', {
        error: error instanceof Error ? error.message : String(error),
        tenantId: req.tenantId,
        userId: req.user?.id,
        requestId: req.requestId,
      });
      throw error;
    }
  }
}

// Export singleton instance
export const tenantController = new TenantController();