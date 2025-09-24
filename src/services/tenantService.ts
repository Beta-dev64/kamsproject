import { PoolClient } from 'pg';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { Tenant, UserRole } from '../types';
import { CreateTenantRequest, UpdateTenantRequest } from '../utils/validation';
import { logger } from '../utils/logger';
import { DatabaseError, ValidationError, NotFoundError, ConflictError } from '../middleware/errorHandler';
import { db, dbHelpers, executeInTransaction } from '../database';
import { jwtService } from '../utils/jwt';

export interface TenantSettings {
  classificationThresholds: {
    championMinTotal: number;
    championMinSelf: number;
    activistMinTotal: number;
    goGetterMinSelf: number;
  };
  classificationLabels: {
    champion: string;
    activist: string;
    paperTiger: string;
    goGetter: string;
  };
  assessmentSettings: {
    allowSelfAssessment: boolean;
    requireManagerApproval: boolean;
    maxAssessmentsPerQuarter: number;
    notificationEnabled: boolean;
  };
  emailSettings: {
    assessmentReminders: boolean;
    completionNotifications: boolean;
    weeklyReports: boolean;
  };
  customization: {
    primaryColor: string;
    logoUrl?: string;
    companyName: string;
  };
}

export interface TenantInvitation {
  id: string;
  tenantId: string;
  email: string;
  role: UserRole;
  invitedBy: string;
  invitationToken: string;
  expiresAt: Date;
  acceptedAt?: Date;
  createdAt: Date;
}

/**
 * Tenant service for managing tenant operations
 */
export class TenantService {
  /**
   * Get tenant by ID
   */
  async getTenantById(tenantId: string): Promise<Tenant | null> {
    try {
      const query = `
        SELECT 
          t.*,
          ts.settings,
          (SELECT COUNT(*) FROM users WHERE tenant_id = t.id AND deleted_at IS NULL) as current_user_count
        FROM tenants t
        LEFT JOIN tenant_settings ts ON t.id = ts.tenant_id
        WHERE t.id = $1 AND t.deleted_at IS NULL
      `;
      
      const result = await db.queryOne<any>(query, [tenantId]);
      
      if (!result) {
        return null;
      }

      return this.mapRowToTenant(result);
    } catch (error) {
      logger.error('Error fetching tenant by ID', {
        error: error instanceof Error ? error.message : String(error),
        tenantId,
      });
      throw new DatabaseError('Failed to fetch tenant');
    }
  }

  /**
   * Get tenant by domain
   */
  async getTenantByDomain(domain: string): Promise<Tenant | null> {
    try {
      const query = `
        SELECT 
          t.*,
          ts.settings,
          (SELECT COUNT(*) FROM users WHERE tenant_id = t.id AND deleted_at IS NULL) as current_user_count
        FROM tenants t
        LEFT JOIN tenant_settings ts ON t.id = ts.tenant_id
        WHERE t.domain = $1 AND t.deleted_at IS NULL
      `;
      
      const result = await db.queryOne<any>(query, [domain.toLowerCase()]);
      
      if (!result) {
        return null;
      }

      return this.mapRowToTenant(result);
    } catch (error) {
      logger.error('Error fetching tenant by domain', {
        error: error instanceof Error ? error.message : String(error),
        domain,
      });
      throw new DatabaseError('Failed to fetch tenant');
    }
  }

  /**
   * Create a new tenant
   */
  async createTenant(tenantData: CreateTenantRequest, createdById?: string): Promise<Tenant> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Check if domain already exists
        const existingTenant = await this.getTenantByDomain(tenantData.domain);
        if (existingTenant) {
          throw new ConflictError('Domain already exists');
        }

        const tenantId = uuidv4();
        const adminUserId = uuidv4();

        // Create tenant record
        const tenantQuery = `
          INSERT INTO tenants (
            id, name, domain, subscription_tier, max_users, is_active
          ) VALUES ($1, $2, $3, $4, $5, $6)
          RETURNING *
        `;
        
        const tenantResult = await client.query(tenantQuery, [
          tenantId,
          tenantData.name,
          tenantData.domain.toLowerCase(),
          tenantData.subscriptionTier || 'basic',
          tenantData.maxUsers || 100,
          true,
        ]);

        // Create default tenant settings
        await this.createDefaultSettings(client, tenantId);

        // Create admin user
        const hashedPassword = await bcrypt.hash(tenantData.adminUser.password, 12);
        
        const userQuery = `
          INSERT INTO users (
            id, tenant_id, email, password_hash, role, 
            is_active, email_verified, created_by
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING *
        `;
        
        await client.query(userQuery, [
          adminUserId,
          tenantId,
          tenantData.adminUser.email.toLowerCase(),
          hashedPassword,
          UserRole.ADMIN,
          true,
          true, // Admin users are pre-verified
          createdById || adminUserId, // Self-created if no creator
        ]);

        // Create admin user profile
        const profileQuery = `
          INSERT INTO user_profiles (
            user_id, first_name, last_name
          ) VALUES ($1, $2, $3)
        `;
        
        await client.query(profileQuery, [
          adminUserId,
          tenantData.adminUser.firstName,
          tenantData.adminUser.lastName,
        ]);

        // Log tenant creation
        await this.logTenantActivity(client, tenantId, 'tenant_created', {
          createdBy: createdById,
          domain: tenantData.domain,
          adminUserId,
        });

        logger.info('Tenant created successfully', {
          tenantId,
          domain: tenantData.domain,
          adminUserId,
          createdBy: createdById,
        });

        // Return the created tenant
        const tenant = await this.getTenantById(tenantId);
        return tenant!;
      } catch (error) {
        if (error instanceof ConflictError) {
          throw error;
        }
        
        logger.error('Error creating tenant', {
          error: error instanceof Error ? error.message : String(error),
          tenantData: { ...tenantData, adminUser: { ...tenantData.adminUser, password: '[REDACTED]' } },
        });
        throw new DatabaseError('Failed to create tenant');
      }
    });
  }

  /**
   * Update tenant information
   */
  async updateTenant(
    tenantId: string,
    updateData: UpdateTenantRequest,
    updatedById?: string
  ): Promise<Tenant> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Check if tenant exists
        const existingTenant = await this.getTenantById(tenantId);
        if (!existingTenant) {
          throw new NotFoundError('Tenant not found');
        }

        const updates: string[] = [];
        const values: any[] = [];
        let paramCount = 1;

        if (updateData.name !== undefined) {
          updates.push(`name = $${paramCount++}`);
          values.push(updateData.name);
        }
        
        if (updateData.subscriptionTier !== undefined) {
          updates.push(`subscription_tier = $${paramCount++}`);
          values.push(updateData.subscriptionTier);
        }
        
        if (updateData.maxUsers !== undefined) {
          updates.push(`max_users = $${paramCount++}`);
          values.push(updateData.maxUsers);
        }
        
        if (updateData.isActive !== undefined) {
          updates.push(`is_active = $${paramCount++}`);
          values.push(updateData.isActive);
        }

        if (updates.length > 0) {
          updates.push(`updated_at = CURRENT_TIMESTAMP`);
          const query = `
            UPDATE tenants 
            SET ${updates.join(', ')} 
            WHERE id = $${paramCount++}
          `;
          
          await client.query(query, [...values, tenantId]);
        }

        // Log tenant update
        await this.logTenantActivity(client, tenantId, 'tenant_updated', {
          updatedBy: updatedById,
          changes: updateData,
        });

        logger.info('Tenant updated successfully', {
          tenantId,
          updatedBy: updatedById,
          changes: updateData,
        });

        // Return updated tenant
        const updatedTenant = await this.getTenantById(tenantId);
        return updatedTenant!;
      } catch (error) {
        if (error instanceof NotFoundError) {
          throw error;
        }
        
        logger.error('Error updating tenant', {
          error: error instanceof Error ? error.message : String(error),
          tenantId,
          updateData,
        });
        throw new DatabaseError('Failed to update tenant');
      }
    });
  }

  /**
   * Get tenant settings
   */
  async getTenantSettings(tenantId: string): Promise<TenantSettings> {
    try {
      const query = `
        SELECT settings FROM tenant_settings WHERE tenant_id = $1
      `;
      
      const result = await db.queryOne<{ settings: any }>(query, [tenantId]);
      
      if (!result || !result.settings) {
        // Return default settings if none exist
        return this.getDefaultSettings();
      }

      return result.settings as TenantSettings;
    } catch (error) {
      logger.error('Error fetching tenant settings', {
        error: error instanceof Error ? error.message : String(error),
        tenantId,
      });
      throw new DatabaseError('Failed to fetch tenant settings');
    }
  }

  /**
   * Update tenant settings
   */
  async updateTenantSettings(
    tenantId: string,
    settings: Partial<TenantSettings>,
    updatedById?: string
  ): Promise<TenantSettings> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Get current settings
        const currentSettings = await this.getTenantSettings(tenantId);
        
        // Merge with new settings
        const updatedSettings = this.mergeSettings(currentSettings, settings);

        // Update or insert settings
        const upsertQuery = `
          INSERT INTO tenant_settings (tenant_id, settings, updated_at)
          VALUES ($1, $2, CURRENT_TIMESTAMP)
          ON CONFLICT (tenant_id)
          DO UPDATE SET 
            settings = $2,
            updated_at = CURRENT_TIMESTAMP
        `;
        
        await client.query(upsertQuery, [tenantId, JSON.stringify(updatedSettings)]);

        // Log settings update
        await this.logTenantActivity(client, tenantId, 'settings_updated', {
          updatedBy: updatedById,
          changes: settings,
        });

        logger.info('Tenant settings updated successfully', {
          tenantId,
          updatedBy: updatedById,
          changedFields: Object.keys(settings),
        });

        return updatedSettings;
      } catch (error) {
        logger.error('Error updating tenant settings', {
          error: error instanceof Error ? error.message : String(error),
          tenantId,
          settings,
        });
        throw new DatabaseError('Failed to update tenant settings');
      }
    });
  }

  /**
   * Send user invitation
   */
  async inviteUser(
    tenantId: string,
    email: string,
    role: UserRole,
    invitedById: string,
    customMessage?: string
  ): Promise<TenantInvitation> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Check if tenant exists and has capacity
        const tenant = await this.getTenantById(tenantId);
        if (!tenant) {
          throw new NotFoundError('Tenant not found');
        }

        const currentUserCount = await this.getCurrentUserCount(tenantId);
        if (currentUserCount >= tenant.maxUsers) {
          throw new ValidationError(`User limit reached. Maximum ${tenant.maxUsers} users allowed.`);
        }

        // Check if user already exists
        const existingUser = await db.queryOne(`
          SELECT id FROM users 
          WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL
        `, [email.toLowerCase(), tenantId]);

        if (existingUser) {
          throw new ConflictError('User with this email already exists in this tenant');
        }

        // Check if there's already a pending invitation
        const existingInvite = await db.queryOne(`
          SELECT id FROM tenant_invitations 
          WHERE email = $1 AND tenant_id = $2 AND accepted_at IS NULL AND expires_at > NOW()
        `, [email.toLowerCase(), tenantId]);

        if (existingInvite) {
          throw new ConflictError('Pending invitation already exists for this email');
        }

        // Generate invitation token
        const invitationToken = jwtService.generateSecureToken(32);
        const invitationId = uuidv4();
        const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 days

        // Create invitation record
        const inviteQuery = `
          INSERT INTO tenant_invitations (
            id, tenant_id, email, role, invited_by, invitation_token, expires_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7)
          RETURNING *
        `;
        
        const inviteResult = await client.query(inviteQuery, [
          invitationId,
          tenantId,
          email.toLowerCase(),
          role,
          invitedById,
          invitationToken,
          expiresAt,
        ]);

        // Log invitation
        await this.logTenantActivity(client, tenantId, 'user_invited', {
          invitedBy: invitedById,
          email: email,
          role: role,
          invitationId,
        });

        logger.info('User invitation created', {
          tenantId,
          email,
          role,
          invitedBy: invitedById,
          invitationId,
        });

        // TODO: Send invitation email
        
        return {
          id: inviteResult.rows[0].id,
          tenantId: inviteResult.rows[0].tenant_id,
          email: inviteResult.rows[0].email,
          role: inviteResult.rows[0].role,
          invitedBy: inviteResult.rows[0].invited_by,
          invitationToken: inviteResult.rows[0].invitation_token,
          expiresAt: new Date(inviteResult.rows[0].expires_at),
          createdAt: new Date(inviteResult.rows[0].created_at),
        };
      } catch (error) {
        if (error instanceof NotFoundError || error instanceof ConflictError || error instanceof ValidationError) {
          throw error;
        }
        
        logger.error('Error creating user invitation', {
          error: error instanceof Error ? error.message : String(error),
          tenantId,
          email,
          role,
          invitedById,
        });
        throw new DatabaseError('Failed to create user invitation');
      }
    });
  }

  /**
   * Get tenant invitations
   */
  async getTenantInvitations(
    tenantId: string,
    filters: {
      pending?: boolean;
      email?: string;
      role?: UserRole;
      page?: number;
      limit?: number;
    } = {}
  ): Promise<{
    invitations: TenantInvitation[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    try {
      const {
        pending,
        email,
        role,
        page = 1,
        limit = 20,
      } = filters;

      let whereConditions = ['ti.tenant_id = $1'];
      let values: any[] = [tenantId];
      let paramCount = 2;

      if (pending !== undefined) {
        if (pending) {
          whereConditions.push('ti.accepted_at IS NULL AND ti.expires_at > NOW()');
        } else {
          whereConditions.push('(ti.accepted_at IS NOT NULL OR ti.expires_at <= NOW())');
        }
      }
      
      if (email) {
        whereConditions.push(`ti.email ILIKE $${paramCount++}`);
        values.push(`%${email}%`);
      }
      
      if (role) {
        whereConditions.push(`ti.role = $${paramCount++}`);
        values.push(role);
      }

      // Get total count
      const countQuery = `
        SELECT COUNT(*) as total
        FROM tenant_invitations ti
        WHERE ${whereConditions.join(' AND ')}
      `;
      
      const countResult = await db.queryOne<{ total: string }>(countQuery, values);
      const total = parseInt(countResult?.total || '0');

      // Get paginated results
      const offset = (page - 1) * limit;
      const dataQuery = `
        SELECT 
          ti.*,
          up.first_name as inviter_first_name,
          up.last_name as inviter_last_name
        FROM tenant_invitations ti
        LEFT JOIN user_profiles up ON ti.invited_by = up.user_id
        WHERE ${whereConditions.join(' AND ')}
        ORDER BY ti.created_at DESC
        LIMIT $${paramCount++} OFFSET $${paramCount++}
      `;
      
      const dataResult = await db.query(dataQuery, [...values, limit, offset]);

      const invitations: TenantInvitation[] = dataResult.rows.map((row: any) => ({
        id: row.id,
        tenantId: row.tenant_id,
        email: row.email,
        role: row.role,
        invitedBy: row.invited_by,
        invitationToken: row.invitation_token,
        expiresAt: new Date(row.expires_at),
        acceptedAt: row.accepted_at ? new Date(row.accepted_at) : undefined,
        createdAt: new Date(row.created_at),
        inviterName: row.inviter_first_name && row.inviter_last_name
          ? `${row.inviter_first_name} ${row.inviter_last_name}`
          : undefined,
      })) as TenantInvitation[];

      const totalPages = Math.ceil(total / limit);

      return {
        invitations,
        total,
        page,
        limit,
        totalPages,
      };
    } catch (error) {
      logger.error('Error fetching tenant invitations', {
        error: error instanceof Error ? error.message : String(error),
        tenantId,
        filters,
      });
      throw new DatabaseError('Failed to fetch tenant invitations');
    }
  }

  /**
   * Accept invitation (used during user registration)
   */
  async acceptInvitation(invitationToken: string, userId: string): Promise<void> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Find and validate invitation
        const invitation = await client.query(`
          SELECT * FROM tenant_invitations 
          WHERE invitation_token = $1 AND accepted_at IS NULL AND expires_at > NOW()
        `, [invitationToken]);

        if (invitation.rows.length === 0) {
          throw new ValidationError('Invalid or expired invitation');
        }

        const invite = invitation.rows[0];

        // Mark invitation as accepted
        await client.query(`
          UPDATE tenant_invitations 
          SET accepted_at = CURRENT_TIMESTAMP 
          WHERE id = $1
        `, [invite.id]);

        // Log invitation acceptance
        await this.logTenantActivity(client, invite.tenant_id, 'invitation_accepted', {
          invitationId: invite.id,
          userId: userId,
          email: invite.email,
        });

        logger.info('Invitation accepted successfully', {
          invitationId: invite.id,
          tenantId: invite.tenant_id,
          userId,
          email: invite.email,
        });
      } catch (error) {
        if (error instanceof ValidationError) {
          throw error;
        }
        
        logger.error('Error accepting invitation', {
          error: error instanceof Error ? error.message : String(error),
          invitationToken: '[REDACTED]',
          userId,
        });
        throw new DatabaseError('Failed to accept invitation');
      }
    });
  }

  /**
   * Get current user count for tenant
   */
  private async getCurrentUserCount(tenantId: string): Promise<number> {
    const result = await db.queryOne<{ count: string }>(
      'SELECT COUNT(*) as count FROM users WHERE tenant_id = $1 AND deleted_at IS NULL',
      [tenantId]
    );
    return parseInt(result?.count || '0');
  }

  /**
   * Create default settings for a new tenant
   */
  private async createDefaultSettings(client: PoolClient, tenantId: string): Promise<void> {
    const defaultSettings = this.getDefaultSettings();
    
    const query = `
      INSERT INTO tenant_settings (tenant_id, settings)
      VALUES ($1, $2)
    `;
    
    await client.query(query, [tenantId, JSON.stringify(defaultSettings)]);
  }

  /**
   * Get default tenant settings
   */
  private getDefaultSettings(): TenantSettings {
    return {
      classificationThresholds: {
        championMinTotal: 90,
        championMinSelf: 85,
        activistMinTotal: 80,
        goGetterMinSelf: 75,
      },
      classificationLabels: {
        champion: 'Champion',
        activist: 'Activist',
        paperTiger: 'Paper Tiger',
        goGetter: 'Go-Getter',
      },
      assessmentSettings: {
        allowSelfAssessment: true,
        requireManagerApproval: false,
        maxAssessmentsPerQuarter: 2,
        notificationEnabled: true,
      },
      emailSettings: {
        assessmentReminders: true,
        completionNotifications: true,
        weeklyReports: false,
      },
      customization: {
        primaryColor: '#007bff',
        companyName: 'Company',
      },
    };
  }

  /**
   * Merge settings objects deeply
   */
  private mergeSettings(current: TenantSettings, updates: Partial<TenantSettings>): TenantSettings {
    const result = { ...current };
    
    for (const [key, value] of Object.entries(updates)) {
      if (value !== undefined && typeof value === 'object' && !Array.isArray(value)) {
        result[key as keyof TenantSettings] = {
          ...result[key as keyof TenantSettings],
          ...value,
        } as any;
      } else if (value !== undefined) {
        result[key as keyof TenantSettings] = value as any;
      }
    }
    
    return result;
  }

  /**
   * Log tenant activity for audit trail
   */
  private async logTenantActivity(
    client: PoolClient,
    tenantId: string,
    action: string,
    details: any
  ): Promise<void> {
    try {
      const query = `
        INSERT INTO audit_logs (
          id, tenant_id, action, entity_type, 
          entity_id, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, CURRENT_TIMESTAMP)
      `;
      
      await client.query(query, [
        uuidv4(),
        tenantId,
        action,
        'tenant',
        tenantId,
        JSON.stringify(details),
      ]);
    } catch (error) {
      logger.warn('Failed to log tenant activity', {
        error: error instanceof Error ? error.message : String(error),
        tenantId,
        action,
      });
    }
  }

  /**
   * Map database row to Tenant object
   */
  private mapRowToTenant(row: any): Tenant {
    return {
      id: row.id,
      name: row.name,
      domain: row.domain,
      subscriptionTier: row.subscription_tier,
      maxUsers: row.max_users,
      settings: row.settings || this.getDefaultSettings(),
      createdAt: new Date(row.created_at),
      updatedAt: new Date(row.updated_at),
      deletedAt: row.deleted_at ? new Date(row.deleted_at) : undefined,
    };
  }
}

// Export singleton instance
export const tenantService = new TenantService();