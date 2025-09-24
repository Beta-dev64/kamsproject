import { db } from '../database';
import { logger } from '../utils/logger';
import { UserRole } from '../types';
import { jwtService } from '../utils/jwt';
import bcrypt from 'bcryptjs';
import crypto from 'crypto';

interface TenantFilters {
  search?: string;
  status?: 'active' | 'inactive';
  subscriptionTier?: 'basic' | 'pro' | 'enterprise';
  sortBy?: 'name' | 'domain' | 'createdAt' | 'userCount';
  sortOrder?: 'asc' | 'desc';
}

interface UserFilters {
  tenantId?: string;
  role?: UserRole;
  isActive?: boolean;
  search?: string;
  sortBy?: 'email' | 'firstName' | 'createdAt' | 'lastLoginAt';
  sortOrder?: 'asc' | 'desc';
}

interface AnalyticsFilters {
  startDate?: Date;
  endDate?: Date;
  tenantId?: string;
}

interface LogFilters {
  level?: 'error' | 'warn' | 'info' | 'debug';
  service?: string;
  startDate?: Date;
  endDate?: Date;
}

/**
 * System Admin Service - Handles system-wide operations
 * Only accessible by SUPER_ADMIN users
 */
class SystemAdminService {

  /**
   * Get system-wide dashboard statistics
   */
  async getSystemDashboard() {
    try {
      // Get tenant statistics
      const tenantStats = await db.queryOne(`
        SELECT 
          COUNT(*) as total_tenants,
          COUNT(CASE WHEN is_active = true THEN 1 END) as active_tenants,
          COUNT(CASE WHEN is_active = false THEN 1 END) as inactive_tenants,
          COUNT(CASE WHEN created_at >= NOW() - INTERVAL '30 days' THEN 1 END) as new_tenants_30d
        FROM kam_tenants 
        WHERE deleted_at IS NULL
      `);

      // Get user statistics
      const userStats = await db.queryOne(`
        SELECT 
          COUNT(*) as total_users,
          COUNT(CASE WHEN is_active = true THEN 1 END) as active_users,
          COUNT(CASE WHEN is_active = false THEN 1 END) as inactive_users,
          COUNT(CASE WHEN created_at >= NOW() - INTERVAL '30 days' THEN 1 END) as new_users_30d
        FROM kam_profiles 
        WHERE deleted_at IS NULL AND tenant_id IS NOT NULL
      `);

      // Get assessment statistics
      const assessmentStats = await db.queryOne(`
        SELECT 
          COUNT(*) as total_assessments,
          COUNT(CASE WHEN status = 'completed' THEN 1 END) as completed_assessments,
          COUNT(CASE WHEN status = 'draft' THEN 1 END) as draft_assessments,
          COUNT(CASE WHEN created_at >= NOW() - INTERVAL '30 days' THEN 1 END) as new_assessments_30d
        FROM kam_assessments 
        WHERE deleted_at IS NULL
      `);

      // Get system resource usage
      const poolStats = db.getPoolStats();

      // Get recent activity (last 7 days)
      const recentActivity = await db.query(`
        SELECT 
          DATE(created_at) as date,
          COUNT(*) as activity_count
        FROM (
          SELECT created_at FROM kam_tenants WHERE created_at >= NOW() - INTERVAL '7 days'
          UNION ALL
          SELECT created_at FROM kam_profiles WHERE created_at >= NOW() - INTERVAL '7 days' AND tenant_id IS NOT NULL
          UNION ALL
          SELECT created_at FROM kam_assessments WHERE created_at >= NOW() - INTERVAL '7 days'
        ) as activity
        GROUP BY DATE(created_at)
        ORDER BY date DESC
        LIMIT 7
      `);

      return {
        overview: {
          totalTenants: parseInt(tenantStats?.total_tenants || '0'),
          activeTenants: parseInt(tenantStats?.active_tenants || '0'),
          inactiveTenants: parseInt(tenantStats?.inactive_tenants || '0'),
          totalUsers: parseInt(userStats?.total_users || '0'),
          activeUsers: parseInt(userStats?.active_users || '0'),
          totalAssessments: parseInt(assessmentStats?.total_assessments || '0'),
          completedAssessments: parseInt(assessmentStats?.completed_assessments || '0')
        },
        growth: {
          newTenantsLast30Days: parseInt(tenantStats?.new_tenants_30d || '0'),
          newUsersLast30Days: parseInt(userStats?.new_users_30d || '0'),
          newAssessmentsLast30Days: parseInt(assessmentStats?.new_assessments_30d || '0')
        },
        system: {
          databaseConnections: poolStats,
          serverUptime: process.uptime(),
          memoryUsage: process.memoryUsage(),
          nodeVersion: process.version
        },
        activity: recentActivity.rows
      };
    } catch (error) {
      logger.error('Error getting system dashboard', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Get detailed system health status
   */
  async getSystemHealth() {
    try {
      const dbHealth = await db.healthCheck();
      const poolStats = db.getPoolStats();

      return {
        status: dbHealth ? 'healthy' : 'unhealthy',
        timestamp: new Date().toISOString(),
        services: {
          database: {
            status: dbHealth ? 'healthy' : 'unhealthy',
            connections: poolStats,
            responseTime: 0 // Could add actual response time measurement
          },
          application: {
            status: 'healthy',
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            version: process.env.npm_package_version || '1.0.0'
          }
        },
        alerts: [] // Could add system alerts here
      };
    } catch (error) {
      logger.error('Error getting system health', {
        error: error instanceof Error ? error.message : String(error)
      });
      throw error;
    }
  }

  /**
   * Get all tenants with pagination and filtering
   */
  async getAllTenants(page: number = 1, limit: number = 20, filters: TenantFilters = {}) {
    try {
      const offset = (page - 1) * limit;
      
      let baseQuery = `
        FROM kam_tenants t
        LEFT JOIN (
          SELECT 
            tenant_id, 
            COUNT(*) as user_count,
            COUNT(CASE WHEN is_active = true THEN 1 END) as active_user_count
          FROM kam_profiles 
          WHERE deleted_at IS NULL AND tenant_id IS NOT NULL
          GROUP BY tenant_id
        ) u ON t.id = u.tenant_id
        WHERE t.deleted_at IS NULL
      `;

      let whereConditions = [];
      let params = [];
      let paramIndex = 1;

      if (filters.search) {
        whereConditions.push(`(t.name ILIKE $${paramIndex} OR t.domain ILIKE $${paramIndex})`);
        params.push(`%${filters.search}%`);
        paramIndex++;
      }

      if (filters.status === 'active') {
        whereConditions.push('t.is_active = true');
      } else if (filters.status === 'inactive') {
        whereConditions.push('t.is_active = false');
      }

      if (filters.subscriptionTier) {
        whereConditions.push(`t.subscription_tier = $${paramIndex}`);
        params.push(filters.subscriptionTier);
        paramIndex++;
      }

      if (whereConditions.length > 0) {
        baseQuery += ' AND ' + whereConditions.join(' AND ');
      }

      // Count total
      const countResult = await db.queryOne(`SELECT COUNT(*) as total ${baseQuery}`, params);
      const total = parseInt(countResult?.total || '0');

      // Build sort clause
      let sortClause = 'ORDER BY ';
      switch (filters.sortBy) {
        case 'name':
          sortClause += 't.name';
          break;
        case 'domain':
          sortClause += 't.domain';
          break;
        case 'userCount':
          sortClause += 'COALESCE(u.user_count, 0)';
          break;
        default:
          sortClause += 't.created_at';
      }
      sortClause += ` ${filters.sortOrder === 'asc' ? 'ASC' : 'DESC'}`;

      // Get paginated data
      const dataQuery = `
        SELECT 
          t.id,
          t.name,
          t.domain,
          t.subscription_tier,
          t.max_users,
          t.is_active,
          t.created_at,
          t.updated_at,
          COALESCE(u.user_count, 0) as user_count,
          COALESCE(u.active_user_count, 0) as active_user_count
        ${baseQuery}
        ${sortClause}
        LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
      `;

      params.push(limit, offset);
      const result = await db.query(dataQuery, params);

      // Get summary statistics
      const summary = await db.queryOne(`
        SELECT 
          COUNT(CASE WHEN is_active = true THEN 1 END) as active_count,
          COUNT(CASE WHEN is_active = false THEN 1 END) as inactive_count,
          COUNT(CASE WHEN subscription_tier = 'basic' THEN 1 END) as basic_tier_count,
          COUNT(CASE WHEN subscription_tier = 'pro' THEN 1 END) as pro_tier_count,
          COUNT(CASE WHEN subscription_tier = 'enterprise' THEN 1 END) as enterprise_tier_count
        ${baseQuery}
      `, params.slice(0, -2)); // Remove limit and offset params

      return {
        tenants: result.rows,
        total,
        summary: {
          activeTenants: parseInt(summary?.active_count || '0'),
          inactiveTenants: parseInt(summary?.inactive_count || '0'),
          basicTier: parseInt(summary?.basic_tier_count || '0'),
          proTier: parseInt(summary?.pro_tier_count || '0'),
          enterpriseTier: parseInt(summary?.enterprise_tier_count || '0')
        }
      };
    } catch (error) {
      logger.error('Error getting all tenants', {
        error: error instanceof Error ? error.message : String(error),
        page,
        limit,
        filters
      });
      throw error;
    }
  }

  /**
   * Get tenant details with enhanced information
   */
  async getTenantDetails(tenantId: string) {
    try {
      // Get basic tenant info
      const tenant = await db.queryOne(`
        SELECT 
          t.*,
          (SELECT COUNT(*) FROM kam_profiles WHERE tenant_id = t.id AND deleted_at IS NULL) as user_count,
          (SELECT COUNT(*) FROM kam_profiles WHERE tenant_id = t.id AND is_active = true AND deleted_at IS NULL) as active_user_count,
          (SELECT COUNT(*) FROM kam_assessments WHERE tenant_id = t.id AND deleted_at IS NULL) as assessment_count,
          (SELECT COUNT(*) FROM kam_assessments WHERE tenant_id = t.id AND status = 'completed' AND deleted_at IS NULL) as completed_assessment_count
        FROM kam_tenants t
        WHERE t.id = $1 AND t.deleted_at IS NULL
      `, [tenantId]);

      if (!tenant) {
        return null;
      }

      // Get tenant settings
      const settings = await db.query(`
        SELECT setting_key, setting_value, description
        FROM kam_tenant_settings
        WHERE tenant_id = $1
      `, [tenantId]);

      // Get recent users
      const recentUsers = await db.query(`
        SELECT id, email, first_name, last_name, role, created_at, is_active
        FROM kam_profiles
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 5
      `, [tenantId]);

      // Get recent activity
      const recentActivity = await db.query(`
        SELECT 
          'assessment' as type,
          created_at,
          json_build_object('id', id, 'status', status) as metadata
        FROM kam_assessments
        WHERE tenant_id = $1 AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 10
      `, [tenantId]);

      return {
        ...tenant,
        settings: settings.rows.reduce((acc: any, setting: any) => {
          acc[setting.setting_key] = JSON.parse(setting.setting_value);
          return acc;
        }, {}),
        recentUsers: recentUsers.rows,
        recentActivity: recentActivity.rows,
        statistics: {
          userCount: parseInt(tenant.user_count),
          activeUserCount: parseInt(tenant.active_user_count),
          assessmentCount: parseInt(tenant.assessment_count),
          completedAssessmentCount: parseInt(tenant.completed_assessment_count)
        }
      };
    } catch (error) {
      logger.error('Error getting tenant details', {
        error: error instanceof Error ? error.message : String(error),
        tenantId
      });
      throw error;
    }
  }

  /**
   * Delete tenant (soft delete)
   */
  async deleteTenant(tenantId: string, deletedBy: string) {
    try {
      await db.transaction(async (client) => {
        // Soft delete the tenant
        await client.query(`
          UPDATE kam_tenants 
          SET 
            deleted_at = NOW(),
            updated_at = NOW()
          WHERE id = $1 AND deleted_at IS NULL
        `, [tenantId]);

        // Deactivate all users in the tenant
        await client.query(`
          UPDATE kam_profiles 
          SET 
            is_active = false,
            updated_at = NOW()
          WHERE tenant_id = $1 AND deleted_at IS NULL
        `, [tenantId]);

        // Log the deletion
        await client.query(`
          INSERT INTO kam_audit_logs (
            tenant_id, user_id, action, resource_type, resource_id, 
            details, ip_address, user_agent, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        `, [
          null, // System-level action
          deletedBy,
          'tenant_deleted',
          'tenant',
          tenantId,
          JSON.stringify({ deletedBy }),
          null,
          'System Admin'
        ]);
      });

      logger.warn('Tenant soft deleted', { tenantId, deletedBy });
    } catch (error) {
      logger.error('Error deleting tenant', {
        error: error instanceof Error ? error.message : String(error),
        tenantId,
        deletedBy
      });
      throw error;
    }
  }

  /**
   * Update tenant status (activate/deactivate)
   */
  async updateTenantStatus(tenantId: string, isActive: boolean, updatedBy: string) {
    try {
      await db.transaction(async (client) => {
        await client.query(`
          UPDATE kam_tenants 
          SET 
            is_active = $1,
            updated_at = NOW()
          WHERE id = $2 AND deleted_at IS NULL
        `, [isActive, tenantId]);

        // If deactivating, also deactivate all users
        if (!isActive) {
          await client.query(`
            UPDATE kam_profiles 
            SET 
              is_active = false,
              updated_at = NOW()
            WHERE tenant_id = $1
          `, [tenantId]);
        }

        // Log the status change
        await client.query(`
          INSERT INTO kam_audit_logs (
            tenant_id, user_id, action, resource_type, resource_id, 
            details, ip_address, user_agent, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        `, [
          null,
          updatedBy,
          isActive ? 'tenant_activated' : 'tenant_deactivated',
          'tenant',
          tenantId,
          JSON.stringify({ isActive, updatedBy }),
          null,
          'System Admin'
        ]);
      });

      logger.info(`Tenant ${isActive ? 'activated' : 'deactivated'}`, { 
        tenantId, 
        isActive, 
        updatedBy 
      });
    } catch (error) {
      logger.error('Error updating tenant status', {
        error: error instanceof Error ? error.message : String(error),
        tenantId,
        isActive,
        updatedBy
      });
      throw error;
    }
  }

  /**
   * Get all users across all tenants
   */
  async getAllUsers(page: number = 1, limit: number = 20, filters: UserFilters = {}) {
    try {
      const offset = (page - 1) * limit;
      
      let baseQuery = `
        FROM kam_profiles p
        LEFT JOIN kam_tenants t ON p.tenant_id = t.id
        WHERE p.deleted_at IS NULL AND p.tenant_id IS NOT NULL
      `;

      let whereConditions = [];
      let params = [];
      let paramIndex = 1;

      if (filters.tenantId) {
        whereConditions.push(`p.tenant_id = $${paramIndex}`);
        params.push(filters.tenantId);
        paramIndex++;
      }

      if (filters.role) {
        whereConditions.push(`p.role = $${paramIndex}`);
        params.push(filters.role);
        paramIndex++;
      }

      if (filters.isActive !== undefined) {
        whereConditions.push(`p.is_active = $${paramIndex}`);
        params.push(filters.isActive);
        paramIndex++;
      }

      if (filters.search) {
        whereConditions.push(`(
          p.email ILIKE $${paramIndex} OR 
          p.first_name ILIKE $${paramIndex} OR 
          p.last_name ILIKE $${paramIndex}
        )`);
        params.push(`%${filters.search}%`);
        paramIndex++;
      }

      if (whereConditions.length > 0) {
        baseQuery += ' AND ' + whereConditions.join(' AND ');
      }

      // Count total
      const countResult = await db.queryOne(`SELECT COUNT(*) as total ${baseQuery}`, params);
      const total = parseInt(countResult?.total || '0');

      // Build sort clause
      let sortClause = 'ORDER BY ';
      switch (filters.sortBy) {
        case 'email':
          sortClause += 'p.email';
          break;
        case 'firstName':
          sortClause += 'p.first_name';
          break;
        case 'lastLoginAt':
          sortClause += 'p.last_login_at';
          break;
        default:
          sortClause += 'p.created_at';
      }
      sortClause += ` ${filters.sortOrder === 'asc' ? 'ASC' : 'DESC'}`;

      // Get paginated data
      const dataQuery = `
        SELECT 
          p.id,
          p.email,
          p.first_name,
          p.last_name,
          p.role,
          p.department,
          p.is_active,
          p.email_verified,
          p.last_login_at,
          p.created_at,
          p.updated_at,
          p.tenant_id,
          t.name as tenant_name,
          t.domain as tenant_domain
        ${baseQuery}
        ${sortClause}
        LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
      `;

      params.push(limit, offset);
      const result = await db.query(dataQuery, params);

      // Get summary statistics
      const summary = await db.queryOne(`
        SELECT 
          COUNT(CASE WHEN p.is_active = true THEN 1 END) as active_count,
          COUNT(CASE WHEN p.is_active = false THEN 1 END) as inactive_count,
          COUNT(CASE WHEN p.role = 'admin' THEN 1 END) as admin_count,
          COUNT(CASE WHEN p.role = 'manager' THEN 1 END) as manager_count,
          COUNT(CASE WHEN p.role = 'user' THEN 1 END) as user_count
        ${baseQuery}
      `, params.slice(0, -2));

      return {
        users: result.rows,
        total,
        summary: {
          activeUsers: parseInt(summary?.active_count || '0'),
          inactiveUsers: parseInt(summary?.inactive_count || '0'),
          adminUsers: parseInt(summary?.admin_count || '0'),
          managerUsers: parseInt(summary?.manager_count || '0'),
          regularUsers: parseInt(summary?.user_count || '0')
        }
      };
    } catch (error) {
      logger.error('Error getting all users', {
        error: error instanceof Error ? error.message : String(error),
        page,
        limit,
        filters
      });
      throw error;
    }
  }

  /**
   * Get user details (cross-tenant)
   */
  async getUserDetails(userId: string) {
    try {
      const user = await db.queryOne(`
        SELECT 
          p.*,
          t.name as tenant_name,
          t.domain as tenant_domain,
          t.is_active as tenant_is_active,
          (SELECT COUNT(*) FROM kam_assessments WHERE employee_id = p.id OR assessor_id = p.id) as assessment_count,
          (SELECT COUNT(*) FROM kam_assessments WHERE (employee_id = p.id OR assessor_id = p.id) AND status = 'completed') as completed_assessment_count
        FROM kam_profiles p
        LEFT JOIN kam_tenants t ON p.tenant_id = t.id
        WHERE p.id = $1 AND p.deleted_at IS NULL
      `, [userId]);

      if (!user) {
        return null;
      }

      // Get recent assessments
      const recentAssessments = await db.query(`
        SELECT 
          id, 
          assessment_type, 
          status, 
          assessment_date,
          created_at,
          CASE 
            WHEN employee_id = $1 THEN 'employee'
            WHEN assessor_id = $1 THEN 'assessor'
          END as role
        FROM kam_assessments
        WHERE (employee_id = $1 OR assessor_id = $1) AND deleted_at IS NULL
        ORDER BY created_at DESC
        LIMIT 10
      `, [userId]);

      return {
        ...user,
        statistics: {
          assessmentCount: parseInt(user.assessment_count),
          completedAssessmentCount: parseInt(user.completed_assessment_count)
        },
        recentAssessments: recentAssessments.rows
      };
    } catch (error) {
      logger.error('Error getting user details', {
        error: error instanceof Error ? error.message : String(error),
        userId
      });
      throw error;
    }
  }

  /**
   * Update user (cross-tenant)
   */
  async updateUser(userId: string, updateData: any, updatedBy: string) {
    try {
      const allowedFields = ['firstName', 'lastName', 'role', 'isActive', 'department', 'managerId'];
      const updates: string[] = [];
      const params: any[] = [];
      let paramIndex = 1;

      for (const [key, value] of Object.entries(updateData)) {
        if (allowedFields.includes(key) && value !== undefined) {
          let dbField = key;
          // Convert camelCase to snake_case
          if (key === 'firstName') dbField = 'first_name';
          else if (key === 'lastName') dbField = 'last_name';
          else if (key === 'isActive') dbField = 'is_active';
          else if (key === 'managerId') dbField = 'manager_id';

          updates.push(`${dbField} = $${paramIndex}`);
          params.push(value);
          paramIndex++;
        }
      }

      if (updates.length === 0) {
        throw new Error('No valid fields to update');
      }

      updates.push(`updated_at = NOW()`);
      params.push(userId); // For WHERE clause

      const query = `
        UPDATE kam_profiles 
        SET ${updates.join(', ')}
        WHERE id = $${paramIndex} AND deleted_at IS NULL
        RETURNING id, email, first_name, last_name, role, department, is_active, updated_at
      `;

      const result = await db.queryOne(query, params);

      // Log the update
      await db.query(`
        INSERT INTO kam_audit_logs (
          tenant_id, user_id, action, resource_type, resource_id, 
          details, ip_address, user_agent, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      `, [
        null,
        updatedBy,
        'user_updated_by_system_admin',
        'user',
        userId,
        JSON.stringify({ updateData, updatedBy }),
        null,
        'System Admin'
      ]);

      return result;
    } catch (error) {
      logger.error('Error updating user', {
        error: error instanceof Error ? error.message : String(error),
        userId,
        updateData,
        updatedBy
      });
      throw error;
    }
  }

  /**
   * Reset user password
   */
  async resetUserPassword(userId: string, resetBy: string): Promise<string> {
    try {
      // Generate temporary password
      const tempPassword = crypto.randomBytes(12).toString('hex');
      const hashedPassword = await bcrypt.hash(tempPassword, 12);

      await db.transaction(async (client) => {
        // Update password
        await client.query(`
          UPDATE kam_profiles 
          SET 
            password_hash = $1,
            password_reset_required = true,
            updated_at = NOW()
          WHERE id = $2 AND deleted_at IS NULL
        `, [hashedPassword, userId]);

        // Log the password reset
        await client.query(`
          INSERT INTO kam_audit_logs (
            tenant_id, user_id, action, resource_type, resource_id, 
            details, ip_address, user_agent, created_at
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
        `, [
          null,
          resetBy,
          'password_reset_by_system_admin',
          'user',
          userId,
          JSON.stringify({ resetBy, targetUserId: userId }),
          null,
          'System Admin'
        ]);
      });

      return tempPassword;
    } catch (error) {
      logger.error('Error resetting user password', {
        error: error instanceof Error ? error.message : String(error),
        userId,
        resetBy
      });
      throw error;
    }
  }

  /**
   * Get system-wide analytics
   */
  async getSystemAnalytics(filters: AnalyticsFilters = {}) {
    try {
      const { startDate, endDate, tenantId } = filters;
      
      let dateCondition = '';
      let params: any[] = [];
      let paramIndex = 1;

      if (startDate && endDate) {
        dateCondition = `AND created_at BETWEEN $${paramIndex} AND $${paramIndex + 1}`;
        params.push(startDate, endDate);
        paramIndex += 2;
      }

      let tenantCondition = '';
      if (tenantId) {
        tenantCondition = `AND tenant_id = $${paramIndex}`;
        params.push(tenantId);
        paramIndex++;
      }

      // Get growth metrics
      const growthMetrics = await db.queryOne(`
        SELECT 
          COUNT(CASE WHEN table_name = 'tenants' THEN 1 END) as new_tenants,
          COUNT(CASE WHEN table_name = 'users' THEN 1 END) as new_users,
          COUNT(CASE WHEN table_name = 'assessments' THEN 1 END) as new_assessments
        FROM (
          SELECT 'tenants' as table_name, created_at FROM kam_tenants WHERE deleted_at IS NULL ${dateCondition}
          UNION ALL
          SELECT 'users' as table_name, created_at FROM kam_profiles WHERE deleted_at IS NULL AND tenant_id IS NOT NULL ${dateCondition} ${tenantCondition}
          UNION ALL
          SELECT 'assessments' as table_name, created_at FROM kam_assessments WHERE deleted_at IS NULL ${dateCondition} ${tenantCondition}
        ) combined
      `, params);

      return {
        period: {
          startDate: startDate?.toISOString(),
          endDate: endDate?.toISOString(),
          tenantId
        },
        growth: {
          newTenants: parseInt(growthMetrics?.new_tenants || '0'),
          newUsers: parseInt(growthMetrics?.new_users || '0'),
          newAssessments: parseInt(growthMetrics?.new_assessments || '0')
        }
      };
    } catch (error) {
      logger.error('Error getting system analytics', {
        error: error instanceof Error ? error.message : String(error),
        filters
      });
      throw error;
    }
  }

  /**
   * Get tenant usage analytics
   */
  async getTenantAnalytics(filters: AnalyticsFilters = {}) {
    try {
      const { startDate, endDate, tenantId } = filters;
      
      let whereCondition = 'WHERE t.deleted_at IS NULL';
      let params: any[] = [];
      let paramIndex = 1;

      if (tenantId) {
        whereCondition += ` AND t.id = $${paramIndex}`;
        params.push(tenantId);
        paramIndex++;
      }

      const analytics = await db.query(`
        SELECT 
          t.id,
          t.name,
          t.domain,
          t.subscription_tier,
          COUNT(DISTINCT p.id) as user_count,
          COUNT(DISTINCT CASE WHEN p.is_active = true THEN p.id END) as active_user_count,
          COUNT(DISTINCT a.id) as assessment_count,
          COUNT(DISTINCT CASE WHEN a.status = 'completed' THEN a.id END) as completed_assessment_count
        FROM kam_tenants t
        LEFT JOIN kam_profiles p ON t.id = p.tenant_id AND p.deleted_at IS NULL
        LEFT JOIN kam_assessments a ON t.id = a.tenant_id AND a.deleted_at IS NULL
        ${whereCondition}
        GROUP BY t.id, t.name, t.domain, t.subscription_tier
        ORDER BY user_count DESC
      `, params);

      return {
        period: {
          startDate: startDate?.toISOString(),
          endDate: endDate?.toISOString(),
          tenantId
        },
        tenants: analytics.rows.map((tenant: any) => ({
          ...tenant,
          userCount: parseInt(tenant.user_count),
          activeUserCount: parseInt(tenant.active_user_count),
          assessmentCount: parseInt(tenant.assessment_count),
          completedAssessmentCount: parseInt(tenant.completed_assessment_count)
        }))
      };
    } catch (error) {
      logger.error('Error getting tenant analytics', {
        error: error instanceof Error ? error.message : String(error),
        filters
      });
      throw error;
    }
  }

  /**
   * Run system cleanup tasks
   */
  async runSystemCleanup(initiatedBy: string) {
    try {
      const results: any = {};

      // Clean up expired refresh tokens
      const expiredTokens = await db.query(`
        DELETE FROM kam_refresh_tokens 
        WHERE expires_at < NOW() OR is_active = false
        RETURNING id
      `);
      results.expiredTokensRemoved = expiredTokens.rowCount;

      // Clean up old audit logs (keep last 90 days)
      const oldAuditLogs = await db.query(`
        DELETE FROM kam_audit_logs 
        WHERE created_at < NOW() - INTERVAL '90 days'
        RETURNING id
      `);
      results.oldAuditLogsRemoved = oldAuditLogs.rowCount;

      // Log the cleanup
      await db.query(`
        INSERT INTO kam_audit_logs (
          tenant_id, user_id, action, resource_type, resource_id, 
          details, ip_address, user_agent, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      `, [
        null,
        initiatedBy,
        'system_cleanup',
        'system',
        null,
        JSON.stringify({ results, initiatedBy }),
        null,
        'System Admin'
      ]);

      return results;
    } catch (error) {
      logger.error('Error running system cleanup', {
        error: error instanceof Error ? error.message : String(error),
        initiatedBy
      });
      throw error;
    }
  }

  /**
   * Get system logs (simplified - would connect to actual logging system in production)
   */
  async getSystemLogs(page: number = 1, limit: number = 50, filters: LogFilters = {}) {
    try {
      const offset = (page - 1) * limit;
      
      // This is a simplified version - in production, this would query actual log storage
      let whereConditions = [];
      let params = [];
      let paramIndex = 1;

      if (filters.level) {
        whereConditions.push(`action LIKE '%${filters.level}%'`);
      }

      if (filters.startDate && filters.endDate) {
        whereConditions.push(`created_at BETWEEN $${paramIndex} AND $${paramIndex + 1}`);
        params.push(filters.startDate, filters.endDate);
        paramIndex += 2;
      }

      let whereClause = whereConditions.length > 0 ? 'WHERE ' + whereConditions.join(' AND ') : '';

      const countResult = await db.queryOne(`
        SELECT COUNT(*) as total 
        FROM kam_audit_logs 
        ${whereClause}
      `, params);

      const result = await db.query(`
        SELECT 
          id,
          action as level,
          resource_type as service,
          details as message,
          created_at as timestamp,
          user_id,
          tenant_id
        FROM kam_audit_logs 
        ${whereClause}
        ORDER BY created_at DESC
        LIMIT $${paramIndex} OFFSET $${paramIndex + 1}
      `, [...params, limit, offset]);

      return {
        logs: result.rows,
        total: parseInt(countResult?.total || '0')
      };
    } catch (error) {
      logger.error('Error getting system logs', {
        error: error instanceof Error ? error.message : String(error),
        page,
        limit,
        filters
      });
      throw error;
    }
  }

  /**
   * Create impersonation token (for support/debugging)
   */
  async createImpersonationToken(targetUserId: string, impersonatedBy: string): Promise<string> {
    try {
      // Get target user details
      const targetUser = await db.queryOne(`
        SELECT id, email, tenant_id, role
        FROM kam_profiles
        WHERE id = $1 AND deleted_at IS NULL
      `, [targetUserId]);

      if (!targetUser) {
        throw new Error('Target user not found');
      }

      // Create impersonation token with special payload
      const impersonationPayload = {
        userId: targetUser.id,
        tenantId: targetUser.tenant_id,
        email: targetUser.email,
        role: targetUser.role,
        impersonatedBy,
        isImpersonation: true
      };

      const token = jwtService.generateAccessToken(targetUser);

      // Log the impersonation
      await db.query(`
        INSERT INTO kam_audit_logs (
          tenant_id, user_id, action, resource_type, resource_id, 
          details, ip_address, user_agent, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
      `, [
        targetUser.tenant_id,
        impersonatedBy,
        'user_impersonation',
        'user',
        targetUserId,
        JSON.stringify({ 
          impersonatedBy, 
          targetUserId,
          targetUserEmail: targetUser.email 
        }),
        null,
        'System Admin'
      ]);

      return token;
    } catch (error) {
      logger.error('Error creating impersonation token', {
        error: error instanceof Error ? error.message : String(error),
        targetUserId,
        impersonatedBy
      });
      throw error;
    }
  }
}

export const systemAdminService = new SystemAdminService();