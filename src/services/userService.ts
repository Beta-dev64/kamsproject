import { Pool, PoolClient } from 'pg';
import bcrypt from 'bcryptjs';
import { v4 as uuidv4 } from 'uuid';
import { User, UserRole, CreateUserRequest, UpdateUserRequest } from '../types';
import { logger } from '../utils/logger';
import { DatabaseError, ValidationError, NotFoundError, ConflictError } from '../middleware/errorHandler';
import { db, dbHelpers, executeInTransaction } from '../database';

/**
 * User service for managing user operations
 */
export class UserService {
  /**
   * Get user by ID with tenant isolation
   */
  async getUserById(userId: string, tenantId: string): Promise<User | null> {
    try {
      const query = `
        SELECT 
          u.*,
          p.first_name,
          p.last_name,
          p.department,
          p.manager_id,
          p.avatar_url,
          p.phone,
          p.hire_date,
          p.last_login_at,
          m_p.first_name as manager_first_name,
          m_p.last_name as manager_last_name
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        LEFT JOIN user_profiles m_p ON p.manager_id = m_p.user_id
        WHERE u.id = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
      `;
      
      const result = await dbHelpers.queryWithTenant(query, [userId, tenantId], tenantId);
      
      if (result.rows.length === 0) {
        return null;
      }

      return this.mapRowToUser(result.rows[0]);
    } catch (error) {
      logger.error('Error fetching user by ID', {
        error: error instanceof Error ? error.message : String(error),
        userId,
        tenantId,
      });
      throw new DatabaseError('Failed to fetch user');
    }
  }

  /**
   * Get user by email with tenant isolation
   */
  async getUserByEmail(email: string, tenantId: string): Promise<User | null> {
    try {
      const query = `
        SELECT 
          u.*,
          p.first_name,
          p.last_name,
          p.department,
          p.manager_id,
          p.avatar_url,
          p.phone,
          p.hire_date,
          p.last_login_at
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        WHERE u.email = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL
      `;
      
      const result = await dbHelpers.queryWithTenant(query, [email, tenantId], tenantId);
      
      if (result.rows.length === 0) {
        return null;
      }

      return this.mapRowToUser(result.rows[0]);
    } catch (error) {
      logger.error('Error fetching user by email', {
        error: error instanceof Error ? error.message : String(error),
        email,
        tenantId,
      });
      throw new DatabaseError('Failed to fetch user');
    }
  }

  /**
   * Create a new user
   */
  async createUser(userData: CreateUserRequest, tenantId: string, createdById?: string): Promise<User> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Check if user already exists
        const existingUser = await this.getUserByEmail(userData.email, tenantId);
        if (existingUser) {
          throw new ConflictError('User with this email already exists');
        }

        // Generate temporary password if not provided
        const tempPassword = Math.random().toString(36).slice(-12);
        const hashedPassword = await bcrypt.hash(tempPassword, 12);
        
        const userId = uuidv4();
        
        // Create user record
        const userQuery = `
          INSERT INTO users (
            id, tenant_id, email, password_hash, role, 
            is_active, email_verified, created_by
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
          RETURNING *
        `;
        
        const userResult = await client.query(userQuery, [
          userId,
          tenantId,
          userData.email.toLowerCase(),
          hashedPassword,
          userData.role,
          true,
          false, // Will need email verification
          createdById,
        ]);

        // Create user profile
        const profileQuery = `
          INSERT INTO user_profiles (
            user_id, first_name, last_name, department, manager_id
          ) VALUES ($1, $2, $3, $4, $5)
          RETURNING *
        `;
        
        const profileResult = await client.query(profileQuery, [
          userId,
          userData.firstName,
          userData.lastName,
          userData.department || null,
          userData.managerId || null,
        ]);

        // Log user creation
        await this.logUserActivity(client, userId, 'user_created', {
          createdBy: createdById,
          role: userData.role,
        }, tenantId);

        logger.info('User created successfully', {
          userId,
          email: userData.email,
          role: userData.role,
          tenantId,
          createdBy: createdById,
        });

        // Return the created user
        const user = this.mapRowToUser({
          ...userResult.rows[0],
          ...profileResult.rows[0],
        });

        return user;
      } catch (error) {
        if (error instanceof ConflictError) {
          throw error;
        }
        
        logger.error('Error creating user', {
          error: error instanceof Error ? error.message : String(error),
          userData: { ...userData, password: '[REDACTED]' },
          tenantId,
        });
        throw new DatabaseError('Failed to create user');
      }
    });
  }

  /**
   * Update user information
   */
  async updateUser(
    userId: string,
    updateData: UpdateUserRequest,
    tenantId: string,
    updatedById?: string
  ): Promise<User> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Check if user exists
        const existingUser = await this.getUserById(userId, tenantId);
        if (!existingUser) {
          throw new NotFoundError('User not found');
        }

        const updates: string[] = [];
        const userValues: any[] = [];
        const profileUpdates: string[] = [];
        const profileValues: any[] = [];
        
        let paramCount = 1;

        // Prepare user table updates
        if (updateData.role !== undefined) {
          updates.push(`role = $${paramCount++}`);
          userValues.push(updateData.role);
        }
        
        if (updateData.isActive !== undefined) {
          updates.push(`is_active = $${paramCount++}`);
          userValues.push(updateData.isActive);
        }

        // Prepare profile table updates
        if (updateData.firstName !== undefined) {
          profileUpdates.push(`first_name = $${paramCount++}`);
          profileValues.push(updateData.firstName);
        }
        
        if (updateData.lastName !== undefined) {
          profileUpdates.push(`last_name = $${paramCount++}`);
          profileValues.push(updateData.lastName);
        }
        
        if (updateData.department !== undefined) {
          profileUpdates.push(`department = $${paramCount++}`);
          profileValues.push(updateData.department);
        }
        
        if (updateData.managerId !== undefined) {
          profileUpdates.push(`manager_id = $${paramCount++}`);
          profileValues.push(updateData.managerId);
        }

        // Update user table if there are user-level changes
        if (updates.length > 0) {
          updates.push(`updated_at = CURRENT_TIMESTAMP`);
          const userQuery = `
            UPDATE users 
            SET ${updates.join(', ')} 
            WHERE id = $${paramCount++} AND tenant_id = $${paramCount++}
          `;
          
          await client.query(userQuery, [...userValues, userId, tenantId]);
        }

        // Update profile table if there are profile-level changes
        if (profileUpdates.length > 0) {
          profileUpdates.push(`updated_at = CURRENT_TIMESTAMP`);
          const profileQuery = `
            UPDATE user_profiles 
            SET ${profileUpdates.join(', ')} 
            WHERE user_id = $${paramCount++}
          `;
          
          await client.query(profileQuery, [...profileValues, userId]);
        }

        // Log user update
        await this.logUserActivity(client, userId, 'user_updated', {
          updatedBy: updatedById,
          changes: updateData,
        }, tenantId);

        logger.info('User updated successfully', {
          userId,
          tenantId,
          updatedBy: updatedById,
          changes: updateData,
        });

        // Return updated user
        const updatedUser = await this.getUserById(userId, tenantId);
        return updatedUser!;
      } catch (error) {
        if (error instanceof NotFoundError) {
          throw error;
        }
        
        logger.error('Error updating user', {
          error: error instanceof Error ? error.message : String(error),
          userId,
          updateData,
          tenantId,
        });
        throw new DatabaseError('Failed to update user');
      }
    });
  }

  /**
   * Soft delete user
   */
  async deleteUser(userId: string, tenantId: string, deletedById?: string): Promise<void> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Check if user exists
        const existingUser = await this.getUserById(userId, tenantId);
        if (!existingUser) {
          throw new NotFoundError('User not found');
        }

        // Check if user is trying to delete themselves
        if (userId === deletedById) {
          throw new ValidationError('Cannot delete your own account');
        }

        // Soft delete user
        const query = `
          UPDATE users 
          SET 
            deleted_at = CURRENT_TIMESTAMP,
            is_active = false,
            updated_at = CURRENT_TIMESTAMP
          WHERE id = $1 AND tenant_id = $2
        `;
        
        await client.query(query, [userId, tenantId]);

        // Log user deletion
        await this.logUserActivity(client, userId, 'user_deleted', {
          deletedBy: deletedById,
        }, tenantId);

        logger.info('User deleted successfully', {
          userId,
          tenantId,
          deletedBy: deletedById,
        });
      } catch (error) {
        if (error instanceof NotFoundError || error instanceof ValidationError) {
          throw error;
        }
        
        logger.error('Error deleting user', {
          error: error instanceof Error ? error.message : String(error),
          userId,
          tenantId,
        });
        throw new DatabaseError('Failed to delete user');
      }
    });
  }

  /**
   * Get users with filtering and pagination
   */
  async getUsers(
    tenantId: string,
    filters: {
      role?: UserRole;
      department?: string;
      isActive?: boolean;
      search?: string;
      managerId?: string;
      page?: number;
      limit?: number;
      sortBy?: string;
      sortOrder?: 'ASC' | 'DESC';
    } = {}
  ): Promise<{
    users: User[];
    total: number;
    page: number;
    limit: number;
    totalPages: number;
  }> {
    try {
      const {
        role,
        department,
        isActive,
        search,
        managerId,
        page = 1,
        limit = 20,
        sortBy = 'created_at',
        sortOrder = 'DESC',
      } = filters;

      let whereConditions = ['u.tenant_id = $1', 'u.deleted_at IS NULL'];
      let values: any[] = [tenantId];
      let paramCount = 2;

      // Add filters
      if (role) {
        whereConditions.push(`u.role = $${paramCount++}`);
        values.push(role);
      }
      
      if (department) {
        whereConditions.push(`p.department = $${paramCount++}`);
        values.push(department);
      }
      
      if (isActive !== undefined) {
        whereConditions.push(`u.is_active = $${paramCount++}`);
        values.push(isActive);
      }
      
      if (managerId) {
        whereConditions.push(`p.manager_id = $${paramCount++}`);
        values.push(managerId);
      }
      
      if (search) {
        whereConditions.push(`(
          p.first_name ILIKE $${paramCount} OR 
          p.last_name ILIKE $${paramCount} OR 
          u.email ILIKE $${paramCount}
        )`);
        values.push(`%${search}%`);
        paramCount++;
      }

      // Get total count
      const countQuery = `
        SELECT COUNT(*) as total
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        WHERE ${whereConditions.join(' AND ')}
      `;
      
      const countResult = await dbHelpers.queryWithTenant(countQuery, values, tenantId);
      const total = parseInt(countResult.rows[0].total);

      // Get paginated results
      const offset = (page - 1) * limit;
      const dataQuery = `
        SELECT 
          u.*,
          p.first_name,
          p.last_name,
          p.department,
          p.manager_id,
          p.avatar_url,
          p.phone,
          p.hire_date,
          p.last_login_at,
          m_p.first_name as manager_first_name,
          m_p.last_name as manager_last_name
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        LEFT JOIN user_profiles m_p ON p.manager_id = m_p.user_id
        WHERE ${whereConditions.join(' AND ')}
        ORDER BY ${this.getSortColumn(sortBy)} ${sortOrder}
        LIMIT $${paramCount++} OFFSET $${paramCount++}
      `;
      
      const dataResult = await dbHelpers.queryWithTenant(
        dataQuery,
        [...values, limit, offset],
        tenantId
      );

      const users = dataResult.rows.map((row: any) => this.mapRowToUser(row));
      const totalPages = Math.ceil(total / limit);

      return {
        users,
        total,
        page,
        limit,
        totalPages,
      };
    } catch (error) {
      logger.error('Error fetching users', {
        error: error instanceof Error ? error.message : String(error),
        filters,
        tenantId,
      });
      throw new DatabaseError('Failed to fetch users');
    }
  }

  /**
   * Update user profile (for users updating their own profile)
   */
  async updateProfile(
    userId: string,
    profileData: {
      firstName?: string;
      lastName?: string;
      department?: string;
      phone?: string;
      avatarUrl?: string;
    },
    tenantId: string
  ): Promise<User> {
    return executeInTransaction(async (client: PoolClient) => {
      try {
        // Check if user exists
        const existingUser = await this.getUserById(userId, tenantId);
        if (!existingUser) {
          throw new NotFoundError('User not found');
        }

        const updates: string[] = [];
        const values: any[] = [];
        let paramCount = 1;

        if (profileData.firstName !== undefined) {
          updates.push(`first_name = $${paramCount++}`);
          values.push(profileData.firstName);
        }
        
        if (profileData.lastName !== undefined) {
          updates.push(`last_name = $${paramCount++}`);
          values.push(profileData.lastName);
        }
        
        if (profileData.department !== undefined) {
          updates.push(`department = $${paramCount++}`);
          values.push(profileData.department);
        }
        
        if (profileData.phone !== undefined) {
          updates.push(`phone = $${paramCount++}`);
          values.push(profileData.phone);
        }
        
        if (profileData.avatarUrl !== undefined) {
          updates.push(`avatar_url = $${paramCount++}`);
          values.push(profileData.avatarUrl);
        }

        if (updates.length > 0) {
          updates.push(`updated_at = CURRENT_TIMESTAMP`);
          const query = `
            UPDATE user_profiles 
            SET ${updates.join(', ')} 
            WHERE user_id = $${paramCount++}
          `;
          
          await client.query(query, [...values, userId]);
        }

        // Log profile update
        await this.logUserActivity(client, userId, 'profile_updated', {
          changes: profileData,
        }, tenantId);

        logger.info('User profile updated successfully', {
          userId,
          tenantId,
          changes: profileData,
        });

        // Return updated user
        const updatedUser = await this.getUserById(userId, tenantId);
        return updatedUser!;
      } catch (error) {
        if (error instanceof NotFoundError) {
          throw error;
        }
        
        logger.error('Error updating user profile', {
          error: error instanceof Error ? error.message : String(error),
          userId,
          profileData,
          tenantId,
        });
        throw new DatabaseError('Failed to update user profile');
      }
    });
  }

  /**
   * Update user's last login timestamp
   */
  async updateLastLogin(userId: string, tenantId: string): Promise<void> {
    try {
      const query = `
        UPDATE user_profiles 
        SET last_login_at = CURRENT_TIMESTAMP 
        WHERE user_id = $1
      `;
      
      await dbHelpers.queryWithTenant(query, [userId], tenantId);
      
      logger.debug('Updated last login timestamp', { userId, tenantId });
    } catch (error) {
      // Don't throw error for login timestamp update failure
      logger.warn('Failed to update last login timestamp', {
        error: error instanceof Error ? error.message : String(error),
        userId,
        tenantId,
      });
    }
  }

  /**
   * Get users by role
   */
  async getUsersByRole(role: UserRole, tenantId: string): Promise<User[]> {
    try {
      const query = `
        SELECT 
          u.*,
          p.first_name,
          p.last_name,
          p.department,
          p.manager_id,
          p.avatar_url,
          p.phone,
          p.hire_date,
          p.last_login_at
        FROM users u
        LEFT JOIN user_profiles p ON u.id = p.user_id
        WHERE u.role = $1 AND u.tenant_id = $2 AND u.deleted_at IS NULL AND u.is_active = true
        ORDER BY p.first_name, p.last_name
      `;
      
      const result = await dbHelpers.queryWithTenant(query, [role, tenantId], tenantId);
      
      return result.rows.map((row: any) => this.mapRowToUser(row));
    } catch (error) {
      logger.error('Error fetching users by role', {
        error: error instanceof Error ? error.message : String(error),
        role,
        tenantId,
      });
      throw new DatabaseError('Failed to fetch users by role');
    }
  }

  /**
   * Check if user can manage another user (based on role hierarchy and manager relationship)
   */
  async canManageUser(managerId: string, targetUserId: string, tenantId: string): Promise<boolean> {
    try {
      if (managerId === targetUserId) {
        return true; // Can manage self
      }

      // Get both users
      const manager = await this.getUserById(managerId, tenantId);
      const targetUser = await this.getUserById(targetUserId, tenantId);

      if (!manager || !targetUser) {
        return false;
      }

      // Super admin can manage anyone
      if (manager.role === UserRole.SUPER_ADMIN) {
        return true;
      }

      // Admin can manage non-super-admin users
      if (manager.role === UserRole.ADMIN && targetUser.role !== UserRole.SUPER_ADMIN) {
        return true;
      }

      // Manager can manage their direct reports and users in same department
      if (manager.role === UserRole.MANAGER) {
        // Direct report relationship
        if (targetUser.managerId === managerId) {
          return true;
        }
        
        // Same department and target is USER role
        if (manager.department === targetUser.department && targetUser.role === UserRole.USER) {
          return true;
        }
      }

      return false;
    } catch (error) {
      logger.error('Error checking user management permissions', {
        error: error instanceof Error ? error.message : String(error),
        managerId,
        targetUserId,
        tenantId,
      });
      return false;
    }
  }

  /**
   * Log user activity for audit trail
   */
  private async logUserActivity(
    client: PoolClient,
    userId: string,
    action: string,
    details: any,
    tenantId: string
  ): Promise<void> {
    try {
      const query = `
        INSERT INTO audit_logs (
          id, tenant_id, user_id, action, entity_type, 
          entity_id, details, created_at
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, CURRENT_TIMESTAMP)
      `;
      
      await client.query(query, [
        uuidv4(),
        tenantId,
        userId,
        action,
        'user',
        userId,
        JSON.stringify(details),
      ]);
    } catch (error) {
      logger.warn('Failed to log user activity', {
        error: error instanceof Error ? error.message : String(error),
        userId,
        action,
        tenantId,
      });
    }
  }

  /**
   * Map database row to User object
   */
  private mapRowToUser(row: any): User {
    return {
      id: row.id,
      email: row.email,
      role: row.role,
      tenantId: row.tenant_id,
      isActive: row.is_active,
      emailVerified: row.email_verified,
      firstName: row.first_name,
      lastName: row.last_name,
      department: row.department,
      managerId: row.manager_id,
      avatarUrl: row.avatar_url,
      phone: row.phone,
      hireDate: row.hire_date,
      lastLoginAt: row.last_login_at,
      createdAt: row.created_at,
      updatedAt: row.updated_at,
      managerName: row.manager_first_name && row.manager_last_name
        ? `${row.manager_first_name} ${row.manager_last_name}`
        : undefined,
    };
  }

  /**
   * Get valid sort column for SQL query
   */
  private getSortColumn(sortBy: string): string {
    const validColumns: { [key: string]: string } = {
      email: 'u.email',
      role: 'u.role',
      firstName: 'p.first_name',
      lastName: 'p.last_name',
      department: 'p.department',
      isActive: 'u.is_active',
      createdAt: 'u.created_at',
      updatedAt: 'u.updated_at',
      lastLoginAt: 'p.last_login_at',
    };

    return validColumns[sortBy] || 'u.created_at';
  }
}

// Export singleton instance
export const userService = new UserService();