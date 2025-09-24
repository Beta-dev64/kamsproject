import { db } from './index';
import { logger } from '../utils/logger';
import bcrypt from 'bcryptjs';

interface TenantSeedData {
  name: string;
  domain: string;
  subscriptionTier: string;
  maxUsers: number;
  adminUser: {
    email: string;
    firstName: string;
    lastName: string;
    password: string;
  };
  sampleUsers: Array<{
    email: string;
    firstName: string;
    lastName: string;
    role: string;
    department?: string;
  }>;
}

class DatabaseSeeder {
  private readonly defaultPassword = 'Admin123!';

  // Sample tenant data
  private readonly tenants: TenantSeedData[] = [
    {
      name: 'Acme Corporation',
      domain: 'acme-corp',
      subscriptionTier: 'premium',
      maxUsers: 500,
      adminUser: {
        email: 'admin@acme-corp.com',
        firstName: 'John',
        lastName: 'Admin',
        password: this.defaultPassword,
      },
      sampleUsers: [
        {
          email: 'sarah.manager@acme-corp.com',
          firstName: 'Sarah',
          lastName: 'Wilson',
          role: 'manager',
          department: 'Sales',
        },
        {
          email: 'mike.user@acme-corp.com',
          firstName: 'Mike',
          lastName: 'Johnson',
          role: 'user',
          department: 'Sales',
        },
        {
          email: 'lisa.user@acme-corp.com',
          firstName: 'Lisa',
          lastName: 'Chen',
          role: 'user',
          department: 'Marketing',
        },
      ],
    },
    {
      name: 'TechStart Inc',
      domain: 'techstart',
      subscriptionTier: 'standard',
      maxUsers: 100,
      adminUser: {
        email: 'admin@techstart.com',
        firstName: 'Alice',
        lastName: 'Cooper',
        password: this.defaultPassword,
      },
      sampleUsers: [
        {
          email: 'bob.manager@techstart.com',
          firstName: 'Bob',
          lastName: 'Smith',
          role: 'manager',
          department: 'Engineering',
        },
        {
          email: 'jane.user@techstart.com',
          firstName: 'Jane',
          lastName: 'Doe',
          role: 'user',
          department: 'Engineering',
        },
      ],
    },
  ];

  // Default assessment questions
  private readonly defaultQuestions = [
    {
      category: 'Customer Relationship Management',
      question: 'How effectively does the KAM build and maintain strong relationships with key stakeholders?',
      example: 'Regular communication, understanding customer needs, building trust',
      weight: 1.2,
      sortOrder: 1,
    },
    {
      category: 'Strategic Planning',
      question: 'How well does the KAM develop and execute strategic account plans?',
      example: 'Clear account strategies, goal setting, execution tracking',
      weight: 1.5,
      sortOrder: 2,
    },
    {
      category: 'Business Development',
      question: 'How effectively does the KAM identify and pursue new business opportunities?',
      example: 'Opportunity identification, proposal development, revenue growth',
      weight: 1.3,
      sortOrder: 3,
    },
    {
      category: 'Communication Skills',
      question: 'How well does the KAM communicate with internal teams and clients?',
      example: 'Clear communication, active listening, presentation skills',
      weight: 1.0,
      sortOrder: 4,
    },
    {
      category: 'Problem Solving',
      question: 'How effectively does the KAM resolve customer issues and challenges?',
      example: 'Quick resolution, creative solutions, customer satisfaction',
      weight: 1.1,
      sortOrder: 5,
    },
    {
      category: 'Market Knowledge',
      question: 'How well does the KAM understand market trends and competitive landscape?',
      example: 'Industry awareness, competitive intelligence, market positioning',
      weight: 1.0,
      sortOrder: 6,
    },
    {
      category: 'Team Collaboration',
      question: 'How effectively does the KAM work with internal cross-functional teams?',
      example: 'Collaboration, teamwork, internal relationship management',
      weight: 0.9,
      sortOrder: 7,
    },
    {
      category: 'Results Achievement',
      question: 'How consistently does the KAM meet or exceed targets and objectives?',
      example: 'Target achievement, KPI performance, results consistency',
      weight: 1.4,
      sortOrder: 8,
    },
  ];

  async seed(): Promise<void> {
    try {
      logger.info('Starting database seeding...');

      // Check if data already exists
      const existingTenants = await db.queryOne('SELECT COUNT(*) as count FROM kam_tenants');
      if (parseInt(existingTenants.count) > 0) {
        logger.info('Database already contains data, skipping seeding');
        return;
      }

      await db.transaction(async (client) => {
        // Seed tenants and users
        for (const tenantData of this.tenants) {
          const tenant = await this.createTenant(client, tenantData);
          await this.createUsers(client, tenant.id, tenantData);
          await this.createDefaultQuestions(client, tenant.id);
          await this.createTenantSettings(client, tenant.id);
        }

        // Create super admin user (not tied to any tenant)
        await this.createSuperAdmin(client);
      });

      logger.info('Database seeding completed successfully');
    } catch (error) {
      logger.error('Database seeding failed', { 
        error: error instanceof Error ? error.message : error 
      });
      throw error;
    }
  }

  private async createTenant(client: any, tenantData: TenantSeedData) {
    const result = await client.query(`
      INSERT INTO kam_tenants (name, domain, subscription_tier, max_users)
      VALUES ($1, $2, $3, $4)
      RETURNING id, name, domain
    `, [tenantData.name, tenantData.domain, tenantData.subscriptionTier, tenantData.maxUsers]);

    const tenant = result.rows[0];
    logger.info(`Created tenant: ${tenant.name} (${tenant.domain})`);
    return tenant;
  }

  private async createUsers(client: any, tenantId: string, tenantData: TenantSeedData) {
    const passwordHash = await bcrypt.hash(tenantData.adminUser.password, 12);

    // Create tenant admin
    const adminResult = await client.query(`
      INSERT INTO kam_profiles (
        tenant_id, email, password_hash, first_name, last_name, role, email_verified
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
      RETURNING id, email, first_name, last_name, role
    `, [
      tenantId,
      tenantData.adminUser.email,
      passwordHash,
      tenantData.adminUser.firstName,
      tenantData.adminUser.lastName,
      'tenant_admin',
      true,
    ]);

    const admin = adminResult.rows[0];
    logger.info(`Created admin user: ${admin.email} for tenant ${tenantData.domain}`);

    // Create sample users
    const defaultPasswordHash = await bcrypt.hash(this.defaultPassword, 12);
    const managers: any[] = [];
    
    for (const userData of tenantData.sampleUsers) {
      const userResult = await client.query(`
        INSERT INTO kam_profiles (
          tenant_id, email, password_hash, first_name, last_name, role, department, email_verified
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING id, email, first_name, last_name, role
      `, [
        tenantId,
        userData.email,
        defaultPasswordHash,
        userData.firstName,
        userData.lastName,
        userData.role,
        userData.department,
        true,
      ]);

      const user = userResult.rows[0];
      if (userData.role === 'manager') {
        managers.push(user);
      }

      logger.info(`Created user: ${user.email} (${user.role})`);
    }

    // Assign managers to regular users
    if (managers.length > 0) {
      const regularUsers = await client.query(`
        SELECT id FROM kam_profiles 
        WHERE tenant_id = $1 AND role = 'user'
      `, [tenantId]);

      for (const user of regularUsers.rows) {
        const randomManager = managers[Math.floor(Math.random() * managers.length)];
        await client.query(`
          UPDATE kam_profiles 
          SET manager_id = $1 
          WHERE id = $2
        `, [randomManager.id, user.id]);
      }
    }
  }

  private async createDefaultQuestions(client: any, tenantId: string) {
    // Get the tenant admin to use as the creator
    const admin = await client.query(`
      SELECT id FROM kam_profiles 
      WHERE tenant_id = $1 AND role = 'tenant_admin' 
      LIMIT 1
    `, [tenantId]);

    if (!admin.rows[0]) {
      throw new Error('No admin user found for tenant');
    }

    const adminId = admin.rows[0].id;

    for (const questionData of this.defaultQuestions) {
      await client.query(`
        INSERT INTO kam_assessment_questions (
          tenant_id, category, question, example, weight, sort_order, created_by
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7)
      `, [
        tenantId,
        questionData.category,
        questionData.question,
        questionData.example,
        questionData.weight,
        questionData.sortOrder,
        adminId,
      ]);
    }

    logger.info(`Created ${this.defaultQuestions.length} default questions for tenant`);
  }

  private async createTenantSettings(client: any, tenantId: string) {
    const defaultSettings = [
      {
        key: 'classification_thresholds',
        value: {
          champion_min_total: 75,
          champion_min_self: 70,
          activist_min_total: 60,
          go_getter_min_self: 70,
        },
        description: 'Score thresholds for KAM classification',
      },
      {
        key: 'classification_labels',
        value: {
          champion: 'Champion',
          activist: 'Activist',
          paper_tiger: 'Paper Tiger',
          go_getter: 'Go-getter',
        },
        description: 'Display labels for KAM classifications',
      },
      {
        key: 'assessment_settings',
        value: {
          allow_self_assessment: true,
          require_manager_approval: true,
          max_assessments_per_quarter: 1,
          notification_enabled: true,
        },
        description: 'Assessment workflow settings',
      },
      {
        key: 'email_settings',
        value: {
          assessment_reminders: true,
          completion_notifications: true,
          weekly_reports: false,
        },
        description: 'Email notification preferences',
      },
    ];

    for (const setting of defaultSettings) {
      await client.query(`
        INSERT INTO kam_tenant_settings (tenant_id, setting_key, setting_value, description)
        VALUES ($1, $2, $3, $4)
      `, [tenantId, setting.key, JSON.stringify(setting.value), setting.description]);
    }

    logger.info('Created default tenant settings');
  }

  private async createSuperAdmin(client: any) {
    const passwordHash = await bcrypt.hash('SuperAdmin123!', 12);

    await client.query(`
      INSERT INTO kam_profiles (
        tenant_id, email, password_hash, first_name, last_name, role, email_verified
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7)
    `, [
      null, // Super admin doesn't belong to any tenant
      'superadmin@kamportal.com',
      passwordHash,
      'Super',
      'Admin',
      'super_admin',
      true,
    ]);

    logger.info('Created super admin user');
  }

  async reset(): Promise<void> {
    logger.warn('Resetting database - this will delete ALL data!');
    
    await db.transaction(async (client) => {
      // Delete in reverse dependency order
      await client.query('DELETE FROM kam_attachments');
      await client.query('DELETE FROM kam_refresh_tokens');
      await client.query('DELETE FROM kam_audit_logs');
      await client.query('DELETE FROM kam_tenant_settings');
      await client.query('DELETE FROM kam_assessment_scores');
      await client.query('DELETE FROM kam_assessments');
      await client.query('DELETE FROM kam_assessment_questions');
      await client.query('DELETE FROM kam_profiles');
      await client.query('DELETE FROM kam_tenants');
    });

    logger.info('Database reset completed');
  }
}

// CLI interface
const seeder = new DatabaseSeeder();

async function main() {
  const command = process.argv[2];

  try {
    switch (command) {
      case 'seed':
        await seeder.seed();
        break;
        
      case 'reset':
        await seeder.reset();
        break;
        
      case 'reset-seed':
        await seeder.reset();
        await seeder.seed();
        break;
        
      default:
        logger.info('Available commands:');
        logger.info('  seed       - Seed the database with sample data');
        logger.info('  reset      - Reset all data (dangerous!)');
        logger.info('  reset-seed - Reset and then seed');
        break;
    }
  } catch (error) {
    logger.error('Seeder command failed', { 
      error: error instanceof Error ? error.message : error 
    });
    process.exit(1);
  } finally {
    await db.close();
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

export { DatabaseSeeder };