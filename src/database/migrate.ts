import { readdir, readFile } from 'fs/promises';
import { join } from 'path';
import { db } from './index';
import { logger } from '../utils/logger';

interface Migration {
  id: number;
  name: string;
  filename: string;
  up: string;
  down: string;
}

class MigrationRunner {
  private migrationsPath = join(__dirname, 'migrations');

  // Create migrations table if it doesn't exist
  private async ensureMigrationsTable(): Promise<void> {
    await db.query(`
      CREATE TABLE IF NOT EXISTS migrations (
        id SERIAL PRIMARY KEY,
        name VARCHAR(255) NOT NULL UNIQUE,
        executed_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
      )
    `);
  }

  // Get all migration files
  private async getMigrationFiles(): Promise<string[]> {
    try {
      const files = await readdir(this.migrationsPath);
      return files
        .filter(file => file.endsWith('.sql'))
        .sort((a, b) => a.localeCompare(b));
    } catch (error) {
      logger.warn('Migrations directory not found, skipping migrations');
      return [];
    }
  }

  // Parse migration file
  private async parseMigrationFile(filename: string): Promise<Migration> {
    const filePath = join(this.migrationsPath, filename);
    const content = await readFile(filePath, 'utf-8');
    
    // Split on -- DOWN comment
    const parts = content.split(/^-- DOWN$/m);
    
    if (parts.length !== 2) {
      throw new Error(`Invalid migration file format: ${filename}. Must contain -- DOWN separator.`);
    }
    
    const up = parts[0].replace(/^-- UP$/m, '').trim();
    const down = parts[1].trim();
    
    // Extract migration number from filename (001_create_table.sql -> 1)
    const match = filename.match(/^(\d+)_(.+)\.sql$/);
    if (!match) {
      throw new Error(`Invalid migration filename format: ${filename}. Must be like 001_description.sql`);
    }
    
    return {
      id: parseInt(match[1], 10),
      name: match[2].replace(/_/g, ' '),
      filename,
      up,
      down,
    };
  }

  // Get executed migrations from database
  private async getExecutedMigrations(): Promise<string[]> {
    const result = await db.query('SELECT name FROM migrations ORDER BY id');
    return result.rows.map(row => row.name);
  }

  // Run pending migrations
  async migrate(): Promise<void> {
    try {
      logger.info('Starting database migrations...');
      
      await this.ensureMigrationsTable();
      
      const migrationFiles = await this.getMigrationFiles();
      const executedMigrations = await this.getExecutedMigrations();
      
      if (migrationFiles.length === 0) {
        logger.info('No migration files found');
        return;
      }
      
      let migrationsRun = 0;
      
      for (const filename of migrationFiles) {
        const migration = await this.parseMigrationFile(filename);
        
        if (!executedMigrations.includes(migration.filename)) {
          logger.info(`Running migration: ${migration.filename}`);
          
          await db.transaction(async (client) => {
            // Execute the migration
            await client.query(migration.up);
            
            // Record the migration as executed
            await client.query(
              'INSERT INTO migrations (name) VALUES ($1)',
              [migration.filename]
            );
          });
          
          migrationsRun++;
          logger.info(`Migration completed: ${migration.filename}`);
        }
      }
      
      if (migrationsRun === 0) {
        logger.info('All migrations are up to date');
      } else {
        logger.info(`Successfully ran ${migrationsRun} migrations`);
      }
      
    } catch (error) {
      logger.error('Migration failed', { error: error instanceof Error ? error.message : error });
      throw error;
    }
  }

  // Rollback last migration
  async rollback(): Promise<void> {
    try {
      logger.info('Starting migration rollback...');
      
      await this.ensureMigrationsTable();
      
      // Get the last executed migration
      const lastMigration = await db.queryOne(`
        SELECT name FROM migrations 
        ORDER BY id DESC 
        LIMIT 1
      `);
      
      if (!lastMigration) {
        logger.info('No migrations to rollback');
        return;
      }
      
      const migration = await this.parseMigrationFile(lastMigration.name);
      
      logger.info(`Rolling back migration: ${migration.filename}`);
      
      await db.transaction(async (client) => {
        // Execute the rollback
        await client.query(migration.down);
        
        // Remove the migration record
        await client.query(
          'DELETE FROM migrations WHERE name = $1',
          [migration.filename]
        );
      });
      
      logger.info(`Migration rolled back: ${migration.filename}`);
      
    } catch (error) {
      logger.error('Rollback failed', { error: error instanceof Error ? error.message : error });
      throw error;
    }
  }

  // Get migration status
  async status(): Promise<void> {
    try {
      await this.ensureMigrationsTable();
      
      const migrationFiles = await this.getMigrationFiles();
      const executedMigrations = await this.getExecutedMigrations();
      
      logger.info('Migration Status:');
      
      for (const filename of migrationFiles) {
        const status = executedMigrations.includes(filename) ? 'EXECUTED' : 'PENDING';
        logger.info(`  ${filename}: ${status}`);
      }
      
    } catch (error) {
      logger.error('Failed to get migration status', { error: error instanceof Error ? error.message : error });
      throw error;
    }
  }
}

// CLI interface
const migrationRunner = new MigrationRunner();

async function main() {
  const command = process.argv[2];
  
  try {
    switch (command) {
      case 'up':
      case 'migrate':
        await migrationRunner.migrate();
        break;
        
      case 'down':
      case 'rollback':
        await migrationRunner.rollback();
        break;
        
      case 'status':
        await migrationRunner.status();
        break;
        
      default:
        logger.info('Available commands:');
        logger.info('  migrate|up    - Run pending migrations');
        logger.info('  rollback|down - Rollback last migration');
        logger.info('  status        - Show migration status');
        break;
    }
  } catch (error) {
    logger.error('Migration command failed', { error: error instanceof Error ? error.message : error });
    process.exit(1);
  } finally {
    await db.close();
  }
}

// Run if called directly
if (require.main === module) {
  main();
}

export { MigrationRunner };