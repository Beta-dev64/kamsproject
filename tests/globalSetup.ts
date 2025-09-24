// Global setup for Jest tests
import { Pool } from 'pg';
import { testConfig } from './setup';

export default async (): Promise<void> => {
  console.log('🚀 Setting up test environment...');

  // Set environment variables for tests
  process.env.NODE_ENV = 'test';
  process.env.LOG_LEVEL = 'error';

  try {
    // Create test database connection
    const pool = new Pool({
      connectionString: testConfig.database.url,
      max: testConfig.database.poolSize,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: testConfig.database.timeout,
    });

    // Test database connection
    try {
      const client = await pool.connect();
      await client.query('SELECT 1');
      client.release();
      console.log('✅ Test database connection successful');
    } catch (dbError) {
      console.warn('⚠️ Test database not available, some tests may fail:', (dbError as Error).message);
    }

    await pool.end();

  } catch (error) {
    console.warn('⚠️ Global setup completed with warnings:', (error as Error).message);
  }

  console.log('✅ Test environment setup complete');
};