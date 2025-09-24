import { Pool, PoolClient, QueryResult, QueryResultRow } from 'pg';
import config from '../config';
import { logger } from '../utils/logger';

class Database {
  private pool: Pool;

  constructor() {
    this.pool = new Pool({
      connectionString: config.database.url,
      max: config.database.poolSize,
      idleTimeoutMillis: 30000,
      connectionTimeoutMillis: config.database.timeout,
      ssl: config.database.url.includes('neon.tech') || config.app.env === 'production' ? { rejectUnauthorized: false } : false,
    });

    // Handle pool events
    this.pool.on('connect', (client: PoolClient) => {
      logger.debug('New database connection established');
    });

    this.pool.on('error', (err: Error) => {
      logger.error('Unexpected error on idle client', { error: err.message });
    });

    this.pool.on('remove', () => {
      logger.debug('Database connection removed from pool');
    });
  }

  // Execute a query with parameters
  async query<T extends QueryResultRow = any>(text: string, params?: any[]): Promise<QueryResult<T>> {
    const start = Date.now();
    try {
      const result = await this.pool.query<T>(text, params);
      const duration = Date.now() - start;
      
      logger.debug('Database query executed', {
        query: text,
        params: params ? '[REDACTED]' : undefined,
        duration: `${duration}ms`,
        rows: result.rowCount,
      });

      return result;
    } catch (error) {
      const duration = Date.now() - start;
      logger.error('Database query error', {
        query: text,
        params: params ? '[REDACTED]' : undefined,
        duration: `${duration}ms`,
        error: error instanceof Error ? error.message : 'Unknown error',
      });
      throw error;
    }
  }

  // Get a single row or null
  async queryOne<T extends QueryResultRow = any>(text: string, params?: any[]): Promise<T | null> {
    const result = await this.query<T>(text, params);
    return result.rows[0] || null;
  }

  // Get all rows
  async queryMany<T extends QueryResultRow = any>(text: string, params?: any[]): Promise<T[]> {
    const result = await this.query<T>(text, params);
    return result.rows;
  }

  // Execute within a transaction
  async transaction<T>(callback: (client: PoolClient) => Promise<T>): Promise<T> {
    const client = await this.pool.connect();
    
    try {
      await client.query('BEGIN');
      const result = await callback(client);
      await client.query('COMMIT');
      return result;
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }

  // Check database connection
  async healthCheck(): Promise<boolean> {
    try {
      const result = await this.query('SELECT 1 as health_check');
      return result.rows[0]?.health_check === 1;
    } catch {
      return false;
    }
  }

  // Get connection pool statistics
  getPoolStats() {
    return {
      totalCount: this.pool.totalCount,
      idleCount: this.pool.idleCount,
      waitingCount: this.pool.waitingCount,
    };
  }

  // Close all connections
  async close(): Promise<void> {
    await this.pool.end();
    logger.info('Database pool closed');
  }

  // Utility method for safe tenant-scoped queries
  async tenantQuery<T extends QueryResultRow = any>(
    tenantId: string,
    text: string,
    params: any[] = []
  ): Promise<QueryResult<T>> {
    // Ensure all queries include tenant_id filter for data isolation
    if (!text.toLowerCase().includes('tenant_id')) {
      logger.warn('Query executed without tenant_id filter', { query: text });
    }
    
    return this.query<T>(text, [tenantId, ...params]);
  }

  // Utility method for paginated queries
  async paginatedQuery<T extends QueryResultRow = any>(
    query: string,
    params: any[],
    page: number = 1,
    limit: number = 50
  ): Promise<{ data: T[]; total: number; pages: number }> {
    const offset = (page - 1) * limit;
    
    // Count query
    const countQuery = `SELECT COUNT(*) FROM (${query}) as count_query`;
    const countResult = await this.query<{ count: string }>(countQuery, params);
    const total = parseInt(countResult.rows[0]?.count || '0', 10);
    
    // Data query with pagination
    const dataQuery = `${query} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    const dataResult = await this.query<T>(dataQuery, [...params, limit, offset]);
    
    return {
      data: dataResult.rows,
      total,
      pages: Math.ceil(total / limit),
    };
  }
}

// Export singleton instance
export const db = new Database();

// Database helper functions for convenience
export const dbHelpers = {
  query: db.query.bind(db),
  queryOne: db.queryOne.bind(db),
  queryMany: db.queryMany.bind(db),
  transaction: db.transaction.bind(db),
  healthCheck: db.healthCheck.bind(db),
  
  // Tenant-aware query wrapper
  queryWithTenant: async <T extends QueryResultRow = any>(
    text: string,
    params: any[] = [],
    tenantId: string
  ): Promise<QueryResult<T>> => {
    // Log the tenant context for debugging
    logger.debug('Executing tenant-scoped query', { tenantId, query: text });
    return db.query<T>(text, params);
  },
  
  // Safe pagination helper
  paginate: async <T extends QueryResultRow = any>(
    baseQuery: string,
    params: any[],
    page: number = 1,
    limit: number = 20
  ): Promise<{ rows: T[]; total: number; page: number; pages: number }> => {
    const offset = (page - 1) * limit;
    
    // Get total count
    const countQuery = `SELECT COUNT(*) as total FROM (${baseQuery}) as count_subquery`;
    const countResult = await db.queryOne<{ total: string }>(countQuery, params);
    const total = parseInt(countResult?.total || '0', 10);
    
    // Get paginated data
    const dataQuery = `${baseQuery} LIMIT $${params.length + 1} OFFSET $${params.length + 2}`;
    const dataResult = await db.query<T>(dataQuery, [...params, limit, offset]);
    
    return {
      rows: dataResult.rows,
      total,
      page,
      pages: Math.ceil(total / limit),
    };
  },
};

// Transaction helper function
export const executeInTransaction = async <T>(
  callback: (client: PoolClient) => Promise<T>
): Promise<T> => {
  return db.transaction(callback);
};

// Export types for external use
export type { QueryResult, PoolClient, QueryResultRow };
export { Database };
