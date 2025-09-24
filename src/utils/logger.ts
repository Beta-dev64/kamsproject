import winston from 'winston';
import config from '../config';

// Define base log format
const logFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format((info, opts) => {
    // Stringify errors with circular dependency handling
    if (info.stack) {
      info.stack = JSON.stringify(info.stack, null, 2);
    }
    return info;
  })(),
  winston.format.printf(({ timestamp, level, message, ...meta }) => {
    let logMessage = `${timestamp} [${level.toUpperCase()}]: ${message}`;
    
    // Add metadata if present
    if (Object.keys(meta).length > 0) {
      logMessage += `\n${JSON.stringify(meta, null, 2)}`;
    }
    
    return logMessage;
  })
);

// Define transports based on environment
const transports = [];

// In production, we only use the Console transport
if (config.app.env === 'production') {
  transports.push(
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple(),
      ),
    })
  );
} else {
  // In development, we use both file and console transports
  // Note: The log directory is not created automatically by Winston,
  // so we'll need to use a separate script or method to handle it.
  transports.push(
    new winston.transports.File({
      filename: `${config.logging.dir}/error.log`,
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.File({
      filename: `${config.logging.dir}/combined.log`,
      maxsize: 5242880, // 5MB
      maxFiles: 5,
    }),
    new winston.transports.Console({
      format: winston.format.combine(
        winston.format.colorize(),
        winston.format.simple()
      ),
    })
  );
}

// Create winston logger
export const logger = winston.createLogger({
  level: config.logging.level,
  format: logFormat,
  defaultMeta: {
    service: config.app.name,
    version: config.app.version,
    environment: config.app.env,
  },
  transports: transports,
});

// A factory function to create other loggers with a consistent format
const createLogger = (filename: string) => {
  const fileTransports = config.app.env !== 'production' ?
    [new winston.transports.File({ filename: `${config.logging.dir}/${filename}`, maxsize: 5242880 })] :
    [new winston.transports.Console()]; // Use console in production
  
  return winston.createLogger({
    level: 'info',
    format: winston.format.combine(
      winston.format.timestamp(),
      winston.format.json()
    ),
    transports: fileTransports,
  });
};

export const auditLogger = createLogger('audit.log');
export const requestLogger = createLogger('requests.log');
export const securityLogger = createLogger('security.log');
export const performanceLogger = createLogger('performance.log');

// Utility functions for structured logging
export const logRequest = (req: any, res: any, duration: number) => {
  requestLogger.info('HTTP Request', {
    method: req.method,
    url: req.url,
    statusCode: res.statusCode,
    duration: `${duration}ms`,
    userAgent: req.get('User-Agent'),
    ip: req.ip,
    userId: req.user?.id,
    tenantId: req.tenantId,
    requestId: req.requestId,
  });
};

export const logSecurityEvent = (event: string, details: Record<string, any>) => {
  securityLogger.info(event, {
    event,
    ...details,
    timestamp: new Date().toISOString(),
  });
};

export const logAuditEvent = (action: string, details: Record<string, any>) => {
  auditLogger.info(action, {
    action,
    ...details,
    timestamp: new Date().toISOString(),
  });
};

export const logPerformance = (operation: string, duration: number, details?: Record<string, any>) => {
  if (duration > 1000) { // Log operations taking more than 1 second
    performanceLogger.warn('Slow Operation', {
      operation,
      duration: `${duration}ms`,
      ...details,
    });
  }
};

// Audit log function for database operations
export const auditLog = async (
  tenantId: string,
  userId: string,
  action: string,
  resourceType: string,
  resourceId?: string,
  oldValues?: Record<string, any> | null,
  newValues?: Record<string, any> | null,
  ipAddress?: string,
  userAgent?: string
) => {
  try {
    const { db } = await import('../database');
    
    await db.query(
      `INSERT INTO kam_audit_logs 
       (tenant_id, user_id, action, resource_type, resource_id, old_values, new_values, ip_address, user_agent)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        tenantId,
        userId,
        action,
        resourceType,
        resourceId || null,
        oldValues ? JSON.stringify(oldValues) : null,
        newValues ? JSON.stringify(newValues) : null,
        ipAddress || null,
        userAgent || null
      ]
    );

    // Also log to audit logger
    auditLogger.info('Database Audit Log', {
      tenantId,
      userId,
      action,
      resourceType,
      resourceId,
      ipAddress,
      userAgent
    });
  } catch (error) {
    // If audit logging fails, log the error but don't throw
    logger.error('Failed to write audit log', {
      error: error instanceof Error ? error.message : error,
      tenantId,
      userId,
      action,
      resourceType
    });
  }
};

// Handle uncaught exceptions and unhandled rejections
process.on('uncaughtException', (error: Error) => {
  logger.error('Uncaught Exception', { error: error.message, stack: error.stack });
  process.exit(1);
});

process.on('unhandledRejection', (reason: any, promise: Promise<any>) => {
  logger.error('Unhandled Rejection', { 
    reason: reason instanceof Error ? reason.message : reason,
    promise: promise.toString(),
  });
});

export default logger;