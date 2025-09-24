import { Request } from 'express';

// User and Authentication Types
export interface User {
  id: string;
  tenantId: string;
  email: string;
  firstName: string;
  lastName: string;
  role: UserRole;
  department?: string;
  managerId?: string;
  isActive: boolean;
  emailVerified: boolean;
  avatarUrl?: string;
  phone?: string;
  hireDate?: Date;
  lastLoginAt?: Date;
  createdAt: Date;
  updatedAt: Date;
  managerName?: string;
}

export enum UserRole {
  SUPER_ADMIN = 'super_admin',
  ADMIN = 'admin',
  MANAGER = 'manager',
  USER = 'user',
}

export enum Permission {
  // Tenant Management
  TENANT_CREATE = 'tenant:create',
  TENANT_READ = 'tenant:read',
  TENANT_UPDATE = 'tenant:update',
  TENANT_DELETE = 'tenant:delete',
  
  // User Management
  USER_CREATE = 'user:create',
  USER_READ = 'user:read',
  USER_UPDATE = 'user:update',
  USER_DELETE = 'user:delete',
  
  // Assessment Management
  ASSESSMENT_CREATE = 'assessment:create',
  ASSESSMENT_READ = 'assessment:read',
  ASSESSMENT_UPDATE = 'assessment:update',
  ASSESSMENT_DELETE = 'assessment:delete',
  ASSESSMENT_READ_ALL = 'assessment:read_all',
  
  // Settings Management
  SETTINGS_READ = 'settings:read',
  SETTINGS_UPDATE = 'settings:update',
}

// Tenant Types
export interface Tenant {
  id: string;
  name: string;
  domain: string;
  settings: Record<string, any>;
  subscriptionTier: string;
  maxUsers: number;
  createdAt: Date;
  updatedAt: Date;
  deletedAt?: Date;
}

// Assessment Types
export interface Assessment {
  id: string;
  tenantId: string;
  employeeId: string;
  assessorId: string;
  assessmentType: AssessmentType;
  assessmentDate: Date;
  quarter?: string;
  year?: number;
  status: AssessmentStatus;
  notes?: string;
  createdAt: Date;
  updatedAt: Date;
}

export enum AssessmentType {
  MANAGER = 'manager',
  SELF = 'self',
}

export enum AssessmentStatus {
  DRAFT = 'draft',
  SUBMITTED = 'submitted',
  COMPLETED = 'completed',
}

export interface AssessmentQuestion {
  id: string;
  tenantId: string;
  category: string;
  question: string;
  example?: string;
  weight: number;
  isActive: boolean;
  createdBy: string;
  createdAt: Date;
  updatedAt: Date;
}

export interface AssessmentScore {
  id: string;
  assessmentId: string;
  questionId: string;
  score: number; // 1-4
  createdAt: Date;
}

// API Request/Response Types
export interface AuthRequest extends Request {
  user?: User;
  tenantId?: string;
  tenantDomain?: string;
  requestId?: string;
  dbContext?: {
    tenantId: string;
    userId?: string;
  };
}

export interface LoginRequest {
  email: string;
  password: string;
  tenantDomain?: string;
}

export interface RegisterRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  tenantDomain: string;
}

export interface AuthResponse {
  user: Omit<User, 'passwordHash'>;
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

// Database Types
export interface DatabaseConfig {
  url: string;
  poolSize: number;
  timeout: number;
}

export interface PaginationOptions {
  page: number;
  limit: number;
  sort?: string;
  order?: 'asc' | 'desc';
}

export interface PaginatedResponse<T> {
  data: T[];
  total: number;
  pages: number;
  currentPage: number;
  hasNext: boolean;
  hasPrev: boolean;
}

// Audit Log Types
export interface AuditLog {
  id: string;
  tenantId: string;
  userId?: string;
  action: string;
  resourceType: string;
  resourceId?: string;
  oldValues?: Record<string, any>;
  newValues?: Record<string, any>;
  ipAddress?: string;
  userAgent?: string;
  createdAt: Date;
}

// Error Types
export interface ApiError {
  code: string;
  message: string;
  details?: any;
  statusCode: number;
}

// Configuration Types
export interface AppConfig {
  app: {
    name: string;
    version: string;
    port: number;
    env: 'development' | 'test' | 'production';
  };
  database: DatabaseConfig;
  jwt: {
    secret: string;
    expiresIn: string;
    refreshExpiresIn: string;
  };
  security: {
    bcryptRounds: number;
    corsOrigins: string[];
  };
  rateLimit: {
    windowMs: number;
    maxRequests: number;
    authMax: number;
  };
  logging: {
    level: string;
    dir: string;
  };
}

// Utility Types
export type CreateUserDTO = Omit<User, 'id' | 'createdAt' | 'updatedAt' | 'lastLoginAt'>;
export type UpdateUserDTO = Partial<Pick<User, 'firstName' | 'lastName' | 'department' | 'role' | 'isActive'>>;
export type CreateAssessmentDTO = Omit<Assessment, 'id' | 'createdAt' | 'updatedAt' | 'status'>;
export type CreateTenantDTO = Omit<Tenant, 'id' | 'createdAt' | 'updatedAt' | 'deletedAt'>;

// Import validation types (re-export from validation.ts)
export type { 
  CreateUserRequest,
  UpdateUserRequest,
  UserFilterRequest
} from '../utils/validation';
