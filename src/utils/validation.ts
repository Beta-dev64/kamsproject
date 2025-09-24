import { z } from 'zod';
import { UserRole, AssessmentType, AssessmentStatus } from '../types';

// Common validation patterns
export const patterns = {
  email: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
  password: /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
  uuid: /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i,
  domain: /^[a-z0-9][a-z0-9-]*[a-z0-9]$/,
};

// Base schemas
export const uuidSchema = z.string().regex(patterns.uuid, 'Invalid UUID format');
export const emailSchema = z.string().email('Invalid email format');
export const domainSchema = z.string().regex(patterns.domain, 'Domain must contain only lowercase letters, numbers, and hyphens');

export const passwordSchema = z
  .string()
  .min(8, 'Password must be at least 8 characters long')
  .regex(patterns.password, 'Password must contain at least one lowercase letter, uppercase letter, number, and special character');

// Authentication schemas
export const registerSchema = z.object({
  email: emailSchema,
  password: passwordSchema,
  firstName: z.string().min(1, 'First name is required').max(100, 'First name too long'),
  lastName: z.string().min(1, 'Last name is required').max(100, 'Last name too long'),
  tenantDomain: domainSchema,
});

export const loginSchema = z.object({
  email: emailSchema,
  password: z.string().min(1, 'Password is required'),
  tenantDomain: domainSchema.optional(),
});

export const refreshTokenSchema = z.object({
  refreshToken: z.string().min(1, 'Refresh token is required'),
});

export const changePasswordSchema = z.object({
  currentPassword: z.string().min(1, 'Current password is required'),
  newPassword: passwordSchema,
  confirmPassword: z.string().min(1, 'Password confirmation is required'),
}).refine((data) => data.newPassword === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

export const forgotPasswordSchema = z.object({
  email: emailSchema,
  tenantDomain: domainSchema.optional(),
});

export const resetPasswordSchema = z.object({
  token: z.string().min(1, 'Reset token is required'),
  password: passwordSchema,
  confirmPassword: z.string().min(1, 'Password confirmation is required'),
}).refine((data) => data.password === data.confirmPassword, {
  message: 'Passwords do not match',
  path: ['confirmPassword'],
});

// User management schemas
export const createUserSchema = z.object({
  email: emailSchema,
  firstName: z.string().min(1, 'First name is required').max(100, 'First name too long'),
  lastName: z.string().min(1, 'Last name is required').max(100, 'Last name too long'),
  role: z.nativeEnum(UserRole, { errorMap: () => ({ message: 'Invalid role' }) }),
  department: z.string().max(100, 'Department name too long').optional(),
  managerId: uuidSchema.optional(),
  sendWelcomeEmail: z.boolean().optional().default(true),
});

export const updateUserSchema = z.object({
  firstName: z.string().min(1).max(100).optional(),
  lastName: z.string().min(1).max(100).optional(),
  role: z.nativeEnum(UserRole).optional(),
  department: z.string().max(100).optional(),
  managerId: uuidSchema.nullable().optional(),
  isActive: z.boolean().optional(),
});

export const updateProfileSchema = z.object({
  firstName: z.string().min(1, 'First name is required').max(100, 'First name too long'),
  lastName: z.string().min(1, 'Last name is required').max(100, 'Last name too long'),
  department: z.string().max(100, 'Department name too long').optional(),
});

// Tenant management schemas
export const createTenantSchema = z.object({
  name: z.string().min(1, 'Tenant name is required').max(255, 'Tenant name too long'),
  domain: domainSchema,
  subscriptionTier: z.enum(['basic', 'standard', 'premium', 'enterprise']).default('basic'),
  maxUsers: z.number().int().min(1).max(10000).default(100),
  adminUser: z.object({
    email: emailSchema,
    firstName: z.string().min(1).max(100),
    lastName: z.string().min(1).max(100),
    password: passwordSchema,
  }),
});

export const updateTenantSchema = z.object({
  name: z.string().min(1).max(255).optional(),
  subscriptionTier: z.enum(['basic', 'standard', 'premium', 'enterprise']).optional(),
  maxUsers: z.number().int().min(1).max(10000).optional(),
  isActive: z.boolean().optional(),
});

// Assessment schemas
export const createAssessmentQuestionSchema = z.object({
  category: z.string().min(1, 'Category is required').max(100, 'Category too long'),
  question: z.string().min(1, 'Question is required').max(1000, 'Question too long'),
  example: z.string().max(500, 'Example too long').optional(),
  weight: z.number().min(0.1).max(5).default(1),
  sortOrder: z.number().int().min(0).default(0),
});

export const updateAssessmentQuestionSchema = z.object({
  category: z.string().min(1).max(100).optional(),
  question: z.string().min(1).max(1000).optional(),
  example: z.string().max(500).optional(),
  weight: z.number().min(0.1).max(5).optional(),
  sortOrder: z.number().int().min(0).optional(),
  isActive: z.boolean().optional(),
});

export const createAssessmentSchema = z.object({
  employeeId: uuidSchema,
  assessmentType: z.nativeEnum(AssessmentType),
  assessmentDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/, 'Date must be in YYYY-MM-DD format'),
  quarter: z.string().regex(/^(Q[1-4]|H[12])\d{4}$/, 'Quarter must be in Q1YYYY or H1YYYY format').optional(),
  notes: z.string().max(1000, 'Notes too long').optional(),
});

export const updateAssessmentSchema = z.object({
  assessmentDate: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  quarter: z.string().regex(/^(Q[1-4]|H[12])\d{4}$/).optional(),
  status: z.nativeEnum(AssessmentStatus).optional(),
  notes: z.string().max(1000).optional(),
});

export const submitAssessmentScoresSchema = z.object({
  scores: z.array(z.object({
    questionId: uuidSchema,
    score: z.number().int().min(1).max(4),
    comments: z.string().max(500).optional(),
  })).min(1, 'At least one score is required'),
});

// Settings schemas
export const updateSettingsSchema = z.object({
  classificationThresholds: z.object({
    championMinTotal: z.number().min(0).max(100).optional(),
    championMinSelf: z.number().min(0).max(100).optional(),
    activistMinTotal: z.number().min(0).max(100).optional(),
    goGetterMinSelf: z.number().min(0).max(100).optional(),
  }).optional(),
  classificationLabels: z.object({
    champion: z.string().min(1).max(50).optional(),
    activist: z.string().min(1).max(50).optional(),
    paperTiger: z.string().min(1).max(50).optional(),
    goGetter: z.string().min(1).max(50).optional(),
  }).optional(),
  assessmentSettings: z.object({
    allowSelfAssessment: z.boolean().optional(),
    requireManagerApproval: z.boolean().optional(),
    maxAssessmentsPerQuarter: z.number().int().min(1).max(10).optional(),
    notificationEnabled: z.boolean().optional(),
  }).optional(),
  emailSettings: z.object({
    assessmentReminders: z.boolean().optional(),
    completionNotifications: z.boolean().optional(),
    weeklyReports: z.boolean().optional(),
  }).optional(),
});

// Pagination and filtering schemas
export const paginationSchema = z.object({
  page: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).pipe(z.number().int().min(1)).optional().default('1'),
  limit: z.string().regex(/^\d+$/).transform(val => parseInt(val, 10)).pipe(z.number().int().min(1).max(100)).optional().default('20'),
  sort: z.string().max(50).optional(),
  order: z.enum(['asc', 'desc']).optional().default('desc'),
});

export const userFilterSchema = paginationSchema.extend({
  role: z.nativeEnum(UserRole).optional(),
  department: z.string().max(100).optional(),
  isActive: z.enum(['true', 'false']).transform(val => val === 'true').optional(),
  search: z.string().max(100).optional(),
});

export const assessmentFilterSchema = paginationSchema.extend({
  employeeId: uuidSchema.optional(),
  assessorId: uuidSchema.optional(),
  assessmentType: z.nativeEnum(AssessmentType).optional(),
  status: z.nativeEnum(AssessmentStatus).optional(),
  dateFrom: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  dateTo: z.string().regex(/^\d{4}-\d{2}-\d{2}$/).optional(),
  quarter: z.string().regex(/^(Q[1-4]|H[12])\d{4}$/).optional(),
});

// File upload schemas
export const fileUploadSchema = z.object({
  filename: z.string().min(1, 'Filename is required').max(255, 'Filename too long'),
  mimeType: z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_]*\/[a-zA-Z0-9][a-zA-Z0-9!#$&\-\^_.]*$/, 'Invalid MIME type'),
  fileSize: z.number().int().min(1).max(10 * 1024 * 1024), // 10MB max
});

// Bulk operation schemas
export const bulkUserActionSchema = z.object({
  userIds: z.array(uuidSchema).min(1, 'At least one user ID is required').max(100, 'Too many users selected'),
  action: z.enum(['activate', 'deactivate', 'delete', 'export']),
});

export const bulkAssessmentActionSchema = z.object({
  assessmentIds: z.array(uuidSchema).min(1, 'At least one assessment ID is required').max(100, 'Too many assessments selected'),
  action: z.enum(['approve', 'reject', 'archive', 'export']),
});

// Export types for use in controllers
export type RegisterRequest = z.infer<typeof registerSchema>;
export type LoginRequest = z.infer<typeof loginSchema>;
export type CreateUserRequest = z.infer<typeof createUserSchema>;
export type UpdateUserRequest = z.infer<typeof updateUserSchema>;
export type CreateTenantRequest = z.infer<typeof createTenantSchema>;
export type UpdateTenantRequest = z.infer<typeof updateTenantSchema>;
export type CreateAssessmentRequest = z.infer<typeof createAssessmentSchema>;
export type UpdateAssessmentRequest = z.infer<typeof updateAssessmentSchema>;
export type SubmitAssessmentScoresRequest = z.infer<typeof submitAssessmentScoresSchema>;
export type UserFilterRequest = z.infer<typeof userFilterSchema>;
export type AssessmentFilterRequest = z.infer<typeof assessmentFilterSchema>;