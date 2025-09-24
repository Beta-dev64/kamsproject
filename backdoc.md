# Backend Development Guide - KAM Assessment Portal

## Table of Contents
1. [Product Overview](#product-overview)
2. [Technical Requirements](#technical-requirements)
3. [System Architecture](#system-architecture)
4. [Authentication & Authorization](#authentication--authorization)
5. [Database Design](#database-design)
6. [API Endpoints](#api-endpoints)
7. [Services Architecture](#services-architecture)
8. [Middleware Stack](#middleware-stack)
9. [Environment Configuration](#environment-configuration)
10. [Security Implementation](#security-implementation)
11. [Testing Strategy](#testing-strategy)
12. [Deployment & DevOps](#deployment--devops)
13. [Monitoring & Logging](#monitoring--logging)
14. [Performance Optimization](#performance-optimization)

## Product Overview

### Business Context
The KAM Assessment Portal is a multi-tenant SaaS platform designed to evaluate Key Account Managers (KAMs) across various competencies and classify them into performance categories. The system supports organizational hierarchies with role-based access control and comprehensive assessment workflows.

### Core Features
- **Multi-Tenant Architecture**: Complete tenant isolation with customizable settings
- **Assessment Engine**: Manager and self-assessment workflows with scoring algorithms
- **Classification System**: 4-quadrant performance classification (Champions, Activists, Paper Tigers, Go-getters)
- **User Management**: Role-based access with tenant admin and regular user roles
- **Analytics Dashboard**: Performance metrics and reporting capabilities
- **Settings Management**: Customizable thresholds, labels, and assessment questions

### Success Metrics
- Support 1000+ concurrent users per tenant
- 99.9% uptime SLA
- Sub-200ms API response times
- SOC 2 Type II compliance
- GDPR compliance for EU operations

## Technical Requirements

### Core Technology Stack
- **Runtime**: Node.js 18+ or Python 3.11+
- **Framework**: Express.js/Fastify or FastAPI/Django
- **Database**: PostgreSQL 15+ (primary), Redis (caching/sessions)
- **Authentication**: JWT + Refresh tokens
- **File Storage**: AWS S3 or Supabase Storage
- **Message Queue**: Redis Bull/BullMQ or AWS SQS
- **Search**: PostgreSQL Full-Text Search or Elasticsearch

### Performance Requirements
- **Response Time**: < 200ms for 95% of API calls
- **Throughput**: 10,000 requests/minute per instance
- **Concurrent Users**: 1,000+ per tenant
- **Database**: < 100ms query response time
- **File Upload**: Support up to 10MB files
- **Data Retention**: 7 years for audit compliance

### Scalability Requirements
- Horizontal scaling capability
- Auto-scaling based on load metrics
- Database connection pooling
- Caching strategy for frequently accessed data
- CDN integration for static assets

## System Architecture

### High-Level Architecture
```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │───▶│   API Gateway   │───▶│  Auth Service   │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│  Tenant Service │    │Assessment Service│    │ Settings Service│
└─────────────────┘    └─────────────────┘    └─────────────────┘
                              │
                              ▼
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   PostgreSQL    │    │     Redis       │    │   File Storage  │
└─────────────────┘    └─────────────────┘    └─────────────────┘
```

### Service Architecture Pattern
- **Modular Monolith**: Start with modular monolith, evolve to microservices
- **Domain-Driven Design**: Services organized by business domains
- **Event-Driven**: Async communication between services
- **CQRS Pattern**: Separate read/write operations for complex queries

## Authentication & Authorization

### Authentication Strategy
```typescript
interface AuthConfig {
  jwt: {
    accessTokenExpiry: '15m'
    refreshTokenExpiry: '7d'
    algorithm: 'RS256'
  }
  password: {
    minLength: 8
    requireSpecialChars: true
    requireNumbers: true
    requireUppercase: true
  }
  mfa: {
    enabled: true
    methods: ['totp', 'sms']
  }
}
```

### Authorization Model
```typescript
enum Role {
  SUPER_ADMIN = 'super_admin',
  TENANT_ADMIN = 'tenant_admin',
  MANAGER = 'manager',
  USER = 'user'
}

enum Permission {
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
  ASSESSMENT_READ_ALL = 'assessment:read_all', // Manager only
  
  // Settings Management
  SETTINGS_READ = 'settings:read',
  SETTINGS_UPDATE = 'settings:update'
}
```

### Security Flows

#### Authentication Flow
1. User submits credentials
2. System validates credentials + MFA
3. Generate access + refresh tokens
4. Return tokens with user profile
5. Client stores tokens securely

#### Authorization Flow
1. Extract JWT from request
2. Validate token signature + expiry
3. Extract user context (tenant_id, role, permissions)
4. Check resource access permissions
5. Apply tenant isolation filters

## Database Design

### Core Tables Schema

```sql
-- Tenants table
CREATE TABLE kam_tenants (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    subscription_tier VARCHAR(50) DEFAULT 'basic',
    max_users INTEGER DEFAULT 100,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Users/Profiles table
CREATE TABLE kam_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    department VARCHAR(100),
    manager_id UUID REFERENCES kam_profiles(id),
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,
    mfa_secret VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT false,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Assessment Questions table
CREATE TABLE kam_assessment_questions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    category VARCHAR(100) NOT NULL,
    question TEXT NOT NULL,
    example TEXT,
    weight DECIMAL(3,2) DEFAULT 1.00,
    is_active BOOLEAN DEFAULT true,
    created_by UUID REFERENCES kam_profiles(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Assessments table
CREATE TABLE kam_assessments (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    employee_id UUID REFERENCES kam_profiles(id) ON DELETE CASCADE,
    assessor_id UUID REFERENCES kam_profiles(id) ON DELETE CASCADE,
    assessment_type VARCHAR(20) NOT NULL CHECK (assessment_type IN ('manager', 'self')),
    assessment_date DATE NOT NULL,
    quarter VARCHAR(6),
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'completed')),
    notes TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Assessment Scores table
CREATE TABLE kam_assessment_scores (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    assessment_id UUID REFERENCES kam_assessments(id) ON DELETE CASCADE,
    question_id UUID REFERENCES kam_assessment_questions(id) ON DELETE CASCADE,
    score INTEGER NOT NULL CHECK (score BETWEEN 1 AND 4),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant Settings table
CREATE TABLE kam_tenant_settings (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    setting_key VARCHAR(100) NOT NULL,
    setting_value JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, setting_key)
);

-- Audit Log table
CREATE TABLE kam_audit_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    user_id UUID REFERENCES kam_profiles(id),
    action VARCHAR(100) NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id VARCHAR(255),
    old_values JSONB,
    new_values JSONB,
    ip_address INET,
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);
```

### Indexes and Performance
```sql
-- Tenant isolation indexes
CREATE INDEX idx_profiles_tenant_id ON kam_profiles(tenant_id);
CREATE INDEX idx_assessments_tenant_id ON kam_assessments(tenant_id);
CREATE INDEX idx_assessment_questions_tenant_id ON kam_assessment_questions(tenant_id);

-- Query performance indexes
CREATE INDEX idx_assessments_employee_date ON kam_assessments(employee_id, assessment_date DESC);
CREATE INDEX idx_profiles_email ON kam_profiles(email) WHERE deleted_at IS NULL;
CREATE INDEX idx_audit_logs_tenant_action ON kam_audit_logs(tenant_id, action, created_at DESC);

-- Full-text search
CREATE INDEX idx_assessment_questions_search ON kam_assessment_questions 
USING gin(to_tsvector('english', question || ' ' || COALESCE(example, '')));
```

## API Endpoints

### Authentication Endpoints
```typescript
// Authentication
POST   /api/v1/auth/register           // User registration
POST   /api/v1/auth/login              // User login
POST   /api/v1/auth/logout             // User logout
POST   /api/v1/auth/refresh            // Refresh access token
POST   /api/v1/auth/forgot-password    // Password reset request
POST   /api/v1/auth/reset-password     // Password reset confirmation
POST   /api/v1/auth/verify-email       // Email verification
POST   /api/v1/auth/resend-verification // Resend verification email

// MFA
POST   /api/v1/auth/mfa/setup          // Setup MFA
POST   /api/v1/auth/mfa/verify         // Verify MFA token
POST   /api/v1/auth/mfa/disable        // Disable MFA
```

### Tenant Management
```typescript
// Tenant CRUD
GET    /api/v1/tenants                 // List tenants (super admin only)
POST   /api/v1/tenants                 // Create tenant (super admin only)
GET    /api/v1/tenants/:id             // Get tenant details
PUT    /api/v1/tenants/:id             // Update tenant
DELETE /api/v1/tenants/:id             // Delete tenant (soft delete)

// Tenant Users
GET    /api/v1/tenants/:id/users       // List tenant users
POST   /api/v1/tenants/:id/users       // Invite user to tenant
PUT    /api/v1/tenants/:id/users/:userId // Update user role
DELETE /api/v1/tenants/:id/users/:userId // Remove user from tenant
```

### User Management
```typescript
// User Profile
GET    /api/v1/users/profile           // Get current user profile
PUT    /api/v1/users/profile           // Update user profile
POST   /api/v1/users/profile/avatar    // Upload profile avatar
PUT    /api/v1/users/profile/password  // Change password

// User Management (Admin)
GET    /api/v1/users                   // List users in tenant
POST   /api/v1/users                   // Create user
GET    /api/v1/users/:id               // Get user details
PUT    /api/v1/users/:id               // Update user
DELETE /api/v1/users/:id               // Delete user (soft delete)
POST   /api/v1/users/:id/activate      // Activate user
POST   /api/v1/users/:id/deactivate    // Deactivate user
```

### Assessment Management
```typescript
// Assessment Questions
GET    /api/v1/assessment-questions    // List questions
POST   /api/v1/assessment-questions    // Create question
GET    /api/v1/assessment-questions/:id // Get question
PUT    /api/v1/assessment-questions/:id // Update question
DELETE /api/v1/assessment-questions/:id // Delete question

// Assessments
GET    /api/v1/assessments             // List assessments (with filters)
POST   /api/v1/assessments             // Create assessment
GET    /api/v1/assessments/:id         // Get assessment details
PUT    /api/v1/assessments/:id         // Update assessment
DELETE /api/v1/assessments/:id         // Delete assessment
POST   /api/v1/assessments/:id/submit  // Submit assessment
POST   /api/v1/assessments/:id/scores  // Save assessment scores

// Assessment Analytics
GET    /api/v1/assessments/analytics/overview // Dashboard overview
GET    /api/v1/assessments/analytics/trends   // Performance trends
GET    /api/v1/assessments/analytics/classifications // Classification distribution
GET    /api/v1/assessments/analytics/export  // Export assessment data
```

### Settings Management
```typescript
// Tenant Settings
GET    /api/v1/settings                // Get all settings
PUT    /api/v1/settings                // Update settings (bulk)
GET    /api/v1/settings/:key           // Get specific setting
PUT    /api/v1/settings/:key           // Update specific setting

// Classification Settings
GET    /api/v1/settings/classifications // Get classification thresholds
PUT    /api/v1/settings/classifications // Update classification thresholds
```

## Services Architecture

### Core Services

#### 1. Authentication Service
```typescript
interface AuthService {
  // Authentication
  register(userData: RegisterDTO): Promise<AuthResponse>
  login(credentials: LoginDTO): Promise<AuthResponse>
  refreshToken(refreshToken: string): Promise<AuthResponse>
  logout(userId: string): Promise<void>
  
  // Password Management
  forgotPassword(email: string): Promise<void>
  resetPassword(token: string, newPassword: string): Promise<void>
  changePassword(userId: string, oldPassword: string, newPassword: string): Promise<void>
  
  // MFA
  setupMFA(userId: string): Promise<MFASetupResponse>
  verifyMFA(userId: string, token: string): Promise<boolean>
  disableMFA(userId: string, password: string): Promise<void>
}
```

#### 2. Tenant Service
```typescript
interface TenantService {
  // Tenant Management
  createTenant(tenantData: CreateTenantDTO): Promise<Tenant>
  getTenant(tenantId: string): Promise<Tenant>
  updateTenant(tenantId: string, updates: UpdateTenantDTO): Promise<Tenant>
  deleteTenant(tenantId: string): Promise<void>
  
  // User Management
  inviteUser(tenantId: string, userData: InviteUserDTO): Promise<User>
  removeUser(tenantId: string, userId: string): Promise<void>
  updateUserRole(tenantId: string, userId: string, role: Role): Promise<User>
  
  // Settings
  getTenantSettings(tenantId: string): Promise<TenantSettings>
  updateTenantSettings(tenantId: string, settings: Partial<TenantSettings>): Promise<TenantSettings>
}
```

#### 3. Assessment Service
```typescript
interface AssessmentService {
  // Question Management
  createQuestion(tenantId: string, questionData: CreateQuestionDTO): Promise<AssessmentQuestion>
  getQuestions(tenantId: string, filters?: QuestionFilters): Promise<AssessmentQuestion[]>
  updateQuestion(questionId: string, updates: UpdateQuestionDTO): Promise<AssessmentQuestion>
  deleteQuestion(questionId: string): Promise<void>
  
  // Assessment Management
  createAssessment(assessmentData: CreateAssessmentDTO): Promise<Assessment>
  getAssessments(tenantId: string, filters?: AssessmentFilters): Promise<Assessment[]>
  getAssessment(assessmentId: string): Promise<AssessmentWithScores>
  submitAssessment(assessmentId: string, scores: AssessmentScoreDTO[]): Promise<Assessment>
  
  // Analytics
  getAssessmentAnalytics(tenantId: string, filters?: AnalyticsFilters): Promise<AssessmentAnalytics>
  getPerformanceTrends(tenantId: string, filters?: TrendFilters): Promise<PerformanceTrend[]>
  exportAssessmentData(tenantId: string, format: 'csv' | 'xlsx'): Promise<Buffer>
}
```

#### 4. User Service
```typescript
interface UserService {
  // Profile Management
  getUserProfile(userId: string): Promise<UserProfile>
  updateUserProfile(userId: string, updates: UpdateProfileDTO): Promise<UserProfile>
  uploadAvatar(userId: string, file: File): Promise<string>
  
  // User Management
  createUser(tenantId: string, userData: CreateUserDTO): Promise<User>
  getUsers(tenantId: string, filters?: UserFilters): Promise<User[]>
  updateUser(userId: string, updates: UpdateUserDTO): Promise<User>
  deactivateUser(userId: string): Promise<void>
  activateUser(userId: string): Promise<void>
}
```

#### 5. Notification Service
```typescript
interface NotificationService {
  // Email Notifications
  sendWelcomeEmail(user: User, tempPassword: string): Promise<void>
  sendPasswordResetEmail(user: User, resetToken: string): Promise<void>
  sendAssessmentReminder(user: User, assessment: Assessment): Promise<void>
  sendAssessmentCompleted(manager: User, assessment: Assessment): Promise<void>
  
  // In-App Notifications
  createNotification(userId: string, notification: CreateNotificationDTO): Promise<Notification>
  getUserNotifications(userId: string): Promise<Notification[]>
  markNotificationRead(notificationId: string): Promise<void>
}
```

## Middleware Stack

### 1. Request Logging Middleware
```typescript
const requestLogger = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now()
  const requestId = uuidv4()
  
  req.requestId = requestId
  
  logger.info('Request started', {
    requestId,
    method: req.method,
    url: req.url,
    userAgent: req.get('User-Agent'),
    ip: req.ip
  })
  
  res.on('finish', () => {
    const duration = Date.now() - start
    logger.info('Request completed', {
      requestId,
      statusCode: res.statusCode,
      duration
    })
  })
  
  next()
}
```

### 2. Authentication Middleware
```typescript
const authenticate = async (req: Request, res: Response, next: NextFunction) => {
  try {
    const token = extractTokenFromHeader(req.headers.authorization)
    if (!token) {
      return res.status(401).json({ error: 'Authentication required' })
    }
    
    const payload = await verifyJWT(token)
    const user = await getUserById(payload.userId)
    
    if (!user || !user.isActive) {
      return res.status(401).json({ error: 'Invalid or inactive user' })
    }
    
    req.user = user
    req.tenantId = user.tenantId
    next()
  } catch (error) {
    return res status(401).json({ error: 'Invalid token' })
  }
}
```

### 3. Authorization Middleware
```typescript
const authorize = (requiredPermission: Permission) => {
  return async (req: Request, res: Response, next: NextFunction) => {
    const user = req.user
    const hasPermission = await checkUserPermission(user.id, requiredPermission)
    
    if (!hasPermission) {
      return res.status(403).json({ error: 'Insufficient permissions' })
    }
    
    next()
  }
}
```

### 4. Tenant Isolation Middleware
```typescript
const tenantIsolation = (req: Request, res: Response, next: NextFunction) => {
  // Ensure all database queries are filtered by tenant_id
  req.dbContext = {
    tenantId: req.tenantId,
    userId: req.user?.id
  }
  next()
}
```

### 5. Rate Limiting Middleware
```typescript
const createRateLimit = (windowMs: number, max: number) => {
  return rateLimit({
    windowMs,
    max,
    keyGenerator: (req) => `${req.ip}:${req.tenantId}`,
    message: 'Too many requests from this IP and tenant'
  })
}

// Different limits for different endpoints
const authRateLimit = createRateLimit(15 * 60 * 1000, 5) // 5 attempts per 15 minutes
const apiRateLimit = createRateLimit(60 * 1000, 100) // 100 requests per minute
```

### 6. Error Handling Middleware
```typescript
const errorHandler = (error: Error, req: Request, res: Response, next: NextFunction) => {
  logger.error('Unhandled error', {
    error: error.message,
    stack: error.stack,
    requestId: req.requestId,
    url: req.url,
    method: req.method
  })
  
  if (error instanceof ValidationError) {
    return res.status(400).json({ error: 'Validation failed', details: error.details })
  }
  
  if (error instanceof NotFoundError) {
    return res.status(404).json({ error: 'Resource not found' })
  }
  
  if (error instanceof UnauthorizedError) {
    return res.status(401).json({ error: 'Unauthorized' })
  }
  
  // Default to 500 server error
  res.status(500).json({ error: 'Internal server error' })
}
```

## Environment Configuration

### Environment Separation
```yaml
# development.env
NODE_ENV=development
PORT=3000
DATABASE_URL=postgresql://user:pass@localhost:5432/kam_dev
REDIS_URL=redis://localhost:6379
JWT_SECRET=dev-secret-key
LOG_LEVEL=debug
CORS_ORIGINS=http://localhost:5173

# test.env
NODE_ENV=test
PORT=3001
DATABASE_URL=postgresql://user:pass@localhost:5432/kam_test
REDIS_URL=redis://localhost:6379/1
JWT_SECRET=test-secret-key
LOG_LEVEL=warn

# production.env
NODE_ENV=production
PORT=8080
DATABASE_URL=${DATABASE_URL}
REDIS_URL=${REDIS_URL}
JWT_SECRET=${JWT_SECRET}
JWT_PRIVATE_KEY=${JWT_PRIVATE_KEY}
JWT_PUBLIC_KEY=${JWT_PUBLIC_KEY}
LOG_LEVEL=info
CORS_ORIGINS=${ALLOWED_ORIGINS}

# Email Configuration
SMTP_HOST=${SMTP_HOST}
SMTP_PORT=${SMTP_PORT}
SMTP_USER=${SMTP_USER}
SMTP_PASS=${SMTP_PASS}

# File Storage
AWS_ACCESS_KEY_ID=${AWS_ACCESS_KEY_ID}
AWS_SECRET_ACCESS_KEY=${AWS_SECRET_ACCESS_KEY}
AWS_S3_BUCKET=${AWS_S3_BUCKET}
AWS_S3_REGION=${AWS_S3_REGION}

# Monitoring
SENTRY_DSN=${SENTRY_DSN}
DATADOG_API_KEY=${DATADOG_API_KEY}
```

### Configuration Management
```typescript
interface Config {
  app: {
    name: string
    version: string
    port: number
    env: 'development' | 'test' | 'production'
  }
  database: {
    url: string
    poolSize: number
    ssl: boolean
  }
  redis: {
    url: string
    ttl: number
  }
  jwt: {
    secret: string
    privateKey: string
    publicKey: string
    accessTokenExpiry: string
    refreshTokenExpiry: string
  }
  email: {
    host: string
    port: number
    user: string
    pass: string
    from: string
  }
  storage: {
    type: 'local' | 's3'
    bucket?: string
    region?: string
    accessKey?: string
    secretKey?: string
  }
}

const config: Config = {
  app: {
    name: process.env.APP_NAME || 'KAM Assessment Portal',
    version: process.env.APP_VERSION || '1.0.0',
    port: parseInt(process.env.PORT || '3000'),
    env: (process.env.NODE_ENV as Config['app']['env']) || 'development'
  }
  // ... rest of configuration
}
```

## Security Implementation

### 1. Input Validation & Sanitization
```typescript
// Request validation schemas
const createAssessmentSchema = z.object({
  employeeId: z.string().uuid(),
  assessmentType: z.enum(['manager', 'self']),
  assessmentDate: z.string().date(),
  questions: z.array(z.object({
    questionId: z.string().uuid(),
    score: z.number().min(1).max(4)
  }))
})

// Validation middleware
const validateRequest = (schema: z.ZodSchema) => {
  return (req: Request, res: Response, next: NextFunction) => {
    try {
      schema.parse(req.body)
      next()
    } catch (error) {
      res.status(400).json({ error: 'Invalid request data', details: error.errors })
    }
  }
}
```

### 2. SQL Injection Prevention
```typescript
// Always use parameterized queries
const getUserByEmail = async (email: string, tenantId: string) => {
  const query = `
    SELECT * FROM kam_profiles 
    WHERE email = $1 AND tenant_id = $2 AND deleted_at IS NULL
  `
  return db.one(query, [email, tenantId])
}

// Use query builders with proper escaping
const getAssessments = async (filters: AssessmentFilters) => {
  let query = db('kam_assessments')
    .select('*')
    .where('tenant_id', filters.tenantId)
  
  if (filters.employeeId) {
    query = query.where('employee_id', filters.employeeId)
  }
  
  return query
}
```

### 3. XSS Prevention
```typescript
// Content Security Policy
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'"],
      fontSrc: ["'self'"],
      objectSrc: ["'none'"],
      mediaSrc: ["'self'"],
      frameSrc: ["'none'"]
    }
  }
}))

// Input sanitization
const sanitizeInput = (input: string): string => {
  return DOMPurify.sanitize(input, { ALLOWED_TAGS: [] })
}
```

### 4. CSRF Protection
```typescript
// CSRF middleware
app.use(csrf({
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'strict'
  }
}))

// CSRF token endpoint
app.get('/api/v1/csrf-token', (req, res) => {
  res.json({ csrfToken: req.csrfToken() })
})
```

### 5. Data Encryption
```typescript
// Encrypt sensitive data at rest
const encryptSensitiveData = (data: string): string => {
  const cipher = crypto.createCipher('aes-256-gcm', process.env.ENCRYPTION_KEY)
  let encrypted = cipher.update(data, 'utf8', 'hex')
  encrypted += cipher.final('hex')
  return encrypted
}

// Decrypt sensitive data
const decryptSensitiveData = (encryptedData: string): string => {
  const decipher = crypto.createDecipher('aes-256-gcm', process.env.ENCRYPTION_KEY)
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8')
  decrypted += decipher.final('utf8')
  return decrypted
}
```

## Testing Strategy

### 1. Unit Tests
```typescript
// Service layer unit tests
describe('AssessmentService', () => {
  describe('createAssessment', () => {
    it('should create assessment with valid data', async () => {
      const assessmentData = {
        employeeId: 'user-id',
        assessmentType: 'manager',
        assessmentDate: '2024-01-15'
      }
      
      const result = await assessmentService.createAssessment(assessmentData)
      
      expect(result).toHaveProperty('id')
      expect(result.employeeId).toBe(assessmentData.employeeId)
    })
    
    it('should throw error for invalid employee ID', async () => {
      const assessmentData = {
        employeeId: 'invalid-id',
        assessmentType: 'manager',
        assessmentDate: '2024-01-15'
      }
      
      await expect(assessmentService.createAssessment(assessmentData))
        .rejects.toThrow('User not found')
    })
  })
})
```

### 2. Integration Tests
```typescript
// API endpoint integration tests
describe('POST /api/v1/assessments', () => {
  it('should create assessment for authenticated user', async () => {
    const token = await getAuthToken('manager@example.com')
    
    const response = await request(app)
      .post('/api/v1/assessments')
      .set('Authorization', `Bearer ${token}`)
      .send({
        employeeId: testUser.id,
        assessmentType: 'manager',
        assessmentDate: '2024-01-15'
      })
    
    expect(response.status).toBe(201)
    expect(response.body).toHaveProperty('id')
  })
  
  it('should reject unauthenticated requests', async () => {
    const response = await request(app)
      .post('/api/v1/assessments')
      .send({})
    
    expect(response.status).toBe(401)
  })
})
```

### 3. Database Tests
```typescript
// Database layer tests
describe('Database Operations', () => {
  beforeEach(async () => {
    await resetDatabase()
    await seedTestData()
  })
  
  it('should enforce tenant isolation', async () => {
    const tenant1User = await createTestUser('tenant1')
    const tenant2User = await createTestUser('tenant2')
    
    const assessments = await getAssessments(tenant1User.tenantId)
    
    expect(assessments).not.toContainEqual(
      expect.objectContaining({ tenant_id: tenant2User.tenantId })
    )
  })
})
```

### 4. Performance Tests
```typescript
// Load testing with Artillery or k6
import http from 'k6/http'
import { check } from 'k6'

export let options = {
  vus: 100, // 100 virtual users
  duration: '5m'
}

export default function() {
  let response = http.get('http://localhost:3000/api/v1/assessments')
  
  check(response, {
    'status is 200': (r) => r.status === 200,
    'response time < 200ms': (r) => r.timings.duration < 200
  })
}
```

## Deployment & DevOps

### 1. Docker Configuration
```dockerfile
# Dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production

FROM node:18-alpine AS runtime

RUN addgroup -g 1001 -S nodejs
RUN adduser -S nodejs -u 1001

WORKDIR /app

COPY --from=builder /app/node_modules ./node_modules
COPY . .

USER nodejs

EXPOSE 3000

CMD ["npm", "start"]
```

### 2. CI/CD Pipeline
```yaml
# .github/workflows/deploy.yml
name: Deploy to Production

on:
  push:
    branches: [main]

jobs:
  test:
    runs-on: ubuntu-latest
    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_PASSWORD: postgres
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
    
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Run tests
        run: npm test
        env:
          DATABASE_URL: postgresql://postgres:postgres@localhost:5432/postgres
      
      - name: Run security audit
        run: npm audit --audit-level moderate

  deploy:
    needs: test
    runs-on: ubuntu-latest
    if: github.ref == 'refs/heads/main'
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Deploy to production
        run: |
          # Deploy to production environment
          # This could be AWS ECS, Kubernetes, etc.
```

### 3. Infrastructure as Code
```yaml
# docker-compose.yml for local development
version: '3.8'
services:
  app:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=development
      - DATABASE_URL=postgresql://postgres:postgres@db:5432/kam_dev
      - REDIS_URL=redis://redis:6379
    depends_on:
      - db
      - redis
  
  db:
    image: postgres:15
    environment:
      - POSTGRES_DB=kam_dev
      - POSTGRES_USER=postgres
      - POSTGRES_PASSWORD=postgres
    volumes:
      - postgres_data:/var/lib/postgresql/data
    ports:
      - "5432:5432"
  
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

volumes:
  postgres_data:
```

## Monitoring & Logging

### 1. Application Logging
```typescript
// Structured logging with Winston
import winston from 'winston'

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: winston.format.combine(
    winston.format.timestamp(),
    winston.format.errors({ stack: true }),
    winston.format.json()
  ),
  defaultMeta: { service: 'kam-assessment-api' },
  transports: [
    new winston.transports.File({ filename: 'error.log', level: 'error' }),
    new winston.transports.File({ filename: 'combined.log' }),
    new winston.transports.Console({
      format: winston.format.simple()
    })
  ]
})

// Usage
logger.info('User created', { userId, tenantId, email })
logger.error('Database connection failed', { error: error.message })
```

### 2. Health Checks
```typescript
// Health check endpoints
app.get('/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: process.env.APP_VERSION
  })
})

app.get('/health/db', async (req, res) => {
  try {
    await db.raw('SELECT 1')
    res.json({ status: 'healthy', service: 'database' })
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', service: 'database' })
  }
})

app.get('/health/redis', async (req, res) => {
  try {
    await redis.ping()
    res.json({ status: 'healthy', service: 'redis' })
  } catch (error) {
    res.status(503).json({ status: 'unhealthy', service: 'redis' })
  }
})
```

### 3. Metrics Collection
```typescript
// Prometheus metrics
import prometheus from 'prom-client'

const httpRequestDuration = new prometheus.Histogram({
  name: 'http_request_duration_seconds',
  help: 'Duration of HTTP requests in seconds',
  labelNames: ['method', 'route', 'status']
})

const activeConnections = new prometheus.Gauge({
  name: 'active_connections_total',
  help: 'Total number of active connections'
})

// Middleware to collect metrics
const metricsMiddleware = (req: Request, res: Response, next: NextFunction) => {
  const start = Date.now()
  
  res.on('finish', () => {
    const duration = (Date.now() - start) / 1000
    httpRequestDuration
      .labels(req.method, req.route?.path || req.path, res.statusCode.toString())
      .observe(duration)
  })
  
  next()
}
```

## Performance Optimization

### 1. Database Optimization
```typescript
// Connection pooling
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 20, // Maximum number of connections
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000
})

// Query optimization
const getAssessmentsOptimized = async (tenantId: string, filters: AssessmentFilters) => {
  // Use indexes effectively
  let query = `
    SELECT a.*, p.first_name, p.last_name, p.email
    FROM kam_assessments a
    JOIN kam_profiles p ON a.employee_id = p.id
    WHERE a.tenant_id = $1
  `
  
  const params = [tenantId]
  let paramIndex = 2
  
  if (filters.employeeId) {
    query += ` AND a.employee_id = $${paramIndex++}`
    params.push(filters.employeeId)
  }
  
  if (filters.dateFrom) {
    query += ` AND a.assessment_date >= $${paramIndex++}`
    params.push(filters.dateFrom)
  }
  
  // Add proper ordering and pagination
  query += ` ORDER BY a.assessment_date DESC LIMIT $${paramIndex++} OFFSET $${paramIndex++}`
  params.push(filters.limit || 50, filters.offset || 0)
  
  return db.many(query, params)
}
```

### 2. Caching Strategy
```typescript
// Redis caching
const cacheService = {
  async get<T>(key: string): Promise<T | null> {
    const cached = await redis.get(key)
    return cached ? JSON.parse(cached) : null
  },
  
  async set(key: string, value: any, ttlSeconds: number = 3600): Promise<void> {
    await redis.setex(key, ttlSeconds, JSON.stringify(value))
  },
  
  async del(key: string): Promise<void> {
    await redis.del(key)
  },
  
  async invalidatePattern(pattern: string): Promise<void> {
    const keys = await redis.keys(pattern)
    if (keys.length > 0) {
      await redis.del(...keys)
    }
  }
}

// Cache frequently accessed data
const getTenantSettings = async (tenantId: string): Promise<TenantSettings> => {
  const cacheKey = `tenant:${tenantId}:settings`
  
  let settings = await cacheService.get<TenantSettings>(cacheKey)
  if (!settings) {
    settings = await db.getTenantSettings(tenantId)
    await cacheService.set(cacheKey, settings, 1800) // 30 minutes
  }
  
  return settings
}
```

### 3. API Response Optimization
```typescript
// Response compression
app.use(compression({
  filter: (req, res) => {
    if (req.headers['x-no-compression']) {
      return false
    }
    return compression.filter(req, res)
  },
  threshold: 1024 // Only compress responses larger than 1KB
}))

// Pagination helpers
interface PaginationOptions {
  page: number
  limit: number
  sort?: string
  order?: 'asc' | 'desc'
}

const paginate = <T>(
  query: any,
  options: PaginationOptions
): Promise<{ data: T[], total: number, pages: number }> => {
  const offset = (options.page - 1) * options.limit
  
  return Promise.all([
    query.clone().offset(offset).limit(options.limit),
    query.clone().count('* as count').first()
  ]).then(([data, { count }]) => ({
    data,
    total: parseInt(count),
    pages: Math.ceil(count / options.limit)
  }))
}
```

---

## Maintenance Notes

This document should be updated whenever:
- New API endpoints are added or modified
- Database schema changes occur
- New security requirements are identified
- Performance optimizations are implemented
- New services or middleware are introduced
- Environment configuration changes

**Last Updated:** [Current Date]
**Version:** 1.0.0
**Reviewed By:** [Backend Team Lead]

---

## Quick Start Guide

1. **Setup Development Environment**
   ```bash
   git clone <repository>
   cd kam-assessment-backend
   npm install
   cp .env.example .env.development
   docker-compose up -d
   npm run migrate
   npm run seed
   npm run dev
   ```

2. **Run Tests**
   ```bash
   npm test
   npm run test:coverage
   npm run test:e2e
   ```

3. **Database Operations**
   ```bash
   npm run migrate
   npm run migrate:rollback
   npm run seed
   npm run db:reset
   ```

4. **Production Deployment**
   ```bash
   npm run build
   npm run start:prod
   ```