# KAM Assessment Portal API Documentation

## Base URL
```
http://localhost:3000/api/v1
```

## Authentication Flow

All API requests (except public auth endpoints) require authentication headers:
- **Authorization**: `Bearer <access_token>`
- **X-Tenant-Domain**: `<tenant_domain>` (for API access when not using subdomain)

---

## 🔐 **Phase 1: Authentication & Setup**

### 1.1 Health Check (Optional)
**GET** `/health`
```bash
curl -X GET http://localhost:3000/health
```
**Response:**
```json
{
  "status": "healthy",
  "timestamp": "2024-01-16T10:00:00.000Z",
  "version": "1.0.0",
  "environment": "development",
  "uptime": 3600
}
```

### 1.2 User Registration
**POST** `/api/v1/auth/register`

**Headers:**
- `Content-Type: application/json`
- `X-Tenant-Domain: acme-corp` (use existing tenant from seed data)

**Request Body:**
```json
{
  "email": "john.smith@acme-corp.com",
  "password": "SecurePassword123!",
  "firstName": "John",
  "lastName": "Smith",
  "tenantDomain": "acme-corp"
}
```

**Response:**
```json
{
  "success": true,
  "message": "User registered successfully",
  "data": {
    "user": {
      "id": "uuid",
      "email": "john.smith@acme-corp.com",
      "firstName": "John",
      "lastName": "Smith",
      "role": "user",
      "isActive": true,
      "emailVerified": false
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
    "expiresIn": 900
  }
}
```

### 1.3 User Login
**POST** `/api/v1/auth/login`

**Headers:**
- `Content-Type: application/json`
- `X-Tenant-Domain: acme-corp`

**Request Body:**
```json
{
  "email": "admin@acme-corp.com",
  "password": "Admin123!@#",
  "tenantDomain": "acme-corp"
}
```

**Response:**
```json
{
  "success": true,
  "message": "Login successful",
  "data": {
    "user": {
      "id": "uuid",
      "email": "admin@acme-corp.com",
      "firstName": "Admin",
      "lastName": "User",
      "role": "admin",
      "tenantId": "tenant-uuid"
    },
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "refreshToken": "eyJhbGciOiJIUzI1NiIs...",
    "expiresIn": 900
  }
}
```

### 1.4 Get Current User Profile
**GET** `/api/v1/auth/me`

**Headers:**
- `Authorization: Bearer <access_token>`
- `X-Tenant-Domain: acme-corp`

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "uuid",
    "email": "admin@acme-corp.com",
    "firstName": "Admin",
    "lastName": "User",
    "role": "admin",
    "department": "Management",
    "tenantId": "tenant-uuid",
    "isActive": true,
    "emailVerified": true
  }
}
```

---

## 🏢 **Phase 2: Tenant Management**

### 2.1 Get Current Tenant Information
**GET** `/api/v1/tenants/current`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "tenant-uuid",
    "name": "Acme Corporation",
    "domain": "acme-corp",
    "subscriptionTier": "basic",
    "maxUsers": 100,
    "isActive": true,
    "settings": {
      "assessmentSettings": {},
      "emailSettings": {},
      "securitySettings": {}
    }
  }
}
```

### 2.2 Get Tenant Settings
**GET** `/api/v1/tenants/settings`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`

### 2.3 Update Tenant Settings
**PUT** `/api/v1/tenants/settings`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "assessmentSettings": {
    "requireManagerApproval": true,
    "allowSelfAssessment": true,
    "scoringMethod": "weighted"
  },
  "emailSettings": {
    "notificationsEnabled": true,
    "reminderFrequency": "weekly"
  }
}
```

---

## 👥 **Phase 3: User Management**

### 3.1 Get Users List
**GET** `/api/v1/users`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`

**Query Parameters:**
- `page=1`
- `limit=20`
- `role=user`
- `department=Sales`

**Response:**
```json
{
  "success": true,
  "data": {
    "users": [
      {
        "id": "user-uuid",
        "email": "mike.user@acme-corp.com",
        "firstName": "Mike",
        "lastName": "User",
        "role": "user",
        "department": "Sales",
        "isActive": true
      }
    ],
    "pagination": {
      "page": 1,
      "limit": 20,
      "total": 4,
      "pages": 1
    }
  }
}
```

### 3.2 Create New User
**POST** `/api/v1/users`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "email": "jane.doe@acme-corp.com",
  "firstName": "Jane",
  "lastName": "Doe",
  "role": "manager",
  "department": "Marketing",
  "password": "TempPassword123!",
  "managerId": "manager-uuid"
}
```

### 3.3 Get User by ID
**GET** `/api/v1/users/{userId}`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`

### 3.4 Update User Profile
**PUT** `/api/v1/users/profile`

**Headers:**
- `Authorization: Bearer <user_token>`
- `X-Tenant-Domain: acme-corp`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "firstName": "John",
  "lastName": "Smith Updated",
  "department": "Sales",
  "bio": "Updated bio information"
}
```

---

## ❓ **Phase 4: Questions Management**

### 4.1 Create Assessment Question
**POST** `/api/v1/assessments/questions`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "category": "Customer Focus",
  "question": "How effectively does the employee understand and address customer needs?",
  "example": "Examples: Active listening, asking clarifying questions, providing tailored solutions",
  "weight": 2.0,
  "sortOrder": 1
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "question-uuid",
    "category": "Customer Focus",
    "question": "How effectively does the employee understand and address customer needs?",
    "example": "Examples: Active listening, asking clarifying questions, providing tailored solutions",
    "weight": 2.0,
    "sortOrder": 1,
    "isActive": true,
    "tenantId": "tenant-uuid",
    "createdBy": "admin-uuid"
  }
}
```

### 4.2 Get All Questions
**GET** `/api/v1/assessments/questions`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Query Parameters:**
- `page=1`
- `limit=50`
- `category=Customer Focus`
- `isActive=true`

### 4.3 Get Active Questions Only
**GET** `/api/v1/assessments/questions/active`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": "question-uuid",
      "category": "Customer Focus",
      "question": "How effectively does the employee understand and address customer needs?",
      "example": "Examples: Active listening, asking clarifying questions",
      "weight": 2.0,
      "sortOrder": 1
    }
  ]
}
```

### 4.4 Bulk Create Questions
**POST** `/api/v1/assessments/questions/bulk`

**Headers:**
- `Authorization: Bearer <admin_token>`
- `X-Tenant-Domain: acme-corp`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "questions": [
    {
      "category": "Communication",
      "question": "How clearly does the employee communicate with team members?",
      "weight": 1.5,
      "sortOrder": 2
    },
    {
      "category": "Problem Solving",
      "question": "How effectively does the employee identify and solve problems?",
      "weight": 1.8,
      "sortOrder": 3
    }
  ]
}
```

---

## 📋 **Phase 5: Assessment Management**

### 5.1 Create New Assessment
**POST** `/api/v1/assessments`

**Headers:**
- `Authorization: Bearer <manager_token>`
- `X-Tenant-Domain: acme-corp`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "employeeId": "employee-uuid",
  "assessmentType": "manager",
  "assessmentDate": "2024-01-15T10:00:00.000Z",
  "quarter": "Q1",
  "year": 2024,
  "notes": "Regular quarterly assessment"
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "id": "assessment-uuid",
    "employeeId": "employee-uuid",
    "assessorId": "manager-uuid",
    "assessmentType": "manager",
    "status": "draft",
    "assessmentDate": "2024-01-15T10:00:00.000Z",
    "quarter": "Q1",
    "year": 2024,
    "notes": "Regular quarterly assessment",
    "tenantId": "tenant-uuid",
    "createdAt": "2024-01-16T10:00:00.000Z"
  }
}
```

### 5.2 Get All Assessments
**GET** `/api/v1/assessments`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Query Parameters:**
- `page=1`
- `limit=20`
- `status=draft`
- `assessmentType=manager`
- `employeeId=uuid`
- `year=2024`
- `quarter=Q1`

### 5.3 Get Assessment by ID
**GET** `/api/v1/assessments/{assessmentId}`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

### 5.4 Get Assessment Progress
**GET** `/api/v1/assessments/{assessmentId}/progress`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Response:**
```json
{
  "success": true,
  "data": {
    "assessmentId": "assessment-uuid",
    "totalQuestions": 8,
    "answeredQuestions": 3,
    "progressPercentage": 37.5,
    "status": "draft",
    "lastUpdated": "2024-01-16T10:00:00.000Z"
  }
}
```

---

## 📊 **Phase 6: Assessment Scoring**

### 6.1 Submit Assessment Scores
**POST** `/api/v1/assessments/{assessmentId}/scores`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`
- `Content-Type: application/json`

**Request Body:**
```json
{
  "scores": [
    {
      "questionId": "question-uuid-1",
      "score": 4,
      "comments": "Excellent customer focus, always goes above and beyond"
    },
    {
      "questionId": "question-uuid-2",
      "score": 3,
      "comments": "Good communication skills, could improve on written communication"
    },
    {
      "questionId": "question-uuid-3",
      "score": 4,
      "comments": "Outstanding problem-solving abilities"
    }
  ]
}
```

**Response:**
```json
{
  "success": true,
  "message": "Assessment scores submitted successfully",
  "data": {
    "assessmentId": "assessment-uuid",
    "totalScore": 85.5,
    "maxScore": 100,
    "classification": "Champion",
    "submittedAt": "2024-01-16T10:00:00.000Z",
    "scoreSummary": {
      "Customer Focus": 4.0,
      "Communication": 3.0,
      "Problem Solving": 4.0
    }
  }
}
```

### 6.2 Get Assessment Scores
**GET** `/api/v1/assessments/{assessmentId}/scores`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Response:**
```json
{
  "success": true,
  "data": {
    "assessmentId": "assessment-uuid",
    "scores": [
      {
        "questionId": "question-uuid-1",
        "category": "Customer Focus",
        "question": "How effectively does the employee understand customer needs?",
        "score": 4,
        "comments": "Excellent customer focus",
        "weight": 2.0
      }
    ],
    "totalScore": 85.5,
    "classification": "Champion"
  }
}
```

---

## 📈 **Phase 7: Analytics & Reporting**

### 7.1 Get Dashboard Stats
**GET** `/api/v1/assessments/dashboard/stats`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Response:**
```json
{
  "success": true,
  "data": {
    "totalAssessments": 25,
    "completedAssessments": 18,
    "pendingAssessments": 7,
    "averageScore": 82.3,
    "topPerformers": 5,
    "recentActivity": {
      "assessmentsThisWeek": 3,
      "assessmentsThisMonth": 12
    }
  }
}
```

### 7.2 Get Assessment Analytics Overview
**GET** `/api/v1/assessments/analytics/overview`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Query Parameters:**
- `year=2024`
- `quarter=Q1`
- `employeeId=uuid` (optional)
- `departmentFilter=Sales` (optional)

**Response:**
```json
{
  "success": true,
  "data": {
    "totalAssessments": 10,
    "completedAssessments": 8,
    "averageScore": 85.5,
    "classificationDistribution": {
      "Champion": 3,
      "Activist": 2,
      "Paper Tiger": 2,
      "Go-getter": 1
    },
    "scoresByCategory": {
      "Customer Focus": {
        "average": 4.2,
        "count": 10
      },
      "Communication": {
        "average": 3.8,
        "count": 10
      }
    },
    "trendData": [
      {
        "period": "2024-Q1",
        "averageScore": 85.0,
        "assessmentCount": 5
      }
    ]
  }
}
```

### 7.3 Get Question Analytics
**GET** `/api/v1/assessments/analytics/questions`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "questionId": "question-uuid",
      "category": "Customer Focus",
      "question": "How effectively does the employee understand customer needs?",
      "averageScore": 3.8,
      "responseCount": 25,
      "scoreDistribution": {
        "1": 1,
        "2": 3,
        "3": 12,
        "4": 9
      }
    }
  ]
}
```

---

## 🔧 **Phase 8: Token Management**

### 8.1 Refresh Access Token
**POST** `/api/v1/auth/refresh`

**Headers:**
- `Content-Type: application/json`

**Request Body:**
```json
{
  "refreshToken": "eyJhbGciOiJIUzI1NiIs..."
}
```

**Response:**
```json
{
  "success": true,
  "data": {
    "accessToken": "eyJhbGciOiJIUzI1NiIs...",
    "expiresIn": 900
  }
}
```

### 8.2 Get Active Sessions
**GET** `/api/v1/auth/sessions`

**Headers:**
- `Authorization: Bearer <token>`
- `X-Tenant-Domain: acme-corp`

### 8.3 Logout (Single Session)
**POST** `/api/v1/auth/logout`

**Headers:**
- `Authorization: Bearer <token>`

### 8.4 Logout All Sessions
**POST** `/api/v1/auth/logout-all`

**Headers:**
- `Authorization: Bearer <token>`

---

## 🚀 **Complete API Testing Flow**

Here's the recommended order to test all APIs:

1. **Start Server**: `yarn start`
2. **Health Check**: Test `/health` endpoint
3. **Login**: Use seeded admin user (`admin@acme-corp.com` / `Admin123!@#`)
4. **Get Profile**: Verify authentication with `/auth/me`
5. **Tenant Info**: Get current tenant with `/tenants/current`
6. **Users**: List and manage users
7. **Questions**: Create and manage assessment questions
8. **Assessments**: Create new assessments
9. **Scoring**: Submit scores for assessments
10. **Analytics**: View dashboard stats and analytics
11. **Token Refresh**: Test token refresh mechanism

---

## 📋 **Sample Seeded Data**

The database is seeded with the following test data:

### Tenants:
- **acme-corp** (Acme Corporation)
- **techstart** (TechStart Inc)

### Users for acme-corp:
- **admin@acme-corp.com** / `Admin123!@#` (admin)
- **sarah.manager@acme-corp.com** / `Manager123!@#` (manager)
- **mike.user@acme-corp.com** / `User123!@#` (user)
- **lisa.user@acme-corp.com** / `User123!@#` (user)

### Pre-created Questions:
- Customer Focus
- Communication
- Problem Solving
- Leadership
- Teamwork
- Innovation
- Adaptability
- Results Orientation

---

## ⚠️ **Important Notes**

1. **Rate Limiting**: Most endpoints have rate limiting. Wait between requests if you hit limits.
2. **Tenant Isolation**: Always include `X-Tenant-Domain` header for API access.
3. **Authentication**: Most endpoints require valid JWT tokens.
4. **Permissions**: Different endpoints require different user roles (admin, manager, user).
5. **Data Validation**: All inputs are validated. Check error messages for validation details.

---

## 🔍 **Error Responses**

All endpoints return errors in this format:
```json
{
  "success": false,
  "message": "Error description",
  "error": "ERROR_CODE",
  "details": {
    "field": "validation error details"
  }
}
```

Common HTTP status codes:
- **200**: Success
- **201**: Created
- **400**: Bad Request (validation errors)
- **401**: Unauthorized (authentication required)
- **403**: Forbidden (insufficient permissions)
- **404**: Not Found
- **429**: Too Many Requests (rate limited)
- **500**: Internal Server Error