# Frontend Integration Guide

This document explains how to integrate the KAM Assessment API into a frontend application.

## Base URL

- Production (Render): `https://your-service.onrender.com`
- API base path: `/api/v1`

Example full URL: `https://your-service.onrender.com/api/v1/auth/login`

## Authentication & Tenant Context

- Authentication uses JWT access tokens (short-lived) and refresh tokens (long-lived).
- Send access token in the `Authorization` header as `Bearer <ACCESS_TOKEN>`.
- Multi-tenant context is provided via:
  - Public auth routes: body field `tenantDomain` (where applicable).
  - Protected routes: header `x-tenant-domain: <tenant-domain>`.

Common headers:
- `Content-Type: application/json`
- `Authorization: Bearer <ACCESS_TOKEN>` (protected routes)
- `x-tenant-domain: <tenant-domain>` (protected routes)

---

## Auth Endpoints
Base: `/api/v1/auth`

### Register
- POST `/register`
- Description: Create a new user within a tenant.
- Body:
```json
{
  "email": "jane.doe@example.com",
  "password": "P@ssw0rd!",
  "firstName": "Jane",
  "lastName": "Doe",
  "tenantDomain": "acme"
}
```
- Notes: Strong password required.

### Login
- POST `/login`
- Description: Login with tenant context.
- Body:
```json
{
  "email": "jane.doe@example.com",
  "password": "P@ssw0rd!",
  "tenantDomain": "acme"
}
```
- Response: `{ user, accessToken, refreshToken, expiresIn }` and also sets `refreshToken` cookie when used from browsers.

### Admin Login (Super Admin)
- POST `/admin-login`
- Description: Tenantless login for super admins.
- Body:
```json
{
  "email": "superadmin@example.com",
  "password": "SuperAdmin123!"
}
```

### Refresh Access Token
- POST `/refresh`
- Description: Obtain new access/refresh tokens using a refresh token.
- Options:
  - Body: `{ "refreshToken": "<REFRESH_TOKEN>" }`
  - Or Cookie: `refreshToken=<REFRESH_TOKEN>`
  - Or Header: `Authorization: Bearer <REFRESH_TOKEN>`

### Validate Token
- GET `/validate`
- Headers: `Authorization: Bearer <ACCESS_TOKEN>`
- Description: Validate access token; returns token metadata.

### Forgot Password
- POST `/forgot-password`
- Body:
```json
{
  "email": "jane.doe@example.com",
  "tenantDomain": "acme"
}
```

### Reset Password
- POST `/reset-password`
- Body:
```json
{
  "token": "<RESET_TOKEN>",
  "password": "N3wP@ssw0rd!",
  "confirmPassword": "N3wP@ssw0rd!"
}
```

### Verify Email
- POST `/verify-email`
- Body:
```json
{ "token": "<EMAIL_VERIFICATION_TOKEN>" }
```

### Resend Verification
- POST `/resend-verification`
- Body:
```json
{
  "email": "jane.doe@example.com",
  "tenantDomain": "acme"
}
```

### Me (Current User)
- GET `/me`
- Headers: `Authorization`, `x-tenant-domain`

### Logout (This device)
- POST `/logout`
- Headers: `Authorization`
- Body (optional): `{ "refreshToken": "<REFRESH_TOKEN>" }`

### Logout All Devices
- POST `/logout-all`
- Headers: `Authorization`

### Change Password
- POST `/change-password`
- Headers: `Authorization`, `x-tenant-domain`
- Body:
```json
{
  "currentPassword": "P@ssw0rd!",
  "newPassword": "N3wP@ssw0rd!",
  "confirmPassword": "N3wP@ssw0rd!"
}
```

### Sessions
- GET `/sessions`
- DELETE `/sessions/:sessionId`
- Headers: `Authorization`, `x-tenant-domain`

---

## User Endpoints
Base: `/api/v1/users`

Headers for all: `Authorization`, `x-tenant-domain`

### Get My Profile
- GET `/profile`

### Update My Profile
- PUT `/profile`
- Body:
```json
{
  "firstName": "Jane",
  "lastName": "Doe",
  "department": "Sales"
}
```

### List Users (Admin/Manager)
- GET `/`
- Query (optional):
  - `page`, `limit`, `role`, `department`, `isActive`, `search`, `sort`, `order`

### Create User (Admin)
- POST `/`
- Body:
```json
{
  "email": "new.user@example.com",
  "firstName": "New",
  "lastName": "User",
  "role": "user",
  "department": "Marketing",
  "managerId": "<UUID>"
}
```

### Get User By ID
- GET `/:userId`

### Update User
- PUT `/:userId`
- Body: any of `firstName`, `lastName`, `role`, `department`, `managerId`, `isActive`

### Delete User (Admin)
- DELETE `/:userId`

### Users by Role (Admin/Manager)
- GET `/role/:role`

### Direct Reports (Manager)
- GET `/reports/:managerId?`

### Users by Department (Admin/Manager)
- GET `/department/:department`

---

## Tenant Endpoints
Base: `/api/v1/tenants`

Headers for all: `Authorization`

### Current Tenant
- GET `/current`
- Headers: `x-tenant-domain`

### Get Tenant by ID (Super Admin)
- GET `/:tenantId`

### Create Tenant (Super Admin)
- POST `/`
- Body:
```json
{
  "name": "Acme Corporation",
  "domain": "acme",
  "subscriptionTier": "basic",
  "maxUsers": 100,
  "adminUser": {
    "email": "admin@acme.com",
    "firstName": "Ada",
    "lastName": "Admin",
    "password": "Admin123!"
  }
}
```

### Update Tenant
- PUT `/:tenantId`
- Body: any of `name`, `subscriptionTier`, `maxUsers`, `isActive`

### Tenant Settings
- GET `/settings`
- PUT `/settings`
- Body example (PUT):
```json
{
  "classificationThresholds": {
    "championMinTotal": 75
  },
  "classificationLabels": {
    "champion": "Champion"
  },
  "assessmentSettings": {
    "allowSelfAssessment": true
  },
  "emailSettings": {
    "weeklyReports": false
  }
}
```

### Invitations (Admin)
- POST `/invitations`
- GET `/invitations`
- POST `/invitations/:invitationId/resend`
- DELETE `/invitations/:invitationId`

### Tenant Stats (Admin)
- GET `/stats`

---

## Assessment Endpoints
Base: `/api/v1/assessments`

Headers for all: `Authorization`, `x-tenant-domain`

### Questions
- POST `/questions`
- GET `/questions`
  - Query: `page`, `limit`, `sort`, `order`, `category`, `isActive`, `search`
- GET `/questions/active`
- GET `/questions/:id`
- PUT `/questions/:id`
- DELETE `/questions/:id`
- POST `/questions/bulk`
  - Body:
```json
{
  "questions": [
    { "category": "CRM", "question": "How do you...", "example": "...", "weight": 1.2, "sortOrder": 1 }
  ]
}
```

### Assessments
- POST `/`
- GET `/`
  - Query: `page`, `limit`, `sort`, `order`, `employeeId`, `assessorId`, `status`, `assessmentType`, `year`, `quarter`
- GET `/:id`
- PUT `/:id`
- GET `/:id/progress`

### Scores
- POST `/:id/scores`
  - Body:
```json
{
  "scores": [
    { "questionId": "<UUID>", "score": 3, "comments": "Good" }
  ]
}
```
- GET `/:id/scores`

### Analytics
- GET `/analytics/overview`
  - Query: `year`, `quarter`, `employeeId`, `departmentFilter`
- GET `/analytics/questions`

---

## System Admin Endpoints (Super Admin)
Base: `/api/v1/system`

Headers for all: `Authorization`

- GET `/dashboard`
- GET `/health`
- GET `/tenants` (query: `page`, `limit`, `search`, `status`, `subscriptionTier`, `sortBy`, `sortOrder`)
- POST `/tenants` (body: same as Create Tenant above)
- GET `/tenants/:tenantId`
- PUT `/tenants/:tenantId`
- DELETE `/tenants/:tenantId`
- POST `/tenants/:tenantId/activate`
- POST `/tenants/:tenantId/deactivate`
- GET `/users` (query: `page`, `limit`, `tenantId`, `role`, `isActive`, `search`, `sortBy`, `sortOrder`)
- GET `/users/:userId`
- PUT `/users/:userId`
- POST `/users/:userId/reset-password`
- GET `/analytics/overview` (query: `startDate`, `endDate`, `tenantId`)
- GET `/analytics/tenants`
- POST `/maintenance/cleanup`
- GET `/logs` (query: `level`, `service`, `startDate`, `endDate`, `page`, `limit`)
- POST `/impersonate/:userId`

---

## Frontend Auth Flow (Recommended)

1. Register or login via `/auth/register` or `/auth/login`.
2. Store `accessToken` (in memory) and rely on `refreshToken` cookie.
3. For protected calls:
   - Add `Authorization: Bearer <ACCESS_TOKEN>`
   - Add `x-tenant-domain: <tenant>`
4. On 401 (expired): call `/auth/refresh` to rotate tokens, then retry.
5. On logout: call `/auth/logout` and clear app state.

---

## Example Fetch Wrapper
```ts
async function apiFetch(path: string, options: RequestInit = {}) {
  const baseUrl = 'https://your-service.onrender.com/api/v1';
  const res = await fetch(`${baseUrl}${path}`, {
    ...options,
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {})
    },
    credentials: 'include' // allow cookies for refreshToken
  });
  if (res.status === 401) {
    // try refresh
    const r = await fetch(`${baseUrl}/auth/refresh`, { method: 'POST', credentials: 'include' });
    if (r.ok) {
      return apiFetch(path, options);
    }
  }
  return res;
}
```

---

## Rate Limiting
- Standard API and auth-specific rate limits are applied. Implement UI retries with backoff and honor `Retry-After` when present.

## Errors
- Errors return JSON with `{ success: false, error, message, code, details? }`. Handle 400/401/403/404/429/5xx appropriately in the UI.
