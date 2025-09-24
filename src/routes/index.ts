import { Router } from 'express';
import authRoutes from './auth';
import userRoutes from './users';
import tenantRoutes from './tenants';
import assessmentRoutes from './assessments';
// Import other route modules as they are created
// import settingsRoutes from './settings';

const router: any = Router();

// API version 1 routes
const v1Router = Router();

// Mount authentication routes
v1Router.use('/auth', authRoutes);

// Mount user routes
v1Router.use('/users', userRoutes);

// Mount tenant routes
v1Router.use('/tenants', tenantRoutes);

// Mount assessment routes
v1Router.use('/assessments', assessmentRoutes);

// TODO: Mount other routes as they are implemented
// v1Router.use('/settings', settingsRoutes);

// Mount v1 routes
router.use('/v1', v1Router);

// API status endpoint
router.get('/', (req: any, res: any) => {
  res.json({
    success: true,
    message: 'KAM Assessment Portal API',
    version: 'v1',
    timestamp: new Date().toISOString(),
    endpoints: {
      auth: '/api/v1/auth',
      users: '/api/v1/users',
      tenants: '/api/v1/tenants',
      assessments: '/api/v1/assessments',
      settings: '/api/v1/settings (coming soon)',
    },
    documentation: {
      postman: '/api/docs/postman (coming soon)',
      swagger: '/api/docs/swagger (coming soon)',
    },
    health: '/health',
  });
});

export default router;