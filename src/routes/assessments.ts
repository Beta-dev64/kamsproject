import { Router } from 'express';
import { assessmentController } from '../controllers/assessmentController';
import { authenticate } from '../middleware/auth';
import { authorize } from '../middleware/auth';
import { rateLimiter } from '../middleware/rateLimiter';
import { validateInput } from '../middleware/validation';
import { Permission } from '../types';
import { body, param, query } from 'express-validator';

const router: Router = Router();

// Apply authentication to all routes
router.use(authenticate);

// Validation schemas
const createQuestionValidation = [
  body('category')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Category must be between 1 and 100 characters'),
  body('question')
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Question must be between 10 and 1000 characters'),
  body('example')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Example must not exceed 1000 characters'),
  body('weight')
    .optional()
    .isFloat({ min: 0.1, max: 10.0 })
    .withMessage('Weight must be between 0.1 and 10.0'),
  body('sortOrder')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Sort order must be a non-negative integer')
];

const updateQuestionValidation = [
  param('id').isUUID().withMessage('Invalid question ID'),
  body('category')
    .optional()
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Category must be between 1 and 100 characters'),
  body('question')
    .optional()
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Question must be between 10 and 1000 characters'),
  body('example')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Example must not exceed 1000 characters'),
  body('weight')
    .optional()
    .isFloat({ min: 0.1, max: 10.0 })
    .withMessage('Weight must be between 0.1 and 10.0'),
  body('isActive')
    .optional()
    .isBoolean()
    .withMessage('isActive must be a boolean'),
  body('sortOrder')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Sort order must be a non-negative integer')
];

const createAssessmentValidation = [
  body('employeeId')
    .isUUID()
    .withMessage('Invalid employee ID'),
  body('assessmentType')
    .isIn(['manager', 'self'])
    .withMessage('Assessment type must be either manager or self'),
  body('assessmentDate')
    .isISO8601()
    .withMessage('Invalid assessment date format'),
  body('quarter')
    .optional()
    .matches(/^Q[1-4]$/)
    .withMessage('Quarter must be in format Q1, Q2, Q3, or Q4'),
  body('year')
    .optional()
    .isInt({ min: 2000, max: 2100 })
    .withMessage('Year must be between 2000 and 2100'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Notes must not exceed 2000 characters')
];

const updateAssessmentValidation = [
  param('id').isUUID().withMessage('Invalid assessment ID'),
  body('assessmentDate')
    .optional()
    .isISO8601()
    .withMessage('Invalid assessment date format'),
  body('quarter')
    .optional()
    .matches(/^Q[1-4]$/)
    .withMessage('Quarter must be in format Q1, Q2, Q3, or Q4'),
  body('year')
    .optional()
    .isInt({ min: 2000, max: 2100 })
    .withMessage('Year must be between 2000 and 2100'),
  body('notes')
    .optional()
    .trim()
    .isLength({ max: 2000 })
    .withMessage('Notes must not exceed 2000 characters'),
  body('status')
    .optional()
    .isIn(['draft', 'submitted', 'completed', 'archived'])
    .withMessage('Invalid status')
];

const submitScoresValidation = [
  param('id').isUUID().withMessage('Invalid assessment ID'),
  body('scores')
    .isArray({ min: 1 })
    .withMessage('Scores array is required and must not be empty'),
  body('scores.*.questionId')
    .isUUID()
    .withMessage('Each score must have a valid question ID'),
  body('scores.*.score')
    .isInt({ min: 1, max: 4 })
    .withMessage('Each score must be between 1 and 4'),
  body('scores.*.comments')
    .optional()
    .trim()
    .isLength({ max: 500 })
    .withMessage('Comments must not exceed 500 characters')
];

const bulkCreateQuestionsValidation = [
  body('questions')
    .isArray({ min: 1 })
    .withMessage('Questions array is required and must not be empty'),
  body('questions.*.category')
    .trim()
    .isLength({ min: 1, max: 100 })
    .withMessage('Each question must have a category between 1 and 100 characters'),
  body('questions.*.question')
    .trim()
    .isLength({ min: 10, max: 1000 })
    .withMessage('Each question text must be between 10 and 1000 characters'),
  body('questions.*.example')
    .optional()
    .trim()
    .isLength({ max: 1000 })
    .withMessage('Example must not exceed 1000 characters'),
  body('questions.*.weight')
    .optional()
    .isFloat({ min: 0.1, max: 10.0 })
    .withMessage('Weight must be between 0.1 and 10.0'),
  body('questions.*.sortOrder')
    .optional()
    .isInt({ min: 0 })
    .withMessage('Sort order must be a non-negative integer')
];

const paginationValidation = [
  query('page')
    .optional()
    .isInt({ min: 1 })
    .withMessage('Page must be a positive integer'),
  query('limit')
    .optional()
    .isInt({ min: 1, max: 100 })
    .withMessage('Limit must be between 1 and 100'),
  query('sort')
    .optional()
    .trim()
    .isLength({ min: 1, max: 50 })
    .withMessage('Sort field must be between 1 and 50 characters'),
  query('order')
    .optional()
    .isIn(['asc', 'desc'])
    .withMessage('Order must be asc or desc')
];

// Question Management Routes
router.post('/questions',
  rateLimiter.createResource,
  authorize([Permission.ASSESSMENT_CREATE]),
  createQuestionValidation,
  validateInput,
  assessmentController.createQuestion
);

router.get('/questions',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  [
    ...paginationValidation,
    query('category').optional().trim().isLength({ min: 1, max: 100 }),
    query('isActive').optional().isBoolean(),
    query('search').optional().trim().isLength({ min: 1, max: 100 })
  ],
  validateInput,
  assessmentController.getQuestions
);

router.get('/questions/active',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  assessmentController.getActiveQuestions
);

router.get('/questions/:id',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  param('id').isUUID().withMessage('Invalid question ID'),
  validateInput,
  assessmentController.getQuestionById
);

router.put('/questions/:id',
  rateLimiter.updateResource,
  authorize([Permission.ASSESSMENT_UPDATE]),
  updateQuestionValidation,
  validateInput,
  assessmentController.updateQuestion
);

router.delete('/questions/:id',
  rateLimiter.deleteResource,
  authorize([Permission.ASSESSMENT_DELETE]),
  param('id').isUUID().withMessage('Invalid question ID'),
  validateInput,
  assessmentController.deleteQuestion
);

router.post('/questions/bulk',
  rateLimiter.bulkOperation,
  authorize([Permission.ASSESSMENT_CREATE]),
  bulkCreateQuestionsValidation,
  validateInput,
  assessmentController.bulkCreateQuestions
);

// Assessment Management Routes
router.post('/',
  rateLimiter.createResource,
  authorize([Permission.ASSESSMENT_CREATE]),
  createAssessmentValidation,
  validateInput,
  assessmentController.createAssessment
);

router.get('/',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  [
    ...paginationValidation,
    query('employeeId').optional().isUUID().withMessage('Invalid employee ID'),
    query('assessorId').optional().isUUID().withMessage('Invalid assessor ID'),
    query('status').optional().isIn(['draft', 'submitted', 'completed', 'archived']),
    query('assessmentType').optional().isIn(['manager', 'self']),
    query('year').optional().isInt({ min: 2000, max: 2100 }),
    query('quarter').optional().matches(/^Q[1-4]$/)
  ],
  validateInput,
  assessmentController.getAssessments
);

router.get('/dashboard/stats',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  assessmentController.getDashboardStats
);

router.get('/:id',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  param('id').isUUID().withMessage('Invalid assessment ID'),
  validateInput,
  assessmentController.getAssessmentById
);

router.put('/:id',
  rateLimiter.updateResource,
  authorize([Permission.ASSESSMENT_UPDATE]),
  updateAssessmentValidation,
  validateInput,
  assessmentController.updateAssessment
);

router.get('/:id/progress',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  param('id').isUUID().withMessage('Invalid assessment ID'),
  validateInput,
  assessmentController.getAssessmentProgress
);

// Assessment Scoring Routes
router.post('/:id/scores',
  rateLimiter.submitScores,
  authorize([Permission.ASSESSMENT_UPDATE]),
  submitScoresValidation,
  validateInput,
  assessmentController.submitScores
);

router.get('/:id/scores',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  param('id').isUUID().withMessage('Invalid assessment ID'),
  validateInput,
  assessmentController.getAssessmentScores
);

// Analytics Routes
router.get('/analytics/overview',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  [
    query('year').optional().isInt({ min: 2000, max: 2100 }),
    query('quarter').optional().matches(/^Q[1-4]$/),
    query('employeeId').optional().isUUID(),
    query('departmentFilter').optional().trim().isLength({ min: 1, max: 100 })
  ],
  validateInput,
  assessmentController.getAssessmentAnalytics
);

router.get('/analytics/questions',
  rateLimiter.readResource,
  authorize([Permission.ASSESSMENT_READ]),
  assessmentController.getQuestionAnalytics
);

// Error handling middleware for this router
router.use((error: any, req: any, res: any, next: any) => {
  if (error.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      message: 'Validation failed',
      errors: error.details
    });
  }
  next(error);
});

export default router;