import { Response } from 'express';
import { assessmentService } from '../services/assessmentService';
import { logger } from '../utils/logger';
import { AuthRequest, AssessmentType, AssessmentStatus } from '../types';
import { auditLog } from '../utils/logger';

class AssessmentController {
  // Question Management Endpoints
  async createQuestion(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { category, question, example, weight, sortOrder } = req.body;
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;

      if (!category || !question) {
        res.status(400).json({
          success: false,
          message: 'Category and question are required'
        });
        return;
      }

      const newQuestion = await assessmentService.createQuestion(tenantId, userId, {
        category,
        question,
        example,
        weight,
        sortOrder
      });

      await auditLog(tenantId, userId, 'CREATE', 'assessment_question', newQuestion.id, null, {
        category,
        question: question.substring(0, 100) // Log truncated question for privacy
      }, req.ip, req.get('User-Agent'));

      res.status(201).json({
        success: true,
        data: newQuestion,
        message: 'Assessment question created successfully'
      });
    } catch (error) {
      logger.error('Assessment question creation failed', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to create assessment question'
      });
    }
  }

  async getQuestions(req: AuthRequest, res: Response): Promise<void> {
    try {
      const tenantId = req.user!.tenantId;
      const {
        page = '1',
        limit = '50',
        category,
        isActive,
        search,
        sort,
        order
      } = req.query;

      const options = {
        page: parseInt(page as string, 10),
        limit: parseInt(limit as string, 10),
        category: category as string,
        isActive: isActive === 'true' ? true : isActive === 'false' ? false : undefined,
        search: search as string,
        sort: sort as string,
        order: order as 'asc' | 'desc'
      };

      const result = await assessmentService.getQuestions(tenantId, options);

      res.json({
        success: true,
        data: result.data,
        pagination: {
          total: result.total,
          pages: result.pages,
          currentPage: result.currentPage,
          hasNext: result.hasNext,
          hasPrev: result.hasPrev
        }
      });
    } catch (error) {
      logger.error('Failed to get assessment questions', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get assessment questions'
      });
    }
  }

  async getQuestionById(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const tenantId = req.user!.tenantId;

      const question = await assessmentService.getQuestionById(tenantId, id);

      if (!question) {
        res.status(404).json({
          success: false,
          message: 'Assessment question not found'
        });
        return;
      }

      res.json({
        success: true,
        data: question
      });
    } catch (error) {
      logger.error('Failed to get assessment question', {
        error: error instanceof Error ? error.message : error,
        questionId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get assessment question'
      });
    }
  }

  async updateQuestion(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { category, question, example, weight, isActive, sortOrder } = req.body;
      const tenantId = req.user!.tenantId;

      const updatedQuestion = await assessmentService.updateQuestion(tenantId, id, {
        category,
        question,
        example,
        weight,
        isActive,
        sortOrder
      });

      if (!updatedQuestion) {
        res.status(404).json({
          success: false,
          message: 'Assessment question not found'
        });
        return;
      }

      await auditLog(tenantId, req.user!.id, 'UPDATE', 'assessment_question', id, null, {
        category,
        question: question?.substring(0, 100) // Log truncated question for privacy
      }, req.ip, req.get('User-Agent'));

      res.json({
        success: true,
        data: updatedQuestion,
        message: 'Assessment question updated successfully'
      });
    } catch (error) {
      logger.error('Failed to update assessment question', {
        error: error instanceof Error ? error.message : error,
        questionId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to update assessment question'
      });
    }
  }

  async deleteQuestion(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const tenantId = req.user!.tenantId;

      const success = await assessmentService.deleteQuestion(tenantId, id);

      if (!success) {
        res.status(404).json({
          success: false,
          message: 'Assessment question not found'
        });
        return;
      }

      await auditLog(tenantId, req.user!.id, 'DELETE', 'assessment_question', id, null, {
        action: 'deactivated'
      }, req.ip, req.get('User-Agent'));

      res.json({
        success: true,
        message: 'Assessment question deleted successfully'
      });
    } catch (error) {
      logger.error('Failed to delete assessment question', {
        error: error instanceof Error ? error.message : error,
        questionId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to delete assessment question'
      });
    }
  }

  async bulkCreateQuestions(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { questions } = req.body;
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;

      if (!Array.isArray(questions) || questions.length === 0) {
        res.status(400).json({
          success: false,
          message: 'Questions array is required and must not be empty'
        });
        return;
      }

      // Validate each question
      for (const question of questions) {
        if (!question.category || !question.question) {
          res.status(400).json({
            success: false,
            message: 'All questions must have category and question fields'
          });
          return;
        }
      }

      const createdQuestions = await assessmentService.bulkCreateQuestions(tenantId, userId, questions);

      await auditLog(tenantId, userId, 'BULK_CREATE', 'assessment_questions', undefined, null, {
        count: questions.length
      }, req.ip, req.get('User-Agent'));

      res.status(201).json({
        success: true,
        data: createdQuestions,
        message: `${createdQuestions.length} assessment questions created successfully`
      });
    } catch (error) {
      logger.error('Bulk question creation failed', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to create assessment questions'
      });
    }
  }

  // Assessment Management Endpoints
  async createAssessment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { employeeId, assessmentType, assessmentDate, quarter, year, notes } = req.body;
      const tenantId = req.user!.tenantId;
      const assessorId = req.user!.id;

      if (!employeeId || !assessmentType || !assessmentDate) {
        res.status(400).json({
          success: false,
          message: 'Employee ID, assessment type, and assessment date are required'
        });
        return;
      }

      if (!Object.values(AssessmentType).includes(assessmentType)) {
        res.status(400).json({
          success: false,
          message: 'Invalid assessment type'
        });
        return;
      }

      const newAssessment = await assessmentService.createAssessment(tenantId, assessorId, {
        employeeId,
        assessmentType,
        assessmentDate: new Date(assessmentDate),
        quarter,
        year,
        notes
      });

      await auditLog(tenantId, assessorId, 'CREATE', 'assessment', newAssessment.id, null, {
        employeeId,
        assessmentType,
        assessmentDate
      }, req.ip, req.get('User-Agent'));

      res.status(201).json({
        success: true,
        data: newAssessment,
        message: 'Assessment created successfully'
      });
    } catch (error) {
      logger.error('Assessment creation failed', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to create assessment'
      });
    }
  }

  async getAssessments(req: AuthRequest, res: Response): Promise<void> {
    try {
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;
      const userRole = req.user!.role;
      
      const {
        page = '1',
        limit = '20',
        employeeId,
        assessorId,
        status,
        assessmentType,
        year,
        quarter,
        sort,
        order
      } = req.query;

      const options = {
        page: parseInt(page as string, 10),
        limit: parseInt(limit as string, 10),
        employeeId: employeeId as string,
        assessorId: assessorId as string,
        status: status as AssessmentStatus,
        assessmentType: assessmentType as AssessmentType,
        year: year ? parseInt(year as string, 10) : undefined,
        quarter: quarter as string,
        sort: sort as string,
        order: order as 'asc' | 'desc'
      };

      const result = await assessmentService.getAssessments(tenantId, userId, userRole, options);

      res.json({
        success: true,
        data: result.data,
        pagination: {
          total: result.total,
          pages: result.pages,
          currentPage: result.currentPage,
          hasNext: result.hasNext,
          hasPrev: result.hasPrev
        }
      });
    } catch (error) {
      logger.error('Failed to get assessments', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get assessments'
      });
    }
  }

  async getAssessmentById(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      const assessment = await assessmentService.getAssessmentById(tenantId, id, userId, userRole);

      if (!assessment) {
        res.status(404).json({
          success: false,
          message: 'Assessment not found or access denied'
        });
        return;
      }

      res.json({
        success: true,
        data: assessment
      });
    } catch (error) {
      logger.error('Failed to get assessment', {
        error: error instanceof Error ? error.message : error,
        assessmentId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get assessment'
      });
    }
  }

  async updateAssessment(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { assessmentDate, quarter, year, notes, status } = req.body;
      const tenantId = req.user!.tenantId;

      const updatedAssessment = await assessmentService.updateAssessment(tenantId, id, {
        assessmentDate: assessmentDate ? new Date(assessmentDate) : undefined,
        quarter,
        year,
        notes,
        status
      });

      if (!updatedAssessment) {
        res.status(404).json({
          success: false,
          message: 'Assessment not found'
        });
        return;
      }

      await auditLog(tenantId, req.user!.id, 'UPDATE', 'assessment', id, null, {
        assessmentDate,
        quarter,
        year,
        status
      }, req.ip, req.get('User-Agent'));

      res.json({
        success: true,
        data: updatedAssessment,
        message: 'Assessment updated successfully'
      });
    } catch (error) {
      logger.error('Failed to update assessment', {
        error: error instanceof Error ? error.message : error,
        assessmentId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to update assessment'
      });
    }
  }

  // Assessment Scoring Endpoints
  async submitScores(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const { scores } = req.body;
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;

      if (!Array.isArray(scores) || scores.length === 0) {
        res.status(400).json({
          success: false,
          message: 'Scores array is required and must not be empty'
        });
        return;
      }

      // Validate scores
      for (const score of scores) {
        if (!score.questionId || typeof score.score !== 'number' || score.score < 1 || score.score > 4) {
          res.status(400).json({
            success: false,
            message: 'Each score must have a questionId and score between 1 and 4'
          });
          return;
        }
      }

      const result = await assessmentService.submitScores(tenantId, id, { scores }, userId);

      await auditLog(tenantId, userId, 'SUBMIT_SCORES', 'assessment', id, null, {
        totalScore: result.totalScore,
        classification: result.classification,
        scoresCount: scores.length
      }, req.ip, req.get('User-Agent'));

      res.json({
        success: true,
        data: result,
        message: 'Assessment scores submitted successfully'
      });
    } catch (error) {
      logger.error('Failed to submit assessment scores', {
        error: error instanceof Error ? error.message : error,
        assessmentId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      if (error instanceof Error && error.message.includes('not found or access denied')) {
        res.status(404).json({
          success: false,
          message: 'Assessment not found or access denied'
        });
        return;
      }

      res.status(500).json({
        success: false,
        message: 'Failed to submit assessment scores'
      });
    }
  }

  async getAssessmentScores(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      const scores = await assessmentService.getAssessmentScores(tenantId, id, userId, userRole);

      res.json({
        success: true,
        data: scores
      });
    } catch (error) {
      logger.error('Failed to get assessment scores', {
        error: error instanceof Error ? error.message : error,
        assessmentId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      if (error instanceof Error && error.message.includes('not found or access denied')) {
        res.status(404).json({
          success: false,
          message: 'Assessment not found or access denied'
        });
        return;
      }

      res.status(500).json({
        success: false,
        message: 'Failed to get assessment scores'
      });
    }
  }

  // Analytics Endpoints
  async getAssessmentAnalytics(req: AuthRequest, res: Response): Promise<void> {
    try {
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      const {
        year,
        quarter,
        employeeId,
        departmentFilter
      } = req.query;

      const options = {
        year: year ? parseInt(year as string, 10) : undefined,
        quarter: quarter as string,
        employeeId: employeeId as string,
        departmentFilter: departmentFilter as string
      };

      const analytics = await assessmentService.getAssessmentAnalytics(tenantId, userId, userRole, options);

      res.json({
        success: true,
        data: analytics
      });
    } catch (error) {
      logger.error('Failed to get assessment analytics', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get assessment analytics'
      });
    }
  }

  async getQuestionAnalytics(req: AuthRequest, res: Response): Promise<void> {
    try {
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      const analytics = await assessmentService.getQuestionAnalytics(tenantId, userId, userRole);

      res.json({
        success: true,
        data: analytics
      });
    } catch (error) {
      logger.error('Failed to get question analytics', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get question analytics'
      });
    }
  }

  // Utility Endpoints
  async getActiveQuestions(req: AuthRequest, res: Response): Promise<void> {
    try {
      const tenantId = req.user!.tenantId;

      const questions = await assessmentService.getActiveQuestions(tenantId);

      res.json({
        success: true,
        data: questions
      });
    } catch (error) {
      logger.error('Failed to get active questions', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get active questions'
      });
    }
  }

  async getAssessmentProgress(req: AuthRequest, res: Response): Promise<void> {
    try {
      const { id } = req.params;
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      // Get assessment details with progress
      const assessment = await assessmentService.getAssessmentById(tenantId, id, userId, userRole);
      if (!assessment) {
        res.status(404).json({
          success: false,
          message: 'Assessment not found or access denied'
        });
        return;
      }

      // Get current scores
      const scores = await assessmentService.getAssessmentScores(tenantId, id, userId, userRole);

      const progress = {
        assessmentId: id,
        status: assessment.status,
        totalQuestions: assessment.totalQuestions,
        completedQuestions: assessment.completedScores,
        progressPercentage: assessment.totalQuestions > 0 
          ? Math.round((assessment.completedScores / assessment.totalQuestions) * 100)
          : 0,
        totalScore: assessment.totalScore,
        classification: assessment.classification,
        isComplete: assessment.status === AssessmentStatus.SUBMITTED,
        lastUpdated: assessment.updatedAt
      };

      res.json({
        success: true,
        data: {
          progress,
          scores: scores.map(score => ({
            questionId: score.questionId,
            category: score.category,
            score: score.score,
            comments: score.comments
          }))
        }
      });
    } catch (error) {
      logger.error('Failed to get assessment progress', {
        error: error instanceof Error ? error.message : error,
        assessmentId: req.params.id,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get assessment progress'
      });
    }
  }

  async getDashboardStats(req: AuthRequest, res: Response): Promise<void> {
    try {
      const tenantId = req.user!.tenantId;
      const userId = req.user!.id;
      const userRole = req.user!.role;

      const currentYear = new Date().getFullYear();
      const currentQuarter = `Q${Math.ceil((new Date().getMonth() + 1) / 3)}`;

      // Get analytics for current period
      const analytics = await assessmentService.getAssessmentAnalytics(tenantId, userId, userRole, {
        year: currentYear,
        quarter: currentQuarter
      });

      // Get overall analytics (all time)
      const overallAnalytics = await assessmentService.getAssessmentAnalytics(tenantId, userId, userRole);

      const dashboardStats = {
        currentPeriod: {
          year: currentYear,
          quarter: currentQuarter,
          totalAssessments: analytics.totalAssessments,
          completedAssessments: analytics.completedAssessments,
          averageScore: analytics.averageScore,
          classificationDistribution: analytics.classificationDistribution
        },
        overall: {
          totalAssessments: overallAnalytics.totalAssessments,
          completedAssessments: overallAnalytics.completedAssessments,
          averageScore: overallAnalytics.averageScore,
          trendData: overallAnalytics.trendData.slice(0, 6) // Last 6 quarters
        },
        scoresByCategory: analytics.scoresByCategory
      };

      res.json({
        success: true,
        data: dashboardStats
      });
    } catch (error) {
      logger.error('Failed to get dashboard stats', {
        error: error instanceof Error ? error.message : error,
        userId: req.user?.id,
        tenantId: req.user?.tenantId
      });

      res.status(500).json({
        success: false,
        message: 'Failed to get dashboard statistics'
      });
    }
  }
}

export const assessmentController = new AssessmentController();