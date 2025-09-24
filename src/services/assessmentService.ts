import { db } from '../database';
import { logger } from '../utils/logger';
import { 
  Assessment, 
  AssessmentQuestion, 
  AssessmentScore, 
  AssessmentType, 
  AssessmentStatus,
  PaginationOptions,
  PaginatedResponse 
} from '../types';

export interface CreateAssessmentRequest {
  employeeId: string;
  assessmentType: AssessmentType;
  assessmentDate: Date;
  quarter?: string;
  year?: number;
  notes?: string;
}

export interface UpdateAssessmentRequest {
  assessmentDate?: Date;
  quarter?: string;
  year?: number;
  notes?: string;
  status?: AssessmentStatus;
}

export interface CreateQuestionRequest {
  category: string;
  question: string;
  example?: string;
  weight?: number;
  sortOrder?: number;
}

export interface UpdateQuestionRequest {
  category?: string;
  question?: string;
  example?: string;
  weight?: number;
  isActive?: boolean;
  sortOrder?: number;
}

export interface SubmitScoresRequest {
  scores: Array<{
    questionId: string;
    score: number; // 1-4
    comments?: string;
  }>;
}

export interface AssessmentWithDetails extends Assessment {
  employeeName: string;
  assessorName: string;
  totalScore?: number;
  classification?: string;
  completedScores: number;
  totalQuestions: number;
}

export interface AssessmentAnalytics {
  totalAssessments: number;
  completedAssessments: number;
  averageScore: number;
  classificationDistribution: Record<string, number>;
  scoresByCategory: Record<string, { average: number; count: number }>;
  trendData: Array<{
    period: string;
    averageScore: number;
    assessmentCount: number;
  }>;
}

export interface QuestionAnalytics {
  totalQuestions: number;
  questionsByCategory: Record<string, number>;
  averageScoreByQuestion: Array<{
    questionId: string;
    question: string;
    category: string;
    averageScore: number;
    responseCount: number;
  }>;
}

class AssessmentService {
  // Question Management
  async createQuestion(
    tenantId: string, 
    userId: string, 
    data: CreateQuestionRequest
  ): Promise<AssessmentQuestion> {
    try {
      const result = await db.queryOne<AssessmentQuestion>(
        `INSERT INTO kam_assessment_questions 
         (tenant_id, category, question, example, weight, sort_order, created_by)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
        [
          tenantId,
          data.category,
          data.question,
          data.example || null,
          data.weight || 1.00,
          data.sortOrder || 0,
          userId
        ]
      );

      if (!result) {
        throw new Error('Failed to create assessment question');
      }

      logger.info('Assessment question created', { 
        questionId: result.id, 
        category: data.category,
        tenantId,
        userId 
      });

      return result;
    } catch (error) {
      logger.error('Failed to create assessment question', { 
        error: error instanceof Error ? error.message : error,
        tenantId,
        userId
      });
      throw new Error('Failed to create assessment question');
    }
  }

  async getQuestions(
    tenantId: string,
    options: PaginationOptions & { 
      category?: string; 
      isActive?: boolean;
      search?: string;
    } = { page: 1, limit: 50 }
  ): Promise<PaginatedResponse<AssessmentQuestion>> {
    try {
      let whereConditions = ['q.tenant_id = $1'];
      let params: any[] = [tenantId];
      let paramCount = 1;

      if (options.category) {
        whereConditions.push(`q.category = $${++paramCount}`);
        params.push(options.category);
      }

      if (options.isActive !== undefined) {
        whereConditions.push(`q.is_active = $${++paramCount}`);
        params.push(options.isActive);
      }

      if (options.search) {
        whereConditions.push(`(q.question ILIKE $${++paramCount} OR q.category ILIKE $${++paramCount})`);
        params.push(`%${options.search}%`, `%${options.search}%`);
        paramCount++;
      }

      const whereClause = whereConditions.length > 0 ? `WHERE ${whereConditions.join(' AND ')}` : '';
      
      const sortOrder = options.sort || 'sort_order';
      const sortDirection = options.order || 'asc';
      const offset = (options.page - 1) * options.limit;

      // Get total count
      const countResult = await db.queryOne<{ count: number }>(
        `SELECT COUNT(*) as count 
         FROM kam_assessment_questions q 
         ${whereClause}`,
        params
      );

      if (!countResult) {
        throw new Error('Failed to get question count');
      }

      // Get questions
      const questionsResult = await db.query<AssessmentQuestion>(
        `SELECT q.*, 
                p.first_name || ' ' || p.last_name as created_by_name
         FROM kam_assessment_questions q
         LEFT JOIN kam_profiles p ON q.created_by = p.id
         ${whereClause}
         ORDER BY q.${sortOrder} ${sortDirection.toUpperCase()}
         LIMIT $${++paramCount} OFFSET $${++paramCount}`,
        [...params, options.limit, offset]
      );

      const total = parseInt(countResult.count.toString());
      const pages = Math.ceil(total / options.limit);

      return {
        data: questionsResult.rows,
        total,
        pages,
        currentPage: options.page,
        hasNext: options.page < pages,
        hasPrev: options.page > 1
      };
    } catch (error) {
      logger.error('Failed to get assessment questions', { 
        error: error instanceof Error ? error.message : error,
        tenantId
      });
      throw new Error('Failed to get assessment questions');
    }
  }

  async getQuestionById(tenantId: string, questionId: string): Promise<AssessmentQuestion | null> {
    try {
      const result = await db.queryOne<AssessmentQuestion>(
        `SELECT * FROM kam_assessment_questions 
         WHERE tenant_id = $1 AND id = $2`,
        [tenantId, questionId]
      );

      return result || null;
    } catch (error) {
      logger.error('Failed to get assessment question', { 
        error: error instanceof Error ? error.message : error,
        questionId,
        tenantId
      });
      return null;
    }
  }

  async updateQuestion(
    tenantId: string,
    questionId: string,
    data: UpdateQuestionRequest
  ): Promise<AssessmentQuestion | null> {
    try {
      const setParts: string[] = [];
      const params: any[] = [tenantId, questionId];
      let paramCount = 2;

      if (data.category !== undefined) {
        setParts.push(`category = $${++paramCount}`);
        params.push(data.category);
      }

      if (data.question !== undefined) {
        setParts.push(`question = $${++paramCount}`);
        params.push(data.question);
      }

      if (data.example !== undefined) {
        setParts.push(`example = $${++paramCount}`);
        params.push(data.example);
      }

      if (data.weight !== undefined) {
        setParts.push(`weight = $${++paramCount}`);
        params.push(data.weight);
      }

      if (data.isActive !== undefined) {
        setParts.push(`is_active = $${++paramCount}`);
        params.push(data.isActive);
      }

      if (data.sortOrder !== undefined) {
        setParts.push(`sort_order = $${++paramCount}`);
        params.push(data.sortOrder);
      }

      if (setParts.length === 0) {
        return this.getQuestionById(tenantId, questionId);
      }

      const result = await db.queryOne<AssessmentQuestion>(
        `UPDATE kam_assessment_questions 
         SET ${setParts.join(', ')}
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        params
      );

      logger.info('Assessment question updated', { questionId, tenantId });
      return result;
    } catch (error) {
      logger.error('Failed to update assessment question', { 
        error: error instanceof Error ? error.message : error,
        questionId,
        tenantId
      });
      throw new Error('Failed to update assessment question');
    }
  }

  async deleteQuestion(tenantId: string, questionId: string): Promise<boolean> {
    try {
      await db.query(
        `UPDATE kam_assessment_questions 
         SET is_active = false 
         WHERE tenant_id = $1 AND id = $2`,
        [tenantId, questionId]
      );

      logger.info('Assessment question deactivated', { questionId, tenantId });
      return true;
    } catch (error) {
      logger.error('Failed to delete assessment question', { 
        error: error instanceof Error ? error.message : error,
        questionId,
        tenantId
      });
      return false;
    }
  }

  // Assessment Management
  async createAssessment(
    tenantId: string,
    assessorId: string,
    data: CreateAssessmentRequest
  ): Promise<Assessment> {
    try {
      const result = await db.queryOne<Assessment>(
        `INSERT INTO kam_assessments 
         (tenant_id, employee_id, assessor_id, assessment_type, assessment_date, quarter, year, notes)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
         RETURNING *`,
        [
          tenantId,
          data.employeeId,
          assessorId,
          data.assessmentType,
          data.assessmentDate,
          data.quarter || null,
          data.year || new Date().getFullYear(),
          data.notes || null
        ]
      );

      if (!result) {
        throw new Error('Failed to create assessment');
      }

      logger.info('Assessment created', { 
        assessmentId: result.id, 
        employeeId: data.employeeId,
        assessorId,
        tenantId 
      });

      return result;
    } catch (error) {
      logger.error('Failed to create assessment', { 
        error: error instanceof Error ? error.message : error,
        tenantId,
        assessorId
      });
      throw new Error('Failed to create assessment');
    }
  }

  async getAssessments(
    tenantId: string,
    userId: string,
    userRole: string,
    options: PaginationOptions & {
      employeeId?: string;
      assessorId?: string;
      status?: AssessmentStatus;
      assessmentType?: AssessmentType;
      year?: number;
      quarter?: string;
    } = { page: 1, limit: 20 }
  ): Promise<PaginatedResponse<AssessmentWithDetails>> {
    try {
      let whereConditions = ['a.tenant_id = $1'];
      let params: any[] = [tenantId];
      let paramCount = 1;

      // Role-based filtering
      if (userRole === 'user') {
        // Users can only see their own assessments or assessments they created
        whereConditions.push(`(a.employee_id = $${++paramCount} OR a.assessor_id = $${++paramCount})`);
        params.push(userId, userId);
        paramCount++;
      } else if (userRole === 'manager') {
        // Managers can see assessments for their team members
        whereConditions.push(`(
          a.employee_id = $${++paramCount} OR 
          a.assessor_id = $${++paramCount} OR
          a.employee_id IN (
            SELECT id FROM kam_profiles 
            WHERE tenant_id = $1 AND manager_id = $${paramCount}
          )
        )`);
        params.push(userId, userId);
        paramCount++;
      }
      // Admins can see all assessments (no additional filtering)

      if (options.employeeId) {
        whereConditions.push(`a.employee_id = $${++paramCount}`);
        params.push(options.employeeId);
      }

      if (options.assessorId) {
        whereConditions.push(`a.assessor_id = $${++paramCount}`);
        params.push(options.assessorId);
      }

      if (options.status) {
        whereConditions.push(`a.status = $${++paramCount}`);
        params.push(options.status);
      }

      if (options.assessmentType) {
        whereConditions.push(`a.assessment_type = $${++paramCount}`);
        params.push(options.assessmentType);
      }

      if (options.year) {
        whereConditions.push(`a.year = $${++paramCount}`);
        params.push(options.year);
      }

      if (options.quarter) {
        whereConditions.push(`a.quarter = $${++paramCount}`);
        params.push(options.quarter);
      }

      const whereClause = whereConditions.join(' AND ');
      
      const sortOrder = options.sort || 'assessment_date';
      const sortDirection = options.order || 'desc';
      const offset = (options.page - 1) * options.limit;

      // Get total count
      const countResult = await db.queryOne<{ count: number }>(
        `SELECT COUNT(*) as count 
         FROM kam_assessments a 
         WHERE ${whereClause}`,
        params
      );

      if (!countResult) {
        throw new Error('Failed to get assessment count');
      }

      // Get assessments with details
      const assessmentsResult = await db.query<AssessmentWithDetails>(
        `SELECT a.*,
                e.first_name || ' ' || e.last_name as employee_name,
                ass.first_name || ' ' || ass.last_name as assessor_name,
                a.total_score,
                a.classification,
                COALESCE(score_counts.completed_scores, 0) as completed_scores,
                COALESCE(question_counts.total_questions, 0) as total_questions
         FROM kam_assessments a
         JOIN kam_profiles e ON a.employee_id = e.id
         JOIN kam_profiles ass ON a.assessor_id = ass.id
         LEFT JOIN (
           SELECT assessment_id, COUNT(*) as completed_scores
           FROM kam_assessment_scores
           GROUP BY assessment_id
         ) score_counts ON a.id = score_counts.assessment_id
         LEFT JOIN (
           SELECT COUNT(*) as total_questions
           FROM kam_assessment_questions
           WHERE tenant_id = $1 AND is_active = true
         ) question_counts ON true
         WHERE ${whereClause}
         ORDER BY a.${sortOrder} ${sortDirection.toUpperCase()}
         LIMIT $${++paramCount} OFFSET $${++paramCount}`,
        [...params, options.limit, offset]
      );

      const total = parseInt(countResult.count.toString());
      const pages = Math.ceil(total / options.limit);

      return {
        data: assessmentsResult.rows,
        total,
        pages,
        currentPage: options.page,
        hasNext: options.page < pages,
        hasPrev: options.page > 1
      };
    } catch (error) {
      logger.error('Failed to get assessments', { 
        error: error instanceof Error ? error.message : error,
        tenantId,
        userId
      });
      throw new Error('Failed to get assessments');
    }
  }

  async getAssessmentById(
    tenantId: string, 
    assessmentId: string,
    userId: string,
    userRole: string
  ): Promise<AssessmentWithDetails | null> {
    try {
      let additionalWhere = '';
      const params: any[] = [tenantId, assessmentId];

      // Role-based access control
      if (userRole === 'user') {
        additionalWhere = ' AND (a.employee_id = $3 OR a.assessor_id = $3)';
        params.push(userId);
      } else if (userRole === 'manager') {
        additionalWhere = ` AND (
          a.employee_id = $3 OR 
          a.assessor_id = $3 OR
          a.employee_id IN (
            SELECT id FROM kam_profiles 
            WHERE tenant_id = $1 AND manager_id = $3
          )
        )`;
        params.push(userId);
      }

      const result = await db.queryOne<AssessmentWithDetails>(
        `SELECT a.*,
                e.first_name || ' ' || e.last_name as employee_name,
                ass.first_name || ' ' || ass.last_name as assessor_name,
                a.total_score,
                a.classification,
                COALESCE(score_counts.completed_scores, 0) as completed_scores,
                COALESCE(question_counts.total_questions, 0) as total_questions
         FROM kam_assessments a
         JOIN kam_profiles e ON a.employee_id = e.id
         JOIN kam_profiles ass ON a.assessor_id = ass.id
         LEFT JOIN (
           SELECT assessment_id, COUNT(*) as completed_scores
           FROM kam_assessment_scores
           WHERE assessment_id = $2
           GROUP BY assessment_id
         ) score_counts ON a.id = score_counts.assessment_id
         LEFT JOIN (
           SELECT COUNT(*) as total_questions
           FROM kam_assessment_questions
           WHERE tenant_id = $1 AND is_active = true
         ) question_counts ON true
         WHERE a.tenant_id = $1 AND a.id = $2${additionalWhere}`,
        params
      );

      return result || null;
    } catch (error) {
      logger.error('Failed to get assessment', { 
        error: error instanceof Error ? error.message : error,
        assessmentId,
        tenantId
      });
      return null;
    }
  }

  async updateAssessment(
    tenantId: string,
    assessmentId: string,
    data: UpdateAssessmentRequest
  ): Promise<Assessment | null> {
    try {
      const setParts: string[] = [];
      const params: any[] = [tenantId, assessmentId];
      let paramCount = 2;

      if (data.assessmentDate !== undefined) {
        setParts.push(`assessment_date = $${++paramCount}`);
        params.push(data.assessmentDate);
      }

      if (data.quarter !== undefined) {
        setParts.push(`quarter = $${++paramCount}`);
        params.push(data.quarter);
      }

      if (data.year !== undefined) {
        setParts.push(`year = $${++paramCount}`);
        params.push(data.year);
      }

      if (data.notes !== undefined) {
        setParts.push(`notes = $${++paramCount}`);
        params.push(data.notes);
      }

      if (data.status !== undefined) {
        setParts.push(`status = $${++paramCount}`);
        params.push(data.status);
      }

      if (setParts.length === 0) {
        const current = await this.getAssessmentById(tenantId, assessmentId, '', 'admin');
        return current;
      }

      const result = await db.queryOne<Assessment>(
        `UPDATE kam_assessments 
         SET ${setParts.join(', ')}
         WHERE tenant_id = $1 AND id = $2
         RETURNING *`,
        params
      );

      logger.info('Assessment updated', { assessmentId, tenantId });
      return result;
    } catch (error) {
      logger.error('Failed to update assessment', { 
        error: error instanceof Error ? error.message : error,
        assessmentId,
        tenantId
      });
      throw new Error('Failed to update assessment');
    }
  }

  // Assessment Scoring
  async submitScores(
    tenantId: string,
    assessmentId: string,
    data: SubmitScoresRequest,
    userId: string
  ): Promise<{ success: boolean; totalScore: number; classification: string }> {
    try {
      return await db.transaction(async (client) => {
        // Helper function for client queries
        const clientQueryOne = async <T>(text: string, params: any[]): Promise<T | null> => {
          const result = await client.query(text, params);
          return result.rows[0] || null;
        };

        // Verify assessment exists and user has permission
        const assessment = await clientQueryOne<Assessment>(
          `SELECT * FROM kam_assessments 
           WHERE tenant_id = $1 AND id = $2 AND assessor_id = $3`,
          [tenantId, assessmentId, userId]
        );

        if (!assessment) {
          throw new Error('Assessment not found or access denied');
        }

        // Delete existing scores for this assessment
        await client.query(
          'DELETE FROM kam_assessment_scores WHERE assessment_id = $1',
          [assessmentId]
        );

        // Insert new scores
        for (const scoreData of data.scores) {
          await client.query(
            `INSERT INTO kam_assessment_scores (assessment_id, question_id, score, comments)
             VALUES ($1, $2, $3, $4)`,
            [assessmentId, scoreData.questionId, scoreData.score, scoreData.comments || null]
          );
        }

        // Calculate total score and classification
        const scoreResult = await this.calculateAssessmentScore(tenantId, assessmentId, client, clientQueryOne);

        // Update assessment with calculated values and mark as submitted
        await client.query(
          `UPDATE kam_assessments 
           SET total_score = $1, classification = $2, status = 'submitted'
           WHERE id = $3`,
          [scoreResult.totalScore, scoreResult.classification, assessmentId]
        );

        logger.info('Assessment scores submitted', { 
          assessmentId, 
          totalScore: scoreResult.totalScore,
          classification: scoreResult.classification,
          tenantId,
          userId 
        });

        return {
          success: true,
          totalScore: scoreResult.totalScore,
          classification: scoreResult.classification
        };
      });
    } catch (error) {
      logger.error('Failed to submit assessment scores', { 
        error: error instanceof Error ? error.message : error,
        assessmentId,
        tenantId,
        userId
      });
      throw new Error('Failed to submit assessment scores');
    }
  }

  async getAssessmentScores(
    tenantId: string, 
    assessmentId: string,
    userId: string,
    userRole: string
  ): Promise<Array<AssessmentScore & { question: string; category: string; comments?: string }>> {
    try {
      // Verify access to assessment
      const assessment = await this.getAssessmentById(tenantId, assessmentId, userId, userRole);
      if (!assessment) {
        throw new Error('Assessment not found or access denied');
      }

      const scoresResult = await db.query<AssessmentScore & { question: string; category: string; comments?: string }>(
        `SELECT s.*, q.question, q.category, s.comments
         FROM kam_assessment_scores s
         JOIN kam_assessment_questions q ON s.question_id = q.id
         WHERE s.assessment_id = $1
         ORDER BY q.category, q.sort_order`,
        [assessmentId]
      );

      return scoresResult.rows;
    } catch (error) {
      logger.error('Failed to get assessment scores', { 
        error: error instanceof Error ? error.message : error,
        assessmentId,
        tenantId,
        userId
      });
      throw new Error('Failed to get assessment scores');
    }
  }

  // KAM Classification Logic
  private async calculateAssessmentScore(
    tenantId: string, 
    assessmentId: string,
    client: any,
    clientQueryOne: <T>(text: string, params: any[]) => Promise<T | null>
  ): Promise<{ totalScore: number; classification: string }> {
    try {
      // Get assessment details
      const assessment = await clientQueryOne<Assessment>(
        'SELECT * FROM kam_assessments WHERE id = $1',
        [assessmentId]
      );

      if (!assessment) {
        throw new Error('Assessment not found');
      }

      // Get weighted scores
      const scoreResult = await clientQueryOne<{ weighted_total: number; max_possible: number }>(
        `SELECT 
           SUM(s.score * q.weight) as weighted_total,
           SUM(4 * q.weight) as max_possible
         FROM kam_assessment_scores s
         JOIN kam_assessment_questions q ON s.question_id = q.id
         WHERE s.assessment_id = $1 AND q.is_active = true`,
        [assessmentId]
      );

      if (!scoreResult || !scoreResult.weighted_total) {
        return { totalScore: 0, classification: 'Incomplete' };
      }

      // Convert to percentage
      const totalScore = Math.round((scoreResult.weighted_total / scoreResult.max_possible) * 100);

      // Get classification thresholds (use defaults if not set)
      let thresholds;
      try {
        const settingResult = await clientQueryOne<{ setting_value: any }>(
          `SELECT setting_value FROM kam_tenant_settings 
           WHERE tenant_id = $1 AND setting_key = 'classification_thresholds'`,
          [tenantId]
        );
        thresholds = settingResult?.setting_value?.thresholds || await this.getDefaultThresholds();
      } catch {
        thresholds = await this.getDefaultThresholds();
      }

      // Determine classification based on assessment type and score
      let classification = 'Unclassified';

      if (assessment.assessmentType === AssessmentType.SELF) {
        // Self-assessment classification logic
        if (totalScore >= thresholds.champion_min_self) {
          // Check if there's a manager assessment to compare
          const managerAssessment = await clientQueryOne<{ total_score: number }>(
            `SELECT total_score FROM kam_assessments 
             WHERE tenant_id = $1 AND employee_id = $2 AND assessment_type = 'manager' 
             AND year = $3 AND quarter = $4 AND status = 'submitted'`,
            [tenantId, assessment.employeeId, assessment.year || new Date().getFullYear(), assessment.quarter || 'Q1']
          );

          if (managerAssessment && managerAssessment.total_score >= thresholds.champion_min_total) {
            classification = 'Champion';
          } else if (managerAssessment) {
            classification = 'Go-getter';
          } else {
            classification = 'Potential Go-getter';
          }
        } else {
          classification = 'Developing';
        }
      } else {
        // Manager assessment classification logic
        if (totalScore >= thresholds.champion_min_total) {
          // Check if there's a self assessment to compare
          const selfAssessment = await clientQueryOne<{ total_score: number }>(
            `SELECT total_score FROM kam_assessments 
             WHERE tenant_id = $1 AND employee_id = $2 AND assessment_type = 'self' 
             AND year = $3 AND quarter = $4 AND status = 'submitted'`,
            [tenantId, assessment.employeeId, assessment.year || new Date().getFullYear(), assessment.quarter || 'Q1']
          );

          if (selfAssessment && selfAssessment.total_score >= thresholds.champion_min_self) {
            classification = 'Champion';
          } else if (selfAssessment) {
            classification = 'Paper Tiger';
          } else {
            classification = 'Potential Champion';
          }
        } else if (totalScore >= thresholds.activist_min_total) {
          classification = 'Activist';
        } else {
          classification = 'Developing';
        }
      }

      return { totalScore, classification };
    } catch (error) {
      logger.error('Failed to calculate assessment score', { 
        error: error instanceof Error ? error.message : error,
        assessmentId
      });
      throw error;
    }
  }

  private async getDefaultThresholds(): Promise<any> {
    const result = await db.queryOne<{ get_default_classification_settings: any }>(
      'SELECT get_default_classification_settings() as settings'
    );
    
    if (!result) {
      // Return hardcoded defaults if function fails
      return {
        champion_min_total: 75,
        champion_min_self: 70,
        activist_min_total: 60,
        go_getter_min_self: 70
      };
    }
    
    return result.get_default_classification_settings.thresholds;
  }

  // Analytics
  async getAssessmentAnalytics(
    tenantId: string,
    userId: string,
    userRole: string,
    options: {
      year?: number;
      quarter?: string;
      employeeId?: string;
      departmentFilter?: string;
    } = {}
  ): Promise<AssessmentAnalytics> {
    try {
      let whereConditions = ['a.tenant_id = $1', 'a.status = $2'];
      let params: any[] = [tenantId, AssessmentStatus.SUBMITTED];
      let paramCount = 2;

      // Role-based filtering
      if (userRole === 'user') {
        whereConditions.push(`(a.employee_id = $${++paramCount} OR a.assessor_id = $${++paramCount})`);
        params.push(userId, userId);
        paramCount++;
      } else if (userRole === 'manager') {
        whereConditions.push(`(
          a.employee_id = $${++paramCount} OR 
          a.assessor_id = $${++paramCount} OR
          a.employee_id IN (
            SELECT id FROM kam_profiles 
            WHERE tenant_id = $1 AND manager_id = $${paramCount}
          )
        )`);
        params.push(userId, userId);
        paramCount++;
      }

      if (options.year) {
        whereConditions.push(`a.year = $${++paramCount}`);
        params.push(options.year);
      }

      if (options.quarter) {
        whereConditions.push(`a.quarter = $${++paramCount}`);
        params.push(options.quarter);
      }

      if (options.employeeId) {
        whereConditions.push(`a.employee_id = $${++paramCount}`);
        params.push(options.employeeId);
      }

      if (options.departmentFilter) {
        whereConditions.push(`p.department = $${++paramCount}`);
        params.push(options.departmentFilter);
      }

      const whereClause = whereConditions.join(' AND ');

      // Get basic analytics
      const basicStats = await db.queryOne<{
        total_assessments: number;
        completed_assessments: number;
        average_score: number;
      }>(
        `SELECT 
           COUNT(*) as total_assessments,
           COUNT(CASE WHEN a.status = 'submitted' THEN 1 END) as completed_assessments,
           ROUND(AVG(a.total_score), 2) as average_score
         FROM kam_assessments a
         JOIN kam_profiles p ON a.employee_id = p.id
         WHERE ${whereClause}`,
        params
      );

      if (!basicStats) {
        throw new Error('Failed to get basic analytics');
      }

      // Get classification distribution
      const classificationResult = await db.query<{ classification: string; count: number }>(
        `SELECT 
           a.classification,
           COUNT(*) as count
         FROM kam_assessments a
         JOIN kam_profiles p ON a.employee_id = p.id
         WHERE ${whereClause} AND a.classification IS NOT NULL
         GROUP BY a.classification`,
        params
      );

      const classificationDistribution: Record<string, number> = {};
      classificationResult.rows.forEach(row => {
        classificationDistribution[row.classification] = parseInt(row.count.toString());
      });

      // Get scores by category
      const categoryResult = await db.query<{ category: string; average: number; count: number }>(
        `SELECT 
           q.category,
           ROUND(AVG(s.score), 2) as average,
           COUNT(s.score) as count
         FROM kam_assessment_scores s
         JOIN kam_assessment_questions q ON s.question_id = q.id
         JOIN kam_assessments a ON s.assessment_id = a.id
         JOIN kam_profiles p ON a.employee_id = p.id
         WHERE ${whereClause}
         GROUP BY q.category`,
        params
      );

      const scoresByCategory: Record<string, { average: number; count: number }> = {};
      categoryResult.rows.forEach(row => {
        scoresByCategory[row.category] = {
          average: parseFloat(row.average.toString()),
          count: parseInt(row.count.toString())
        };
      });

      // Get trend data (last 6 quarters)
      const trendResult = await db.query<{ period: string; average_score: number; assessment_count: number }>(
        `SELECT 
           CONCAT(a.year, '-Q', a.quarter) as period,
           ROUND(AVG(a.total_score), 2) as average_score,
           COUNT(*) as assessment_count
         FROM kam_assessments a
         JOIN kam_profiles p ON a.employee_id = p.id
         WHERE a.tenant_id = $1 AND a.status = 'submitted'
           ${userRole === 'user' ? ' AND (a.employee_id = $2 OR a.assessor_id = $2)' : ''}
           ${userRole === 'manager' ? ' AND (a.employee_id = $2 OR a.assessor_id = $2 OR a.employee_id IN (SELECT id FROM kam_profiles WHERE tenant_id = $1 AND manager_id = $2))' : ''}
         GROUP BY a.year, a.quarter
         ORDER BY a.year DESC, a.quarter DESC
         LIMIT 6`,
        userRole === 'admin' ? [tenantId] : [tenantId, userId]
      );

      return {
        totalAssessments: parseInt(basicStats.total_assessments.toString()),
        completedAssessments: parseInt(basicStats.completed_assessments.toString()),
        averageScore: parseFloat(basicStats.average_score.toString()) || 0,
        classificationDistribution,
        scoresByCategory,
        trendData: trendResult.rows.map(row => ({
          period: row.period,
          averageScore: parseFloat(row.average_score.toString()),
          assessmentCount: parseInt(row.assessment_count.toString())
        }))
      };
    } catch (error) {
      logger.error('Failed to get assessment analytics', { 
        error: error instanceof Error ? error.message : error,
        tenantId,
        userId
      });
      throw new Error('Failed to get assessment analytics');
    }
  }

  async getQuestionAnalytics(
    tenantId: string,
    userId: string,
    userRole: string
  ): Promise<QuestionAnalytics> {
    try {
      // Get question stats
      const questionStats = await db.queryOne<{ total_questions: number }>(
        `SELECT COUNT(*) as total_questions
         FROM kam_assessment_questions
         WHERE tenant_id = $1 AND is_active = true`,
        [tenantId]
      );

      if (!questionStats) {
        throw new Error('Failed to get question statistics');
      }

      // Get questions by category
      const categoryResult = await db.query<{ category: string; count: number }>(
        `SELECT category, COUNT(*) as count
         FROM kam_assessment_questions
         WHERE tenant_id = $1 AND is_active = true
         GROUP BY category`,
        [tenantId]
      );

      const questionsByCategory: Record<string, number> = {};
      categoryResult.rows.forEach(row => {
        questionsByCategory[row.category] = parseInt(row.count.toString());
      });

      // Get average score by question (filtered by user role)
      let roleFilter = '';
      let params: any[] = [tenantId];
      
      if (userRole === 'user') {
        roleFilter = ' AND (a.employee_id = $2 OR a.assessor_id = $2)';
        params.push(userId);
      } else if (userRole === 'manager') {
        roleFilter = ` AND (
          a.employee_id = $2 OR 
          a.assessor_id = $2 OR
          a.employee_id IN (
            SELECT id FROM kam_profiles 
            WHERE tenant_id = $1 AND manager_id = $2
          )
        )`;
        params.push(userId);
      }

      const questionScoreResult = await db.query<{
        question_id: string;
        question: string;
        category: string;
        average_score: number;
        response_count: number;
      }>(
        `SELECT 
           q.id as question_id,
           q.question,
           q.category,
           ROUND(AVG(s.score::numeric), 2) as average_score,
           COUNT(s.score) as response_count
         FROM kam_assessment_questions q
         LEFT JOIN kam_assessment_scores s ON q.id = s.question_id
         LEFT JOIN kam_assessments a ON s.assessment_id = a.id
         WHERE q.tenant_id = $1 AND q.is_active = true ${roleFilter}
         GROUP BY q.id, q.question, q.category
         ORDER BY q.category, q.sort_order`,
        params
      );

      const averageScoreByQuestion = questionScoreResult.rows.map(row => ({
        questionId: row.question_id,
        question: row.question,
        category: row.category,
        averageScore: parseFloat(row.average_score?.toString() || '0'),
        responseCount: parseInt(row.response_count.toString())
      }));

      return {
        totalQuestions: parseInt(questionStats.total_questions.toString()),
        questionsByCategory,
        averageScoreByQuestion
      };
    } catch (error) {
      logger.error('Failed to get question analytics', { 
        error: error instanceof Error ? error.message : error,
        tenantId,
        userId
      });
      throw new Error('Failed to get question analytics');
    }
  }

  // Bulk Operations
  async bulkCreateQuestions(
    tenantId: string,
    userId: string,
    questions: CreateQuestionRequest[]
  ): Promise<AssessmentQuestion[]> {
    try {
      return await db.transaction(async (client) => {
        const results: AssessmentQuestion[] = [];

        // Helper function for client queries in transaction
        const clientQueryOne = async <T>(text: string, params: any[]): Promise<T | null> => {
          const result = await client.query(text, params);
          return result.rows[0] || null;
        };

        for (const questionData of questions) {
          const result = await clientQueryOne<AssessmentQuestion>(
            `INSERT INTO kam_assessment_questions 
             (tenant_id, category, question, example, weight, sort_order, created_by)
             VALUES ($1, $2, $3, $4, $5, $6, $7)
             RETURNING *`,
            [
              tenantId,
              questionData.category,
              questionData.question,
              questionData.example || null,
              questionData.weight || 1.00,
              questionData.sortOrder || 0,
              userId
            ]
          );
          
          if (!result) {
            throw new Error('Failed to create question in bulk operation');
          }
          
          results.push(result);
        }

        logger.info('Bulk questions created', { 
          count: questions.length,
          tenantId,
          userId 
        });

        return results;
      });
    } catch (error) {
      logger.error('Failed to bulk create questions', { 
        error: error instanceof Error ? error.message : error,
        tenantId,
        userId
      });
      throw new Error('Failed to bulk create questions');
    }
  }

  async getActiveQuestions(tenantId: string): Promise<AssessmentQuestion[]> {
    try {
      const questionsResult = await db.query<AssessmentQuestion>(
        `SELECT * FROM kam_assessment_questions 
         WHERE tenant_id = $1 AND is_active = true
         ORDER BY category, sort_order`,
        [tenantId]
      );

      return questionsResult.rows;
    } catch (error) {
      logger.error('Failed to get active questions', { 
        error: error instanceof Error ? error.message : error,
        tenantId
      });
      throw new Error('Failed to get active questions');
    }
  }
}

export const assessmentService = new AssessmentService();