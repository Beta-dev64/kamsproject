-- UP

-- Enable UUID extension
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";
CREATE EXTENSION IF NOT EXISTS "pgcrypto";

-- Tenants table - the core of multi-tenancy
CREATE TABLE kam_tenants (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    name VARCHAR(255) NOT NULL,
    domain VARCHAR(255) UNIQUE NOT NULL,
    settings JSONB DEFAULT '{}',
    subscription_tier VARCHAR(50) DEFAULT 'basic' CHECK (subscription_tier IN ('basic', 'standard', 'premium', 'enterprise')),
    max_users INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Profiles/Users table with tenant isolation
CREATE TABLE kam_profiles (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    email VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user' CHECK (role IN ('super_admin', 'tenant_admin', 'manager', 'user')),
    department VARCHAR(100),
    manager_id UUID REFERENCES kam_profiles(id),
    is_active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,
    mfa_secret VARCHAR(255),
    mfa_enabled BOOLEAN DEFAULT false,
    password_reset_token VARCHAR(255),
    password_reset_expires TIMESTAMP WITH TIME ZONE,
    email_verified BOOLEAN DEFAULT false,
    email_verification_token VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    deleted_at TIMESTAMP WITH TIME ZONE
);

-- Assessment Questions table
CREATE TABLE kam_assessment_questions (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    category VARCHAR(100) NOT NULL,
    question TEXT NOT NULL,
    example TEXT,
    weight DECIMAL(3,2) DEFAULT 1.00,
    is_active BOOLEAN DEFAULT true,
    sort_order INTEGER DEFAULT 0,
    created_by UUID REFERENCES kam_profiles(id),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Assessments table
CREATE TABLE kam_assessments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    employee_id UUID REFERENCES kam_profiles(id) ON DELETE CASCADE,
    assessor_id UUID REFERENCES kam_profiles(id) ON DELETE CASCADE,
    assessment_type VARCHAR(20) NOT NULL CHECK (assessment_type IN ('manager', 'self')),
    assessment_date DATE NOT NULL,
    quarter VARCHAR(6),
    year INTEGER,
    status VARCHAR(20) DEFAULT 'draft' CHECK (status IN ('draft', 'submitted', 'completed', 'archived')),
    notes TEXT,
    total_score DECIMAL(5,2),
    classification VARCHAR(50),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Assessment Scores table
CREATE TABLE kam_assessment_scores (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    assessment_id UUID REFERENCES kam_assessments(id) ON DELETE CASCADE,
    question_id UUID REFERENCES kam_assessment_questions(id) ON DELETE CASCADE,
    score INTEGER NOT NULL CHECK (score BETWEEN 1 AND 4),
    comments TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Tenant Settings table
CREATE TABLE kam_tenant_settings (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    setting_key VARCHAR(100) NOT NULL,
    setting_value JSONB NOT NULL,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    UNIQUE(tenant_id, setting_key)
);

-- Audit Log table
CREATE TABLE kam_audit_logs (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
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

-- Refresh Tokens table for JWT management
CREATE TABLE kam_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    user_id UUID REFERENCES kam_profiles(id) ON DELETE CASCADE,
    token_hash VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- File attachments table (for avatars, documents, etc.)
CREATE TABLE kam_attachments (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    tenant_id UUID REFERENCES kam_tenants(id) ON DELETE CASCADE,
    uploaded_by UUID REFERENCES kam_profiles(id),
    filename VARCHAR(255) NOT NULL,
    original_name VARCHAR(255) NOT NULL,
    mime_type VARCHAR(100) NOT NULL,
    file_size INTEGER NOT NULL,
    storage_path TEXT NOT NULL,
    resource_type VARCHAR(50) NOT NULL,
    resource_id UUID,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for performance and tenant isolation

-- Tenant isolation indexes
CREATE INDEX idx_profiles_tenant_id ON kam_profiles(tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_assessments_tenant_id ON kam_assessments(tenant_id);
CREATE INDEX idx_assessment_questions_tenant_id ON kam_assessment_questions(tenant_id) WHERE is_active = true;
CREATE INDEX idx_tenant_settings_tenant_id ON kam_tenant_settings(tenant_id);
CREATE INDEX idx_audit_logs_tenant_id ON kam_audit_logs(tenant_id);
CREATE INDEX idx_attachments_tenant_id ON kam_attachments(tenant_id);

-- Query performance indexes
CREATE INDEX idx_profiles_email_tenant ON kam_profiles(email, tenant_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_profiles_manager_id ON kam_profiles(manager_id) WHERE deleted_at IS NULL;
CREATE INDEX idx_assessments_employee_date ON kam_assessments(employee_id, assessment_date DESC);
CREATE INDEX idx_assessments_assessor_id ON kam_assessments(assessor_id);
CREATE INDEX idx_assessment_scores_assessment_id ON kam_assessment_scores(assessment_id);
CREATE INDEX idx_refresh_tokens_user_id ON kam_refresh_tokens(user_id) WHERE is_active = true;
CREATE INDEX idx_audit_logs_tenant_action ON kam_audit_logs(tenant_id, action, created_at DESC);
CREATE INDEX idx_audit_logs_user_id ON kam_audit_logs(user_id, created_at DESC);

-- Full-text search index for questions
CREATE INDEX idx_assessment_questions_search ON kam_assessment_questions 
    USING gin(to_tsvector('english', question || ' ' || COALESCE(example, ''))) 
    WHERE is_active = true;

-- Unique constraints
CREATE UNIQUE INDEX idx_profiles_email_unique ON kam_profiles(email) WHERE deleted_at IS NULL;
CREATE UNIQUE INDEX idx_tenants_domain_unique ON kam_tenants(domain) WHERE deleted_at IS NULL;

-- Create updated_at trigger function
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add updated_at triggers
CREATE TRIGGER update_kam_tenants_updated_at BEFORE UPDATE ON kam_tenants 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_kam_profiles_updated_at BEFORE UPDATE ON kam_profiles 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_kam_assessment_questions_updated_at BEFORE UPDATE ON kam_assessment_questions 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_kam_assessments_updated_at BEFORE UPDATE ON kam_assessments 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

CREATE TRIGGER update_kam_tenant_settings_updated_at BEFORE UPDATE ON kam_tenant_settings 
    FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();

-- RLS (Row Level Security) policies for additional tenant isolation
ALTER TABLE kam_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE kam_assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE kam_assessment_questions ENABLE ROW LEVEL SECURITY;
ALTER TABLE kam_assessment_scores ENABLE ROW LEVEL SECURITY;
ALTER TABLE kam_tenant_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE kam_audit_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE kam_attachments ENABLE ROW LEVEL SECURITY;

-- Default classification thresholds function
CREATE OR REPLACE FUNCTION get_default_classification_settings()
RETURNS JSONB AS $$
BEGIN
    RETURN jsonb_build_object(
        'thresholds', jsonb_build_object(
            'champion_min_total', 75,
            'champion_min_self', 70,
            'activist_min_total', 60,
            'go_getter_min_self', 70
        ),
        'labels', jsonb_build_object(
            'champion', 'Champion',
            'activist', 'Activist', 
            'paper_tiger', 'Paper Tiger',
            'go_getter', 'Go-getter'
        ),
        'colors', jsonb_build_object(
            'champion', '#10B981',
            'activist', '#F59E0B',
            'paper_tiger', '#EF4444',
            'go_getter', '#8B5CF6'
        )
    );
END;
$$ LANGUAGE plpgsql;

-- DOWN

-- Drop all tables in reverse dependency order
DROP TABLE IF EXISTS kam_attachments CASCADE;
DROP TABLE IF EXISTS kam_refresh_tokens CASCADE;
DROP TABLE IF EXISTS kam_audit_logs CASCADE;
DROP TABLE IF EXISTS kam_tenant_settings CASCADE;
DROP TABLE IF EXISTS kam_assessment_scores CASCADE;
DROP TABLE IF EXISTS kam_assessments CASCADE;
DROP TABLE IF EXISTS kam_assessment_questions CASCADE;
DROP TABLE IF EXISTS kam_profiles CASCADE;
DROP TABLE IF EXISTS kam_tenants CASCADE;

-- Drop functions
DROP FUNCTION IF EXISTS update_updated_at_column() CASCADE;
DROP FUNCTION IF EXISTS get_default_classification_settings() CASCADE;

-- Drop extensions (be careful in production)
-- DROP EXTENSION IF EXISTS "uuid-ossp";
-- DROP EXTENSION IF EXISTS "pgcrypto";