-- Create tables for tracking submission files and signatures with clean URLs
-- This replaces direct R2 URL exposure with secure proxy links

-- Submission files table
CREATE TABLE IF NOT EXISTS submission_files (
    id VARCHAR(16) PRIMARY KEY,
    form_id VARCHAR(64) NOT NULL,
    response_id VARCHAR(64) NOT NULL,
    r2_key TEXT NOT NULL,
    filename TEXT NOT NULL,
    content_type VARCHAR(255) DEFAULT 'application/octet-stream',
    size_bytes BIGINT DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_submission_files_response ON submission_files(response_id);
CREATE INDEX IF NOT EXISTS idx_submission_files_form ON submission_files(form_id);

-- Submission signatures table
CREATE TABLE IF NOT EXISTS submission_signatures (
    id VARCHAR(16) PRIMARY KEY,
    form_id VARCHAR(64) NOT NULL,
    response_id VARCHAR(64) NOT NULL,
    field_id VARCHAR(64) NOT NULL,
    r2_key TEXT NOT NULL,
    filename TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_submission_signatures_response ON submission_signatures(response_id);
CREATE INDEX IF NOT EXISTS idx_submission_signatures_form ON submission_signatures(form_id);
