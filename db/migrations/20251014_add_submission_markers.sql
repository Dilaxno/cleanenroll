-- Migration: add submission_markers table to replace Firestore submissions_markers
-- Safe to run multiple times

CREATE TABLE IF NOT EXISTS submission_markers (
    id VARCHAR(128) PRIMARY KEY,
    form_id VARCHAR(128) NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    response_id VARCHAR(128),
    lat DOUBLE PRECISION,
    lon DOUBLE PRECISION,
    country_code VARCHAR(2),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_submission_markers_form_id ON submission_markers(form_id);
