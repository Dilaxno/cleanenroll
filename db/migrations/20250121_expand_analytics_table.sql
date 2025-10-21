-- Expand analytics table to include all metrics from form_analytics_events
-- This migration adds columns to match the rich data captured in form_analytics_events

-- Add new columns to analytics table
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS user_id TEXT;
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS session_id TEXT;
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS visitor_id TEXT;
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS device_info JSONB;
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS ts TIMESTAMPTZ;

-- Rename event_type to type for consistency
-- Note: This is a non-destructive operation if column already exists
DO $$ 
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'analytics' AND column_name = 'event_type'
    ) THEN
        ALTER TABLE analytics RENAME COLUMN event_type TO type;
    END IF;
EXCEPTION
    WHEN duplicate_column THEN NULL;
END $$;

-- Add type column if it doesn't exist (in case event_type didn't exist)
ALTER TABLE analytics ADD COLUMN IF NOT EXISTS type VARCHAR(50);

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_analytics_session ON analytics(session_id) WHERE session_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_analytics_visitor ON analytics(visitor_id) WHERE visitor_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_analytics_type ON analytics(form_id, type);
CREATE INDEX IF NOT EXISTS idx_analytics_ts ON analytics(form_id, ts) WHERE ts IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_analytics_user ON analytics(user_id) WHERE user_id IS NOT NULL;

-- Update existing records to have ts from created_at if ts is null
UPDATE analytics SET ts = created_at WHERE ts IS NULL;

COMMENT ON TABLE analytics IS 'Unified analytics table storing all form interaction events with rich metadata';
COMMENT ON COLUMN analytics.user_id IS 'User ID if authenticated';
COMMENT ON COLUMN analytics.session_id IS 'Browser session ID for tracking user journey';
COMMENT ON COLUMN analytics.visitor_id IS 'Stable visitor ID across sessions';
COMMENT ON COLUMN analytics.device_info IS 'JSON containing deviceType, browser, os, userAgent';
COMMENT ON COLUMN analytics.ts IS 'Event timestamp from client';
COMMENT ON COLUMN analytics.type IS 'Event type: view, start, field_focus, field_filled, field_error, submit, email_typo_suggested, email_typo_corrected';
