-- Add R2 link, recording name, and duration to sessions table
-- Migration: 20250119_sessions_r2_metadata

ALTER TABLE sessions
ADD COLUMN IF NOT EXISTS r2_url TEXT,
ADD COLUMN IF NOT EXISTS recording_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS duration INTEGER;

-- Create index for querying by form_id and r2_url existence
CREATE INDEX IF NOT EXISTS idx_sessions_r2_url ON sessions(form_id) WHERE r2_url IS NOT NULL;

-- Comments
COMMENT ON COLUMN sessions.r2_url IS 'Cloudflare R2 URL for the exported/finalized session recording';
COMMENT ON COLUMN sessions.recording_name IS 'Human-readable name for the session recording';
COMMENT ON COLUMN sessions.duration IS 'Duration of the recording in milliseconds';
