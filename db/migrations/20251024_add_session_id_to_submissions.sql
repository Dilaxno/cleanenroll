-- Add session_id column to submissions table for completion time analytics
ALTER TABLE submissions
  ADD COLUMN IF NOT EXISTS session_id TEXT;

-- Create index for session-based analytics queries
CREATE INDEX IF NOT EXISTS idx_submissions_session_id
  ON submissions (session_id)
  WHERE session_id IS NOT NULL;
