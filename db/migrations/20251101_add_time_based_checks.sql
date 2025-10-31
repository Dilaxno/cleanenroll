-- Add time-based submission check columns for bot protection
-- Safe to run multiple times due to IF NOT EXISTS guards

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS time_based_check_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS min_submission_time INTEGER DEFAULT 3;

-- Ensure NOT NULL defaults on existing rows
UPDATE forms
SET 
  time_based_check_enabled = COALESCE(time_based_check_enabled, FALSE),
  min_submission_time = COALESCE(min_submission_time, 3)
WHERE time_based_check_enabled IS NULL OR min_submission_time IS NULL;
