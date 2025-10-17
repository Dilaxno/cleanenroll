-- Add file safety check flag to forms table
-- Safe to run multiple times due to IF NOT EXISTS guard

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS file_safety_check_enabled BOOLEAN DEFAULT FALSE;

-- Set default for existing rows
UPDATE forms
SET file_safety_check_enabled = COALESCE(file_safety_check_enabled, FALSE)
WHERE file_safety_check_enabled IS NULL;
