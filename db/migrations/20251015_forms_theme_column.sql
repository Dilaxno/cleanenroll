-- Ensure theme JSONB column exists on forms
ALTER TABLE IF EXISTS forms
  ADD COLUMN IF NOT EXISTS theme jsonb DEFAULT '{}'::jsonb;
