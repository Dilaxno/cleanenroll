-- Add honeypot_enabled column for bot protection
-- Safe to run multiple times due to IF NOT EXISTS guard

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS honeypot_enabled BOOLEAN DEFAULT FALSE;

-- Ensure NOT NULL default on existing rows
UPDATE forms
SET honeypot_enabled = COALESCE(honeypot_enabled, FALSE)
WHERE honeypot_enabled IS NULL;
