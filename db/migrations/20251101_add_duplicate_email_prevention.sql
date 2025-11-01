-- Add duplicate email prevention column for bot protection
-- Safe to run multiple times due to IF NOT EXISTS guard

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS prevent_duplicate_email BOOLEAN DEFAULT FALSE;

-- Ensure NOT NULL default on existing rows
UPDATE forms
SET prevent_duplicate_email = COALESCE(prevent_duplicate_email, FALSE)
WHERE prevent_duplicate_email IS NULL;
