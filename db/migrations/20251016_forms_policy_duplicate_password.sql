-- Add new form controls: password protection, duplicate-by-IP prevention, powered-by watermark, privacy policy URL
-- Safe to run multiple times due to IF NOT EXISTS guards

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS password_protection_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS password_hash TEXT NULL,
  ADD COLUMN IF NOT EXISTS prevent_duplicate_by_ip BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS duplicate_window_hours INTEGER DEFAULT 24,
  ADD COLUMN IF NOT EXISTS show_powered_by BOOLEAN DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS privacy_policy_url TEXT NULL;

-- Optional: ensure NOT NULL defaults where desired (do not force on existing rows)
UPDATE forms
SET
  password_protection_enabled = COALESCE(password_protection_enabled, FALSE),
  prevent_duplicate_by_ip = COALESCE(prevent_duplicate_by_ip, FALSE),
  duplicate_window_hours = COALESCE(duplicate_window_hours, 24),
  show_powered_by = COALESCE(show_powered_by, TRUE)
WHERE TRUE;
