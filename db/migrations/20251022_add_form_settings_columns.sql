-- Add missing form settings columns that are used in the builder
-- These columns ensure all form settings persist across sessions
-- Safe to run multiple times due to IF NOT EXISTS guards

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS subtitle TEXT,
  ADD COLUMN IF NOT EXISTS language VARCHAR(10) DEFAULT 'en',
  ADD COLUMN IF NOT EXISTS redirect JSONB,
  ADD COLUMN IF NOT EXISTS title_style JSONB,
  ADD COLUMN IF NOT EXISTS subtitle_style JSONB,
  ADD COLUMN IF NOT EXISTS recaptcha_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS gdpr_compliance_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS url_scan_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS file_safety_check_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS email_validation_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS professional_emails_only BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS block_role_emails BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS email_reject_bad_reputation BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS min_domain_age_days INTEGER DEFAULT 30,
  ADD COLUMN IF NOT EXISTS restricted_countries JSONB,
  ADD COLUMN IF NOT EXISTS show_top_progress BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS show_keyboard_hints BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS session_recording_enabled BOOLEAN DEFAULT TRUE,
  ADD COLUMN IF NOT EXISTS submit_button JSONB;

-- Ensure defaults for existing rows
UPDATE forms
SET
  language = COALESCE(language, 'en'),
  recaptcha_enabled = COALESCE(recaptcha_enabled, FALSE),
  gdpr_compliance_enabled = COALESCE(gdpr_compliance_enabled, FALSE),
  url_scan_enabled = COALESCE(url_scan_enabled, FALSE),
  file_safety_check_enabled = COALESCE(file_safety_check_enabled, FALSE),
  email_validation_enabled = COALESCE(email_validation_enabled, FALSE),
  professional_emails_only = COALESCE(professional_emails_only, FALSE),
  block_role_emails = COALESCE(block_role_emails, FALSE),
  email_reject_bad_reputation = COALESCE(email_reject_bad_reputation, FALSE),
  min_domain_age_days = COALESCE(min_domain_age_days, 30),
  show_top_progress = COALESCE(show_top_progress, FALSE),
  show_keyboard_hints = COALESCE(show_keyboard_hints, FALSE),
  session_recording_enabled = COALESCE(session_recording_enabled, TRUE)
WHERE TRUE;

-- Create indexes for commonly queried fields
CREATE INDEX IF NOT EXISTS idx_forms_language ON forms(language);
CREATE INDEX IF NOT EXISTS idx_forms_recaptcha_enabled ON forms(recaptcha_enabled);
