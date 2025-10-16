-- Migration: add extended form settings columns to forms table (idempotent)
-- This includes redirect config, reCAPTCHA, GDPR, email validation flags,
-- allowed/restricted countries lists, publishing flags, and misc settings.

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS language VARCHAR(10),
  ADD COLUMN IF NOT EXISTS thank_you_message TEXT,
  ADD COLUMN IF NOT EXISTS redirect JSONB,
  ADD COLUMN IF NOT EXISTS email_validation_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS professional_emails_only BOOLEAN,
  ADD COLUMN IF NOT EXISTS block_role_emails BOOLEAN,
  ADD COLUMN IF NOT EXISTS email_reject_bad_reputation BOOLEAN,
  ADD COLUMN IF NOT EXISTS min_domain_age_days INTEGER,
  ADD COLUMN IF NOT EXISTS recaptcha_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS url_scan_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS gdpr_compliance_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS show_powered_by BOOLEAN,
  ADD COLUMN IF NOT EXISTS privacy_policy_url TEXT,
  ADD COLUMN IF NOT EXISTS password_protection_enabled BOOLEAN,
  ADD COLUMN IF NOT EXISTS password_hash TEXT,
  ADD COLUMN IF NOT EXISTS prevent_duplicate_by_ip BOOLEAN,
  ADD COLUMN IF NOT EXISTS duplicate_window_hours INTEGER,
  ADD COLUMN IF NOT EXISTS restricted_countries JSONB,
  ADD COLUMN IF NOT EXISTS allowed_countries JSONB,
  ADD COLUMN IF NOT EXISTS is_published BOOLEAN,
  ADD COLUMN IF NOT EXISTS form_type VARCHAR(50),
  ADD COLUMN IF NOT EXISTS embed_allow_list JSONB;

-- Helpful defaults (optional): leave NULL to let application logic decide
