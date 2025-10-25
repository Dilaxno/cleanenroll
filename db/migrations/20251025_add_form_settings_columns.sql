-- Add all form settings columns to forms table
-- Date: 2025-10-25
-- Description: Add individual columns for all form settings (language, thank you, auto-reply, email validation, security, etc.)

-- Language and thank you settings
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS language VARCHAR(10) DEFAULT 'en',
  ADD COLUMN IF NOT EXISTS show_top_progress BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS show_keyboard_hints BOOLEAN DEFAULT FALSE;

-- Auto-reply email settings (add missing columns)
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS auto_reply_message_text TEXT,
  ADD COLUMN IF NOT EXISTS auto_reply_content_mode VARCHAR(20) DEFAULT 'html',
  ADD COLUMN IF NOT EXISTS auto_reply_footer_html TEXT;

-- Email validation settings
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS email_validation_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS professional_emails_only BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS block_role_emails BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS email_reject_bad_reputation BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS min_domain_age_days INTEGER DEFAULT 30;

-- Duplicate prevention settings
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS prevent_duplicate_by_uid BOOLEAN DEFAULT FALSE;

-- Security settings
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS recaptcha_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS url_scan_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS file_scan_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS gdpr_compliance_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS privacy_policy_url TEXT;

-- Custom domain settings
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS custom_domain_verified BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS ssl_verified BOOLEAN DEFAULT FALSE;

-- Geo restrictions
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS restricted_countries JSONB DEFAULT '[]'::jsonb,
  ADD COLUMN IF NOT EXISTS allowed_countries JSONB DEFAULT '[]'::jsonb;

-- Redirect settings
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS redirect JSONB;

-- Submit button, title/subtitle styles
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS submit_button JSONB,
  ADD COLUMN IF NOT EXISTS title_style JSONB,
  ADD COLUMN IF NOT EXISTS subtitle_style JSONB;

-- Full page layout settings
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS full_page_progress_enabled BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS full_page_keyboard_hints_enabled BOOLEAN DEFAULT FALSE;

-- Add indexes for frequently queried boolean columns
CREATE INDEX IF NOT EXISTS idx_forms_is_published ON forms(is_published);
CREATE INDEX IF NOT EXISTS idx_forms_recaptcha_enabled ON forms(recaptcha_enabled);
CREATE INDEX IF NOT EXISTS idx_forms_email_validation_enabled ON forms(email_validation_enabled);

-- Add comment
COMMENT ON TABLE forms IS 'Forms table with all settings stored in individual columns for queryability and type safety';
