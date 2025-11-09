-- Add domain-specific reCAPTCHA key storage
-- Each custom domain gets its own site key/secret pair for proper domain validation

ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS recaptcha_site_key VARCHAR(255),
  ADD COLUMN IF NOT EXISTS recaptcha_secret_key VARCHAR(255),
  ADD COLUMN IF NOT EXISTS recaptcha_key_created_at TIMESTAMP WITH TIME ZONE;

-- Create index for faster key lookups
CREATE INDEX IF NOT EXISTS idx_forms_custom_domain ON forms(custom_domain) WHERE custom_domain IS NOT NULL;

-- Add comment
COMMENT ON COLUMN forms.recaptcha_site_key IS 'Domain-specific reCAPTCHA v2 site key (public)';
COMMENT ON COLUMN forms.recaptcha_secret_key IS 'Domain-specific reCAPTCHA v2 secret key (encrypted)';
COMMENT ON COLUMN forms.recaptcha_key_created_at IS 'Timestamp when reCAPTCHA keys were provisioned';
