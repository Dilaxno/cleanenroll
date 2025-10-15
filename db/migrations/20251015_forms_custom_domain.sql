-- Ensure forms has custom domain fields and index
ALTER TABLE IF EXISTS forms
  ADD COLUMN IF NOT EXISTS custom_domain TEXT,
  ADD COLUMN IF NOT EXISTS custom_domain_verified BOOLEAN DEFAULT FALSE,
  ADD COLUMN IF NOT EXISTS ssl_verified BOOLEAN DEFAULT FALSE;

-- Optional index for faster lookups by domain (used in allow-domain and verify)
CREATE INDEX IF NOT EXISTS idx_forms_custom_domain
  ON forms (custom_domain);
