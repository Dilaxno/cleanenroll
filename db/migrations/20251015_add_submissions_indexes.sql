-- Ensure submissions table has required columns for Neon-backed responses
ALTER TABLE IF EXISTS submissions
  ADD COLUMN IF NOT EXISTS form_owner_id TEXT,
  ADD COLUMN IF NOT EXISTS data JSONB,
  ADD COLUMN IF NOT EXISTS metadata JSONB,
  ADD COLUMN IF NOT EXISTS ip_address TEXT,
  ADD COLUMN IF NOT EXISTS country_code TEXT,
  ADD COLUMN IF NOT EXISTS user_agent TEXT,
  ADD COLUMN IF NOT EXISTS submitted_at TIMESTAMPTZ DEFAULT NOW();

-- Indexes to support limits and dedupe efficiently
CREATE INDEX IF NOT EXISTS idx_submissions_owner_month
  ON submissions (form_owner_id, submitted_at);

CREATE INDEX IF NOT EXISTS idx_submissions_form_date
  ON submissions (form_id, submitted_at);

CREATE INDEX IF NOT EXISTS idx_submissions_form_ip_date
  ON submissions (form_id, ip_address, submitted_at);
