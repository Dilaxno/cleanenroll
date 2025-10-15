-- Analytics tables in Neon (no Supabase)

-- Ensure required pgcrypto or gen_random_uuid is available
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Daily countries aggregation per form
CREATE TABLE IF NOT EXISTS form_daily_countries (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  form_id TEXT NOT NULL,
  day DATE NOT NULL,
  country_code TEXT,
  count INTEGER NOT NULL DEFAULT 0
);

-- Uniqueness for upsert
CREATE UNIQUE INDEX IF NOT EXISTS uq_form_daily_countries
  ON form_daily_countries (form_id, day, country_code);

-- Helpful indexes
CREATE INDEX IF NOT EXISTS idx_fdc_form_day
  ON form_daily_countries (form_id, day);

CREATE INDEX IF NOT EXISTS idx_fdc_form_country_day
  ON form_daily_countries (form_id, country_code, day);

-- Submission markers table (if not already created elsewhere)
CREATE TABLE IF NOT EXISTS submission_markers (
  id UUID PRIMARY KEY,
  form_id TEXT NOT NULL,
  response_id TEXT NOT NULL,
  lat DOUBLE PRECISION,
  lon DOUBLE PRECISION,
  country_code TEXT,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_submission_markers_form_created
  ON submission_markers (form_id, created_at);

CREATE INDEX IF NOT EXISTS idx_submission_markers_form_country
  ON submission_markers (form_id, country_code);
