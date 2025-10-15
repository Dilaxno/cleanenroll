-- Create table to store per-form, per-day country counts
CREATE TABLE IF NOT EXISTS form_countries_analytics (
  form_id TEXT NOT NULL,
  day DATE NOT NULL,
  country_iso2 TEXT NOT NULL,
  count INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (form_id, day, country_iso2)
);

-- Helpful indexes for range queries and aggregations
CREATE INDEX IF NOT EXISTS idx_fca_form_day ON form_countries_analytics (form_id, day);
CREATE INDEX IF NOT EXISTS idx_fca_form_country ON form_countries_analytics (form_id, country_iso2);
