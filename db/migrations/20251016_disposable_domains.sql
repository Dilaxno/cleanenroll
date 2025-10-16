-- Disposable email domains table
CREATE TABLE IF NOT EXISTS disposable_domains (
  domain TEXT PRIMARY KEY,
  strict BOOLEAN DEFAULT TRUE,
  updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_disposable_updated_at
  ON disposable_domains (updated_at DESC);
