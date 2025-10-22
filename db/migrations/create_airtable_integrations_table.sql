-- Create table for Airtable OAuth integrations and mappings
CREATE TABLE IF NOT EXISTS airtable_integrations (
    uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
    access_token TEXT,
    refresh_token TEXT,
    expires_at TIMESTAMPTZ,
    scopes TEXT[],
    mappings JSONB DEFAULT '{}'::jsonb,
    connected_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_airtable_integrations_uid ON airtable_integrations(uid);

COMMENT ON TABLE airtable_integrations IS 'Stores Airtable OAuth tokens and form-to-table mappings';
COMMENT ON COLUMN airtable_integrations.access_token IS 'Airtable OAuth access token';
COMMENT ON COLUMN airtable_integrations.refresh_token IS 'Airtable OAuth refresh token for renewing access';
COMMENT ON COLUMN airtable_integrations.expires_at IS 'When the access token expires';
COMMENT ON COLUMN airtable_integrations.scopes IS 'Array of granted OAuth scopes';
COMMENT ON COLUMN airtable_integrations.mappings IS 'JSONB object containing form-to-Airtable-table mappings';
