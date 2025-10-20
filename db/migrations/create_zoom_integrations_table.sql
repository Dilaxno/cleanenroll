-- Create table for Zoom OAuth integrations
CREATE TABLE IF NOT EXISTS zoom_integrations (
    uid TEXT PRIMARY KEY REFERENCES users(uid) ON DELETE CASCADE,
    access_token TEXT NOT NULL,
    refresh_token TEXT,
    expires_at TIMESTAMPTZ,
    zoom_user_id TEXT,
    zoom_email TEXT,
    connected_at TIMESTAMPTZ DEFAULT NOW(),
    updated_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_zoom_integrations_uid ON zoom_integrations(uid);
CREATE INDEX IF NOT EXISTS idx_zoom_integrations_zoom_user_id ON zoom_integrations(zoom_user_id);

COMMENT ON TABLE zoom_integrations IS 'Stores Zoom OAuth tokens for creating meetings via API';
COMMENT ON COLUMN zoom_integrations.access_token IS 'Zoom OAuth access token';
COMMENT ON COLUMN zoom_integrations.refresh_token IS 'Zoom OAuth refresh token for renewing access';
COMMENT ON COLUMN zoom_integrations.expires_at IS 'When the access token expires';
