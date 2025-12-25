-- OAuth 2.0 Provider Schema for CleanEnroll
-- Implements RFC 6749 compliant OAuth 2.0 authorization server

-- OAuth Clients (third-party applications)
CREATE TABLE IF NOT EXISTS oauth_clients (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) UNIQUE NOT NULL,
    client_secret_hash VARCHAR(128) NOT NULL,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    redirect_uris TEXT[] NOT NULL,
    allowed_scopes TEXT[] NOT NULL DEFAULT ARRAY['forms:read'],
    grant_types TEXT[] NOT NULL DEFAULT ARRAY['authorization_code', 'refresh_token'],
    is_confidential BOOLEAN DEFAULT TRUE,
    is_active BOOLEAN DEFAULT TRUE,
    logo_url TEXT,
    website_url TEXT,
    privacy_policy_url TEXT,
    terms_of_service_url TEXT,
    webhook_url TEXT,
    webhook_secret VARCHAR(64),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_clients_client_id ON oauth_clients(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_clients_user_id ON oauth_clients(user_id);

-- Authorization Codes (short-lived, single use)
CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    code VARCHAR(128) UNIQUE NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    scope TEXT NOT NULL,
    code_challenge VARCHAR(128),
    code_challenge_method VARCHAR(10),
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_code ON oauth_authorization_codes(code);
CREATE INDEX IF NOT EXISTS idx_oauth_auth_codes_client_id ON oauth_authorization_codes(client_id);

-- Access Tokens
CREATE TABLE IF NOT EXISTS oauth_access_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(128) UNIQUE NOT NULL,
    client_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_hash ON oauth_access_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_user_id ON oauth_access_tokens(user_id);
CREATE INDEX IF NOT EXISTS idx_oauth_access_tokens_client_id ON oauth_access_tokens(client_id);

-- Refresh Tokens (long-lived)
CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash VARCHAR(128) UNIQUE NOT NULL,
    access_token_id UUID REFERENCES oauth_access_tokens(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL,
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    scope TEXT NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    revoked_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_hash ON oauth_refresh_tokens(token_hash);
CREATE INDEX IF NOT EXISTS idx_oauth_refresh_tokens_user_id ON oauth_refresh_tokens(user_id);

-- User Consent Records
CREATE TABLE IF NOT EXISTS oauth_consents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL,
    scope TEXT NOT NULL,
    granted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    revoked_at TIMESTAMP WITH TIME ZONE,
    UNIQUE(user_id, client_id)
);

CREATE INDEX IF NOT EXISTS idx_oauth_consents_user_client ON oauth_consents(user_id, client_id);

-- Webhook Events Queue
CREATE TABLE IF NOT EXISTS oauth_webhook_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    client_id VARCHAR(64) NOT NULL,
    event_type VARCHAR(50) NOT NULL,
    payload JSONB NOT NULL,
    signature VARCHAR(128) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',
    attempts INTEGER DEFAULT 0,
    last_attempt_at TIMESTAMP WITH TIME ZONE,
    delivered_at TIMESTAMP WITH TIME ZONE,
    error_message TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_webhook_events_client_id ON oauth_webhook_events(client_id);
CREATE INDEX IF NOT EXISTS idx_oauth_webhook_events_status ON oauth_webhook_events(status);

-- Webhook Delivery Log
CREATE TABLE IF NOT EXISTS oauth_webhook_deliveries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    event_id UUID NOT NULL REFERENCES oauth_webhook_events(id) ON DELETE CASCADE,
    client_id VARCHAR(64) NOT NULL,
    webhook_url TEXT NOT NULL,
    status_code INTEGER,
    response_body TEXT,
    response_time_ms INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_oauth_webhook_deliveries_event_id ON oauth_webhook_deliveries(event_id);
