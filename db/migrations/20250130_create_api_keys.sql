-- Create API keys table for developer platform
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL, -- First 8 chars for display (e.g., "ce_live_12345678...")
    name VARCHAR(255) NOT NULL,
    environment VARCHAR(20) NOT NULL DEFAULT 'production', -- 'production' or 'test'
    permissions JSONB DEFAULT '{"validate": true, "protect": true, "analytics": true}'::jsonb,
    created_at TIMESTAMP DEFAULT NOW(),
    last_used_at TIMESTAMP,
    expires_at TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE,
    metadata JSONB DEFAULT '{}'::jsonb
);

-- Create indexes for performance
CREATE INDEX idx_api_keys_user_id ON api_keys(user_id);
CREATE INDEX idx_api_keys_key_hash ON api_keys(key_hash);
CREATE INDEX idx_api_keys_is_active ON api_keys(is_active);
CREATE INDEX idx_api_keys_environment ON api_keys(environment);

-- Create API usage logs table
CREATE TABLE IF NOT EXISTS api_usage_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id UUID REFERENCES api_keys(id) ON DELETE CASCADE,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    ip_address INET,
    user_agent TEXT,
    request_data JSONB,
    error_message TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create indexes for API logs
CREATE INDEX idx_api_usage_logs_api_key_id ON api_usage_logs(api_key_id);
CREATE INDEX idx_api_usage_logs_created_at ON api_usage_logs(created_at);
CREATE INDEX idx_api_usage_logs_endpoint ON api_usage_logs(endpoint);

-- Create API quota table for rate limiting
CREATE TABLE IF NOT EXISTS api_quotas (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    plan_type VARCHAR(50) DEFAULT 'free', -- 'free', 'pro', 'business', 'enterprise'
    monthly_requests INTEGER DEFAULT 1000,
    requests_used INTEGER DEFAULT 0,
    reset_date TIMESTAMP DEFAULT (NOW() + INTERVAL '1 month'),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(user_id)
);

-- Create index for quotas
CREATE INDEX idx_api_quotas_user_id ON api_quotas(user_id);
CREATE INDEX idx_api_quotas_reset_date ON api_quotas(reset_date);
