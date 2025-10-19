-- Create live_visitors table for real-time visitor tracking
CREATE TABLE IF NOT EXISTS live_visitors (
    id SERIAL PRIMARY KEY,
    form_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) NOT NULL UNIQUE,
    ip_address VARCHAR(45),
    city VARCHAR(255),
    country VARCHAR(255),
    country_code VARCHAR(2),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    user_agent TEXT,
    referrer TEXT,
    screen_width INTEGER,
    screen_height INTEGER,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast lookups by form_id and active status
CREATE INDEX IF NOT EXISTS idx_live_visitors_form_active 
ON live_visitors(form_id, is_active, last_seen);

-- Index for session_id lookups
CREATE INDEX IF NOT EXISTS idx_live_visitors_session 
ON live_visitors(session_id);

-- Index for cleanup queries
CREATE INDEX IF NOT EXISTS idx_live_visitors_last_seen 
ON live_visitors(last_seen);
