-- Create owners_tracking table for tracking site owner activity
CREATE TABLE IF NOT EXISTS owners_tracking (
    id SERIAL PRIMARY KEY,
    user_id VARCHAR(255) NOT NULL,
    session_id VARCHAR(255) NOT NULL,
    user_email VARCHAR(255),
    ip_address VARCHAR(45),
    city VARCHAR(255),
    country VARCHAR(255),
    country_code VARCHAR(2),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    current_page TEXT,
    referrer TEXT,
    user_agent TEXT,
    device_type VARCHAR(50),
    browser VARCHAR(100),
    os VARCHAR(100),
    screen_width INTEGER,
    screen_height INTEGER,
    metadata JSONB,
    first_seen TIMESTAMP NOT NULL,
    last_seen TIMESTAMP NOT NULL,
    is_active BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast lookups by user_id and active status
CREATE INDEX IF NOT EXISTS idx_owners_tracking_user_active 
ON owners_tracking(user_id, is_active, last_seen);

-- Index for session_id lookups
CREATE INDEX IF NOT EXISTS idx_owners_tracking_session 
ON owners_tracking(session_id);

-- Index for cleanup queries (remove old inactive sessions)
CREATE INDEX IF NOT EXISTS idx_owners_tracking_last_seen 
ON owners_tracking(last_seen);

-- Index for country-based analytics
CREATE INDEX IF NOT EXISTS idx_owners_tracking_country 
ON owners_tracking(country_code);

-- Index for user email lookups
CREATE INDEX IF NOT EXISTS idx_owners_tracking_email 
ON owners_tracking(user_email);

-- Add foreign key constraint to users table if it exists
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name = 'users') THEN
        ALTER TABLE owners_tracking 
        ADD CONSTRAINT fk_owners_tracking_user 
        FOREIGN KEY (user_id) REFERENCES users(uid) ON DELETE CASCADE;
    END IF;
END $$;
