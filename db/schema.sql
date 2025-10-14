-- CleanEnroll PostgreSQL Schema
-- This schema maintains the same data organization as Firestore
-- with user UID as the foreign key across all tables

-- Users table to store Firebase Auth UIDs and related info
CREATE TABLE users (
    uid VARCHAR(128) PRIMARY KEY,
    email VARCHAR(255),
    display_name VARCHAR(255),
    photo_url TEXT,
    plan VARCHAR(50) DEFAULT 'free',
    forms_count INTEGER DEFAULT 0,
    signup_ip VARCHAR(45),
    signup_country VARCHAR(2),
    signup_geo_lat FLOAT,
    signup_geo_lon FLOAT,
    signup_user_agent TEXT,
    signup_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Forms table
CREATE TABLE forms (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    title VARCHAR(255),
    name VARCHAR(255),
    description TEXT,
    form_type VARCHAR(50) DEFAULT 'simple',
    is_published BOOLEAN DEFAULT FALSE,
    views INTEGER DEFAULT 0,
    submissions INTEGER DEFAULT 0,
    submission_limit INTEGER DEFAULT 0,
    fields JSONB,
    theme JSONB,
    branding JSONB,
    allowed_domains JSONB,
    idempotency_key VARCHAR(255),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on user_id for faster queries
CREATE INDEX idx_forms_user_id ON forms(user_id);
-- Create index on name for conflict detection
CREATE INDEX idx_forms_name ON forms(name);

-- Form submissions
CREATE TABLE submissions (
    id VARCHAR(128) PRIMARY KEY,
    form_id VARCHAR(128) NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    form_owner_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    data JSONB,
    metadata JSONB,
    ip_address VARCHAR(45),
    country_code VARCHAR(2),
    user_agent TEXT,
    submitted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on form_id for faster queries
CREATE INDEX idx_submissions_form_id ON submissions(form_id);
-- Create index on form_owner_id for faster queries
CREATE INDEX idx_submissions_form_owner_id ON submissions(form_owner_id);

-- Form analytics events
CREATE TABLE analytics (
    id VARCHAR(128) PRIMARY KEY,
    form_id VARCHAR(128) NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    event_type VARCHAR(50),
    data JSONB,
    ip_address VARCHAR(45),
    country_code VARCHAR(2),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on form_id for faster queries
CREATE INDEX idx_analytics_form_id ON analytics(form_id);

-- Form versions (for version history)
CREATE TABLE form_versions (
    id VARCHAR(128) PRIMARY KEY,
    form_id VARCHAR(128) NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    version_number INTEGER,
    data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on form_id for faster queries
CREATE INDEX idx_form_versions_form_id ON form_versions(form_id);

-- Form abandons (abandoned form sessions)
CREATE TABLE form_abandons (
    id VARCHAR(128) PRIMARY KEY,
    form_id VARCHAR(128) NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    data JSONB,
    ip_address VARCHAR(45),
    country_code VARCHAR(2),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on form_id for faster queries
CREATE INDEX idx_form_abandons_form_id ON form_abandons(form_id);

-- Session recordings
CREATE TABLE sessions (
    id VARCHAR(128) PRIMARY KEY,
    form_id VARCHAR(128) NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    metadata JSONB,
    ip_address VARCHAR(45),
    country_code VARCHAR(2),
    user_agent TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on form_id for faster queries
CREATE INDEX idx_sessions_form_id ON sessions(form_id);

-- Session recording chunks
CREATE TABLE session_chunks (
    id VARCHAR(128) PRIMARY KEY,
    session_id VARCHAR(128) NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    form_id VARCHAR(128) NOT NULL REFERENCES forms(id) ON DELETE CASCADE,
    chunk_number INTEGER,
    events JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on session_id for faster queries
CREATE INDEX idx_session_chunks_session_id ON session_chunks(session_id);
-- Create index on form_id for faster queries
CREATE INDEX idx_session_chunks_form_id ON session_chunks(form_id);

-- User notifications
CREATE TABLE notifications (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    title VARCHAR(255),
    message TEXT,
    type VARCHAR(50),
    is_read BOOLEAN DEFAULT FALSE,
    data JSONB,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on user_id for faster queries
CREATE INDEX idx_notifications_user_id ON notifications(user_id);