-- Migration: Create developer_waitlist table
-- Description: Store developer portal waitlist signups with email, interests, and use cases

CREATE TABLE IF NOT EXISTS developer_waitlist (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255),
    company VARCHAR(255),
    role VARCHAR(255),
    interests TEXT[], -- Array of interest areas (e.g., API, SDKs, Webhooks, etc.)
    use_cases TEXT, -- Detailed use case description
    additional_info TEXT, -- Any additional information
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_developer_waitlist_email ON developer_waitlist(email);

-- Create index on created_at for sorting
CREATE INDEX IF NOT EXISTS idx_developer_waitlist_created_at ON developer_waitlist(created_at DESC);

COMMENT ON TABLE developer_waitlist IS 'Stores developer portal waitlist signups';
COMMENT ON COLUMN developer_waitlist.interests IS 'Array of developer interests (API, SDKs, Webhooks, Documentation, etc.)';
COMMENT ON COLUMN developer_waitlist.use_cases IS 'Description of intended use cases for the developer portal';
