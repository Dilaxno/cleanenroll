-- Migration: Create coming_soon_waitlist table
-- Description: Store email signups from the coming soon landing page

CREATE TABLE IF NOT EXISTS coming_soon_waitlist (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Create index on email for faster lookups
CREATE INDEX IF NOT EXISTS idx_coming_soon_waitlist_email ON coming_soon_waitlist(email);

-- Create index on created_at for sorting
CREATE INDEX IF NOT EXISTS idx_coming_soon_waitlist_created_at ON coming_soon_waitlist(created_at DESC);

COMMENT ON TABLE coming_soon_waitlist IS 'Stores email signups from the coming soon landing page';
