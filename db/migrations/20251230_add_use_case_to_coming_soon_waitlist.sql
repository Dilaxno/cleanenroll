-- Migration: Add use_case column to coming_soon_waitlist table
-- Description: Store the use case selected by users when signing up for the waitlist

ALTER TABLE coming_soon_waitlist 
ADD COLUMN IF NOT EXISTS use_case VARCHAR(100);

-- Create index on use_case for analytics queries
CREATE INDEX IF NOT EXISTS idx_coming_soon_waitlist_use_case ON coming_soon_waitlist(use_case);

COMMENT ON COLUMN coming_soon_waitlist.use_case IS 'The use case selected by the user (e.g., lead_generation, contact_forms, etc.)';
