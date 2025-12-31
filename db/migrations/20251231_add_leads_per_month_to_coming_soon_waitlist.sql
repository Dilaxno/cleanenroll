-- Migration: Add leads_per_month column to coming_soon_waitlist table
-- Description: Store how many leads users collect per month

ALTER TABLE coming_soon_waitlist 
ADD COLUMN IF NOT EXISTS leads_per_month VARCHAR(50);

-- Create index on leads_per_month for analytics queries
CREATE INDEX IF NOT EXISTS idx_coming_soon_waitlist_leads_per_month ON coming_soon_waitlist(leads_per_month);

COMMENT ON COLUMN coming_soon_waitlist.leads_per_month IS 'Monthly lead volume range (e.g., 0-100, 100-500, 500-1000, etc.)';
