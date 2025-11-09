-- Add is_admin column to users table
-- This allows certain users to access admin endpoints like developer waitlist

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;

-- Create an index for faster admin lookups
CREATE INDEX IF NOT EXISTS idx_users_is_admin ON users(is_admin) WHERE is_admin = TRUE;

-- Optional: Set yourself as admin (replace with your Firebase UID)
-- UPDATE users SET is_admin = TRUE WHERE uid = 'YOUR_FIREBASE_UID_HERE';
