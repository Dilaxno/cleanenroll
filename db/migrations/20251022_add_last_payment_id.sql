-- Add last_payment_id to users table for displaying on success page
-- This stores the most recent payment ID from the payment provider

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS last_payment_id VARCHAR(255);

-- Add index for faster payment lookups
CREATE INDEX IF NOT EXISTS idx_users_last_payment_id ON users(last_payment_id);

-- Add comment
COMMENT ON COLUMN users.last_payment_id IS 'Most recent payment ID from payment provider (displayed on success page)';
