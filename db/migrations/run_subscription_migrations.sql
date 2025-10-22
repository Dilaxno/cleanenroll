-- Combined migration for subscription and payment tracking
-- Run this on production Neon database

-- Add subscription_id and plan_details (from 20251018)
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255),
ADD COLUMN IF NOT EXISTS plan_details JSONB;

-- Add last_payment_id (from 20251022)
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS last_payment_id VARCHAR(255);

-- Add indexes
CREATE INDEX IF NOT EXISTS idx_users_subscription_id ON users(subscription_id);
CREATE INDEX IF NOT EXISTS idx_users_last_payment_id ON users(last_payment_id);

-- Add comments
COMMENT ON COLUMN users.subscription_id IS 'Active payment subscription ID (e.g., from Dodo Payments)';
COMMENT ON COLUMN users.plan_details IS 'Full subscription details including billing info';
COMMENT ON COLUMN users.last_payment_id IS 'Most recent payment ID from payment provider (displayed on success page)';

-- Verify columns were added
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'users' 
AND column_name IN ('subscription_id', 'last_payment_id', 'plan_details')
ORDER BY column_name;
