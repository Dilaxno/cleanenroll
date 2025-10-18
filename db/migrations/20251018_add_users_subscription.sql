-- Add subscription_id and plan_details to users table
-- This allows storing payment subscription information in Neon instead of Firestore

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS subscription_id VARCHAR(255),
ADD COLUMN IF NOT EXISTS plan_details JSONB;

-- Add index for faster subscription lookups
CREATE INDEX IF NOT EXISTS idx_users_subscription_id ON users(subscription_id);

-- Add comments
COMMENT ON COLUMN users.subscription_id IS 'Active payment subscription ID (e.g., from Dodo Payments)';
COMMENT ON COLUMN users.plan_details IS 'Full subscription details including billing info';
