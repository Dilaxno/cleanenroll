-- Add next_billing_at and member_since columns to users table
-- These are billing timestamps that were previously stored in plan_details JSONB

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS next_billing_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS member_since TIMESTAMP WITH TIME ZONE;

-- Add indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_users_next_billing_at ON users(next_billing_at);
CREATE INDEX IF NOT EXISTS idx_users_member_since ON users(member_since);

-- Add comments
COMMENT ON COLUMN users.next_billing_at IS 'Next billing date for Pro subscription';
COMMENT ON COLUMN users.member_since IS 'Date when user first became a Pro member';

-- Verify columns were added
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'users' 
AND column_name IN ('next_billing_at', 'member_since')
ORDER BY column_name;
