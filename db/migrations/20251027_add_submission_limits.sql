-- Add submission limit tracking fields to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS submissions_this_month INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS submissions_limit INTEGER DEFAULT 50,
ADD COLUMN IF NOT EXISTS limit_reset_date TIMESTAMP DEFAULT DATE_TRUNC('month', CURRENT_TIMESTAMP) + INTERVAL '1 month';

-- Create index for efficient queries
CREATE INDEX IF NOT EXISTS idx_users_limit_reset_date ON users(limit_reset_date);

-- Add comment for documentation
COMMENT ON COLUMN users.submissions_this_month IS 'Number of submissions received this month across all user forms';
COMMENT ON COLUMN users.submissions_limit IS 'Monthly submission limit based on plan (50 for free, unlimited for pro)';
COMMENT ON COLUMN users.limit_reset_date IS 'Date when the monthly submission counter resets';
