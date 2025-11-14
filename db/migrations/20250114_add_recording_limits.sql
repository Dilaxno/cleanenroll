-- Add session recording limit tracking fields to users table
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS recordings_this_month INTEGER DEFAULT 0,
ADD COLUMN IF NOT EXISTS recordings_limit INTEGER DEFAULT 10,
ADD COLUMN IF NOT EXISTS recording_limit_reset_date TIMESTAMP DEFAULT DATE_TRUNC('month', CURRENT_TIMESTAMP) + INTERVAL '1 month';

-- Create index for efficient queries
CREATE INDEX IF NOT EXISTS idx_users_recording_limit_reset_date ON users(recording_limit_reset_date);

-- Add comments for documentation
COMMENT ON COLUMN users.recordings_this_month IS 'Number of session recordings captured this month across all user forms';
COMMENT ON COLUMN users.recordings_limit IS 'Monthly recording limit based on plan (10 for free, 100 for pro)';
COMMENT ON COLUMN users.recording_limit_reset_date IS 'Date when the monthly recording counter resets';
