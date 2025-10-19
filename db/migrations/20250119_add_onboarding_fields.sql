-- Add onboarding fields to users table to replace Firestore storage
-- Migration: 20250119_add_onboarding_fields

ALTER TABLE users
ADD COLUMN IF NOT EXISTS first_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS last_name VARCHAR(255),
ADD COLUMN IF NOT EXISTS account_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS use_cases JSONB,
ADD COLUMN IF NOT EXISTS other_use_case TEXT,
ADD COLUMN IF NOT EXISTS heard_about_us VARCHAR(100),
ADD COLUMN IF NOT EXISTS heard_about_us_other TEXT,
ADD COLUMN IF NOT EXISTS business_info JSONB,
ADD COLUMN IF NOT EXISTS preferences JSONB,
ADD COLUMN IF NOT EXISTS marketing_opt_in BOOLEAN DEFAULT FALSE;

-- Create index for account type queries
CREATE INDEX IF NOT EXISTS idx_users_account_type ON users(account_type);

-- Comment describing the structure
COMMENT ON COLUMN users.use_cases IS 'Array of use case strings from onboarding';
COMMENT ON COLUMN users.business_info IS 'Business details: {name, size, revenue}';
COMMENT ON COLUMN users.preferences IS 'User preferences like theme, notifications, etc';
