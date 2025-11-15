-- Add banner image URL and tagline columns to users table for profile customization

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS banner_image_url TEXT,
    ADD COLUMN IF NOT EXISTS tagline VARCHAR(100);

-- Add index for users with custom banners (for potential profile browsing features)
CREATE INDEX IF NOT EXISTS idx_users_banner_image_url 
    ON users(banner_image_url) WHERE banner_image_url IS NOT NULL;

COMMENT ON COLUMN users.banner_image_url IS 'URL to user profile banner image';
COMMENT ON COLUMN users.tagline IS 'Short bio or tagline for user profile (max 100 chars)';
