-- Add email_verified flag to users table to track email verification status
-- Run date: 2025-10-16

ALTER TABLE users
ADD COLUMN IF NOT EXISTS email_verified BOOLEAN DEFAULT FALSE;
