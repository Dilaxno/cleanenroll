-- Update email_verified column based on Firebase Auth verification status
-- This migration should be run after syncing verification status from Firebase Auth
-- Run date: 2025-10-27

-- Note: This SQL assumes you have already populated the email_verified column
-- from Firebase Auth using the backend sync script. If not, run the Python script first.

-- Verify current state
SELECT 
    COUNT(*) as total_users,
    SUM(CASE WHEN email_verified = TRUE THEN 1 ELSE 0 END) as verified_count,
    SUM(CASE WHEN email_verified = FALSE THEN 1 ELSE 0 END) as unverified_count
FROM users;

-- If you need to manually set specific users as verified (replace UIDs as needed):
-- UPDATE users SET email_verified = TRUE WHERE uid IN ('user_uid_1', 'user_uid_2');

-- If you need to manually set specific users as unverified:
-- UPDATE users SET email_verified = FALSE WHERE uid IN ('user_uid_3', 'user_uid_4');

-- Show users grouped by verification status
SELECT 
    email_verified,
    COUNT(*) as count,
    array_agg(email ORDER BY email LIMIT 10) as sample_emails
FROM users
GROUP BY email_verified
ORDER BY email_verified DESC;
