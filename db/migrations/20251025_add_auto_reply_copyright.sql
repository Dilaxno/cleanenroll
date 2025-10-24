-- Migration: Add auto_reply_copyright column to forms table
-- Date: 2025-10-25
-- Description: Replace auto_reply_footer_html with copyright name field for thank you emails

ALTER TABLE forms
ADD COLUMN IF NOT EXISTS auto_reply_copyright VARCHAR(255);

-- Add comment
COMMENT ON COLUMN forms.auto_reply_copyright IS 'Copyright name displayed in thank you email footer (e.g., "YourCompany.com")';
