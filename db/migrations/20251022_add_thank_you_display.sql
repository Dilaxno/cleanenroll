-- Add thank_you_display column to forms table
-- This controls whether the thank you message appears as a toast or full page

ALTER TABLE forms
ADD COLUMN IF NOT EXISTS thank_you_display VARCHAR(20) DEFAULT 'toast';

-- Add thank_you_message column if not exists
ALTER TABLE forms
ADD COLUMN IF NOT EXISTS thank_you_message TEXT;

-- Add celebration_enabled column if not exists
ALTER TABLE forms
ADD COLUMN IF NOT EXISTS celebration_enabled BOOLEAN DEFAULT FALSE;

-- Create index for faster queries
CREATE INDEX IF NOT EXISTS idx_forms_thank_you_display ON forms(thank_you_display);
