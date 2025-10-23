-- Add button customization columns for auto-reply emails
ALTER TABLE forms
  ADD COLUMN IF NOT EXISTS auto_reply_button_label TEXT DEFAULT 'Visit Website',
  ADD COLUMN IF NOT EXISTS auto_reply_button_url TEXT,
  ADD COLUMN IF NOT EXISTS auto_reply_button_color TEXT DEFAULT '#4f46e5';
