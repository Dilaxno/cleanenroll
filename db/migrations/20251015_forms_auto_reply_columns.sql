-- Ensure auto-reply columns exist on forms
ALTER TABLE IF EXISTS forms
  ADD COLUMN IF NOT EXISTS auto_reply_enabled boolean DEFAULT FALSE;
ALTER TABLE IF EXISTS forms
  ADD COLUMN IF NOT EXISTS auto_reply_email_field_id text;
ALTER TABLE IF EXISTS forms
  ADD COLUMN IF NOT EXISTS auto_reply_subject text;
ALTER TABLE IF EXISTS forms
  ADD COLUMN IF NOT EXISTS auto_reply_message_html text;
