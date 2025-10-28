-- Add form scheduling columns
ALTER TABLE forms ADD COLUMN IF NOT EXISTS closed_from TIMESTAMP;
ALTER TABLE forms ADD COLUMN IF NOT EXISTS closed_to TIMESTAMP;
ALTER TABLE forms ADD COLUMN IF NOT EXISTS closed_page_config JSONB DEFAULT '{
  "title": "This form is temporarily closed",
  "message": "Thank you for your interest. This form is currently not accepting submissions. Please check back later.",
  "backgroundColor": "#1a1a1a",
  "textColor": "#ffffff",
  "accentColor": "#7ED957",
  "fontFamily": "Inter",
  "backgroundImageUrl": null
}'::jsonb;

-- Add index for faster lookups on scheduled forms
CREATE INDEX IF NOT EXISTS idx_forms_closed_schedule ON forms(closed_from, closed_to) WHERE closed_from IS NOT NULL OR closed_to IS NOT NULL;
