-- Add form schedule columns to support closing forms for specific periods
ALTER TABLE forms ADD COLUMN IF NOT EXISTS closed_from TIMESTAMPTZ;
ALTER TABLE forms ADD COLUMN IF NOT EXISTS closed_to TIMESTAMPTZ;
ALTER TABLE forms ADD COLUMN IF NOT EXISTS closed_page_config JSONB;

-- Create index for checking active schedules
CREATE INDEX IF NOT EXISTS idx_forms_closed_schedule 
ON forms(closed_from, closed_to) 
WHERE closed_from IS NOT NULL AND closed_to IS NOT NULL;

-- Add comment
COMMENT ON COLUMN forms.closed_from IS 'Start date/time when form is closed';
COMMENT ON COLUMN forms.closed_to IS 'End date/time when form is closed';
COMMENT ON COLUMN forms.closed_page_config IS 'Configuration for the closed page (title, message, colors, etc.)';
