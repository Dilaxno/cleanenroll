-- Add current field tracking to live_visitors table
ALTER TABLE live_visitors 
ADD COLUMN IF NOT EXISTS current_field VARCHAR(255),
ADD COLUMN IF NOT EXISTS current_field_label VARCHAR(255);

COMMENT ON COLUMN live_visitors.current_field IS 'Field ID that the visitor is currently interacting with';
COMMENT ON COLUMN live_visitors.current_field_label IS 'Human-readable field label for display';
