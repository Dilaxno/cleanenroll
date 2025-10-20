-- Add device information columns to live_visitors table
ALTER TABLE live_visitors 
ADD COLUMN IF NOT EXISTS device_type VARCHAR(50),
ADD COLUMN IF NOT EXISTS os VARCHAR(50),
ADD COLUMN IF NOT EXISTS browser VARCHAR(50);
