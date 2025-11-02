-- Add detailed payout information columns to affiliates table

ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS payout_method VARCHAR(50); -- 'paypal' or 'bank'
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS paypal_email VARCHAR(255);

-- Bank account details
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_country VARCHAR(2);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_account_holder_name VARCHAR(255);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_iban VARCHAR(100);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_bic VARCHAR(50);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_account_number VARCHAR(100);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_routing_number VARCHAR(50);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_sort_code VARCHAR(20);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_name VARCHAR(255);
ALTER TABLE affiliates ADD COLUMN IF NOT EXISTS bank_address TEXT;

-- Index for faster queries
CREATE INDEX IF NOT EXISTS idx_affiliates_payout_method ON affiliates(payout_method);
