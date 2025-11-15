-- Owner payouts batching to support the Earnings dashboard
-- Note: amounts are stored in the smallest currency unit (e.g., cents for USD)

-- Payout batches table
CREATE TABLE IF NOT EXISTS owner_payouts (
    id                 VARCHAR(64) PRIMARY KEY,
    owner_id           VARCHAR(128) REFERENCES users(uid) ON DELETE SET NULL,
    period_start       TIMESTAMPTZ NOT NULL,
    period_end         TIMESTAMPTZ NOT NULL,
    total_gross        INTEGER NOT NULL DEFAULT 0,
    total_fees         INTEGER NOT NULL DEFAULT 0,
    total_net          INTEGER NOT NULL DEFAULT 0,
    status             VARCHAR(32) NOT NULL DEFAULT 'pending', -- pending | paid | cancelled
    notes              TEXT,
    created_at         TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    paid_at            TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_owner_payouts_owner_id_created_at
    ON owner_payouts(owner_id, created_at);

-- Link transactions to a payout batch (only if owner_transactions exists)
DO $$
BEGIN
    IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'owner_transactions') THEN
        ALTER TABLE owner_transactions
            ADD COLUMN IF NOT EXISTS payout_id VARCHAR(64) REFERENCES owner_payouts(id) ON DELETE SET NULL;
        
        CREATE INDEX IF NOT EXISTS idx_owner_transactions_payout_id
            ON owner_transactions(payout_id);
    END IF;
END $$;