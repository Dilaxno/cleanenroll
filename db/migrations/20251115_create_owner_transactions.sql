-- Create table to store owner-level one-time payments for the Earnings dashboard
-- Amounts are stored in the smallest currency unit (e.g., cents for USD)

CREATE TABLE IF NOT EXISTS owner_transactions (
    payment_id           VARCHAR(255) PRIMARY KEY,
    owner_id             VARCHAR(128) REFERENCES users(uid) ON DELETE SET NULL,
    form_id              VARCHAR(128) REFERENCES forms(id) ON DELETE SET NULL,
    submission_id        VARCHAR(128),
    status               VARCHAR(32) NOT NULL,
    total_amount         INTEGER NOT NULL,
    currency             VARCHAR(3) NOT NULL,
    fee_amount           INTEGER DEFAULT 0,
    net_amount           INTEGER NOT NULL DEFAULT 0,
    customer_email       VARCHAR(255),
    payment_method_type  VARCHAR(64),
    created_at           TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,
    updated_at           TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- Helpful compound index for dashboard queries (by owner and time)
CREATE INDEX IF NOT EXISTS idx_owner_transactions_owner_id_created_at
    ON owner_transactions(owner_id, created_at);

-- Index by form for drill-downs
CREATE INDEX IF NOT EXISTS idx_owner_transactions_form_id
    ON owner_transactions(form_id);