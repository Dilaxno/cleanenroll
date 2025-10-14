-- Migration: add webhooks_idempotency table for webhook deduplication
-- Safe to run multiple times

CREATE TABLE IF NOT EXISTS webhooks_idempotency (
    webhook_id VARCHAR(255) PRIMARY KEY,
    received_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    event_type VARCHAR(100),
    user_uid VARCHAR(128),
    customer_email VARCHAR(255),
    payment_id VARCHAR(255),
    product_id VARCHAR(255)
);
