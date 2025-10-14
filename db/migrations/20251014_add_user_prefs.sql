-- Migration: add preferences and marketing_opt_in on users
-- Safe to run multiple times

ALTER TABLE users
    ADD COLUMN IF NOT EXISTS preferences JSONB,
    ADD COLUMN IF NOT EXISTS marketing_opt_in BOOLEAN;
