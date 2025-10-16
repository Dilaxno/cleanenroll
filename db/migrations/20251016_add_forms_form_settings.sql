-- Migration: add form_settings JSONB column to forms to store per-form runtime settings
-- Includes recaptcha config, GDPR/privacy link, redirect link, email checks, and geo restrictions
-- Safe to run multiple times

ALTER TABLE forms
    ADD COLUMN IF NOT EXISTS form_settings JSONB DEFAULT '{}'::jsonb;
