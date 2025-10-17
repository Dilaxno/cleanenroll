-- Create table to track abandoned/partial form sessions
CREATE TABLE IF NOT EXISTS form_abandons (
    id TEXT PRIMARY KEY,
    form_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    user_id TEXT,
    values JSONB,
    filled_count INTEGER,
    total_fields INTEGER,
    progress TEXT,
    step INTEGER,
    total_steps INTEGER,
    submitted BOOLEAN DEFAULT FALSE,
    abandoned BOOLEAN DEFAULT FALSE,
    abandoned_at TIMESTAMPTZ,
    last_activity_at TIMESTAMPTZ,
    updated_at TIMESTAMPTZ DEFAULT NOW(),
    created_at TIMESTAMPTZ DEFAULT NOW()
);

-- Index for efficient lookups by form and session
CREATE INDEX IF NOT EXISTS idx_form_abandons_form_session 
ON form_abandons(form_id, session_id);

-- Index for querying abandoned sessions
CREATE INDEX IF NOT EXISTS idx_form_abandons_abandoned 
ON form_abandons(form_id, abandoned, abandoned_at DESC) 
WHERE abandoned = TRUE;
