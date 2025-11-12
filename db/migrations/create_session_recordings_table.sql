-- Create session_recordings table for storing session recording metadata
-- The actual recording data (events) is stored in R2 for cost efficiency

CREATE TABLE IF NOT EXISTS session_recordings (
    id VARCHAR(36) PRIMARY KEY,
    form_id VARCHAR(36) NOT NULL,
    owner_uid VARCHAR(128) NOT NULL,
    start_time TIMESTAMP WITH TIME ZONE,
    end_time TIMESTAMP WITH TIME ZONE,
    user_agent TEXT,
    viewport_width INTEGER,
    viewport_height INTEGER,
    r2_key VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    
    -- Indexes for efficient querying
    INDEX idx_session_recordings_owner_uid (owner_uid),
    INDEX idx_session_recordings_form_id (form_id),
    INDEX idx_session_recordings_created_at (created_at),
    
    -- Foreign key constraint to forms table
    FOREIGN KEY (form_id) REFERENCES forms(id) ON DELETE CASCADE
);

-- Add comment for documentation
COMMENT ON TABLE session_recordings IS 'Metadata for session recordings stored in R2. Contains references to R2 objects and basic session info.';
COMMENT ON COLUMN session_recordings.r2_key IS 'Key path in R2 bucket where the full recording data is stored';
COMMENT ON COLUMN session_recordings.owner_uid IS 'UID of the form owner who can access this recording';
