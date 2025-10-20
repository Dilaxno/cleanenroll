-- Create table for short file link redirects
CREATE TABLE IF NOT EXISTS file_redirects (
    id TEXT PRIMARY KEY,
    r2_key TEXT NOT NULL,
    form_id TEXT NOT NULL,
    response_id TEXT,
    file_type TEXT, -- 'upload', 'signature', 'audio', 'video'
    created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_file_redirects_form ON file_redirects(form_id);
CREATE INDEX IF NOT EXISTS idx_file_redirects_response ON file_redirects(response_id);

COMMENT ON TABLE file_redirects IS 'Short link redirects for file URLs to avoid displaying full R2 URLs in submissions table';
COMMENT ON COLUMN file_redirects.id IS 'Short ID used in URL path (e.g., /f/abc123)';
COMMENT ON COLUMN file_redirects.r2_key IS 'Full R2 key for the file';
COMMENT ON COLUMN file_redirects.file_type IS 'Type of file: upload, signature, audio, video';
