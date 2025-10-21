-- Add custom_fonts table for user-uploaded fonts
CREATE TABLE IF NOT EXISTS custom_fonts (
    id VARCHAR(128) PRIMARY KEY,
    user_id VARCHAR(128) NOT NULL REFERENCES users(uid) ON DELETE CASCADE,
    font_name VARCHAR(255) NOT NULL,
    font_url TEXT NOT NULL,
    font_format VARCHAR(50) DEFAULT 'woff2',
    file_size INTEGER,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Create index on user_id for faster queries
CREATE INDEX IF NOT EXISTS idx_custom_fonts_user_id ON custom_fonts(user_id);

-- Create index on font_name for searching
CREATE INDEX IF NOT EXISTS idx_custom_fonts_name ON custom_fonts(font_name);
