-- Migration: Add Notion integration support
-- Description: Store Notion workspace connection, database selection, and field mappings per form

-- Create notion_integrations table to store Notion OAuth credentials and database selection per form
CREATE TABLE IF NOT EXISTS notion_integrations (
    id SERIAL PRIMARY KEY,
    form_id TEXT NOT NULL,
    user_id VARCHAR(255) NOT NULL,
    
    -- Notion OAuth credentials
    access_token TEXT NOT NULL,
    workspace_id VARCHAR(255),
    workspace_name VARCHAR(255),
    bot_id VARCHAR(255),
    
    -- Selected Notion database
    database_id VARCHAR(255) NOT NULL,
    database_name VARCHAR(255),
    
    -- Field mappings: JSON object mapping form field IDs to Notion property names
    -- Format: {"field_id_1": "notion_property_name_1", "field_id_2": "notion_property_name_2", ...}
    field_mappings JSONB DEFAULT '{}'::jsonb,
    
    -- Integration status
    enabled BOOLEAN DEFAULT true,
    
    -- Timestamps
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    
    -- Ensure one integration per form
    UNIQUE(form_id)
);

-- Create index on form_id for faster lookups
CREATE INDEX IF NOT EXISTS idx_notion_integrations_form_id ON notion_integrations(form_id);

-- Create index on user_id for admin queries
CREATE INDEX IF NOT EXISTS idx_notion_integrations_user_id ON notion_integrations(user_id);

COMMENT ON TABLE notion_integrations IS 'Stores Notion integration settings per form';
COMMENT ON COLUMN notion_integrations.access_token IS 'Encrypted Notion OAuth access token';
COMMENT ON COLUMN notion_integrations.database_id IS 'Notion database ID where form responses will be sent';
COMMENT ON COLUMN notion_integrations.field_mappings IS 'JSON mapping of form field IDs to Notion property names';
