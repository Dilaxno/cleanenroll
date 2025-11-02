-- Add detailed geolocation and activity tracking for affiliate clicks

ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS city VARCHAR(100);
ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS region VARCHAR(100);
ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS country VARCHAR(100);
ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS latitude DECIMAL(10, 8);
ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS longitude DECIMAL(11, 8);
ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS device_type VARCHAR(50); -- mobile, desktop, tablet
ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS browser VARCHAR(100);
ALTER TABLE affiliate_clicks ADD COLUMN IF NOT EXISTS os VARCHAR(100);

-- Create affiliate activities table for tracking user actions
CREATE TABLE IF NOT EXISTS affiliate_activities (
    id VARCHAR(128) PRIMARY KEY,
    affiliate_id VARCHAR(128) NOT NULL REFERENCES affiliates(id) ON DELETE CASCADE,
    affiliate_code VARCHAR(50) NOT NULL,
    click_id VARCHAR(128) REFERENCES affiliate_clicks(id) ON DELETE CASCADE,
    session_id VARCHAR(255),
    activity_type VARCHAR(50) NOT NULL, -- 'click', 'page_view', 'signup', 'form_submit', 'conversion'
    page_url TEXT,
    page_title VARCHAR(255),
    ip_address VARCHAR(45),
    country_code VARCHAR(2),
    city VARCHAR(100),
    latitude DECIMAL(10, 8),
    longitude DECIMAL(11, 8),
    metadata JSONB, -- Additional activity-specific data
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_affiliate_activities_affiliate_id ON affiliate_activities(affiliate_id);
CREATE INDEX idx_affiliate_activities_click_id ON affiliate_activities(click_id);
CREATE INDEX idx_affiliate_activities_session_id ON affiliate_activities(session_id);
CREATE INDEX idx_affiliate_activities_created_at ON affiliate_activities(created_at);
CREATE INDEX idx_affiliate_activities_type ON affiliate_activities(activity_type);
