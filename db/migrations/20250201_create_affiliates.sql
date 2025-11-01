-- Affiliates table for affiliate program authentication and tracking
-- Uses email/password auth (not Firebase) with JWT tokens

CREATE TABLE IF NOT EXISTS affiliates (
    id VARCHAR(128) PRIMARY KEY,
    email VARCHAR(255) UNIQUE NOT NULL,
    name VARCHAR(255) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    
    -- Affiliate program details
    affiliate_code VARCHAR(50) UNIQUE NOT NULL,
    commission_rate DECIMAL(5,2) DEFAULT 30.00,
    total_earnings DECIMAL(10,2) DEFAULT 0.00,
    total_clicks INTEGER DEFAULT 0,
    total_signups INTEGER DEFAULT 0,
    total_conversions INTEGER DEFAULT 0,
    
    -- Payment information
    payment_email VARCHAR(255),
    payment_method VARCHAR(50),
    
    -- Metadata
    signup_ip VARCHAR(45),
    signup_country VARCHAR(2),
    last_login_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

-- Index for fast email lookups
CREATE INDEX idx_affiliates_email ON affiliates(email);

-- Index for affiliate code lookups
CREATE INDEX idx_affiliates_code ON affiliates(affiliate_code);

-- Affiliate clicks tracking
CREATE TABLE IF NOT EXISTS affiliate_clicks (
    id VARCHAR(128) PRIMARY KEY,
    affiliate_id VARCHAR(128) NOT NULL REFERENCES affiliates(id) ON DELETE CASCADE,
    affiliate_code VARCHAR(50) NOT NULL,
    ip_address VARCHAR(45),
    country_code VARCHAR(2),
    user_agent TEXT,
    referrer TEXT,
    clicked_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_affiliate_clicks_affiliate_id ON affiliate_clicks(affiliate_id);
CREATE INDEX idx_affiliate_clicks_clicked_at ON affiliate_clicks(clicked_at);

-- Affiliate conversions (signups that became paying customers)
CREATE TABLE IF NOT EXISTS affiliate_conversions (
    id VARCHAR(128) PRIMARY KEY,
    affiliate_id VARCHAR(128) NOT NULL REFERENCES affiliates(id) ON DELETE CASCADE,
    user_id VARCHAR(128) REFERENCES users(uid) ON DELETE SET NULL,
    affiliate_code VARCHAR(50) NOT NULL,
    commission_amount DECIMAL(10,2) NOT NULL,
    subscription_plan VARCHAR(50),
    status VARCHAR(50) DEFAULT 'pending', -- pending, paid, cancelled
    converted_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    paid_at TIMESTAMP WITH TIME ZONE
);

CREATE INDEX idx_affiliate_conversions_affiliate_id ON affiliate_conversions(affiliate_id);
CREATE INDEX idx_affiliate_conversions_user_id ON affiliate_conversions(user_id);
CREATE INDEX idx_affiliate_conversions_status ON affiliate_conversions(status);

-- Affiliate payouts
CREATE TABLE IF NOT EXISTS affiliate_payouts (
    id VARCHAR(128) PRIMARY KEY,
    affiliate_id VARCHAR(128) NOT NULL REFERENCES affiliates(id) ON DELETE CASCADE,
    amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(50) DEFAULT 'pending', -- pending, processing, paid, failed
    payment_method VARCHAR(50),
    payment_reference VARCHAR(255),
    notes TEXT,
    paid_at TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_affiliate_payouts_affiliate_id ON affiliate_payouts(affiliate_id);
CREATE INDEX idx_affiliate_payouts_status ON affiliate_payouts(status);

-- Password reset tokens for affiliates
CREATE TABLE IF NOT EXISTS affiliate_reset_tokens (
    id VARCHAR(128) PRIMARY KEY,
    affiliate_id VARCHAR(128) NOT NULL REFERENCES affiliates(id) ON DELETE CASCADE,
    token VARCHAR(255) UNIQUE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_affiliate_reset_tokens_token ON affiliate_reset_tokens(token);
CREATE INDEX idx_affiliate_reset_tokens_affiliate_id ON affiliate_reset_tokens(affiliate_id);
