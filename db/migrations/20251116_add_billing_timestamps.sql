-- Add next_billing_at and member_since columns to users table
-- These are billing timestamps that were previously stored in plan_details JSONB

ALTER TABLE users 
ADD COLUMN IF NOT EXISTS next_billing_at TIMESTAMP WITH TIME ZONE,
ADD COLUMN IF NOT EXISTS member_since TIMESTAMP WITH TIME ZONE;

-- Add indexes for faster queries
CREATE INDEX IF NOT EXISTS idx_users_next_billing_at ON users(next_billing_at);
CREATE INDEX IF NOT EXISTS idx_users_member_since ON users(member_since);

-- Add comments
COMMENT ON COLUMN users.next_billing_at IS 'Next billing date for Pro subscription';
COMMENT ON COLUMN users.member_since IS 'Date when user first became a Pro member';

-- Backfill data from plan_details JSONB for existing Pro users
DO $$
DECLARE
    rec RECORD;
    next_billing_val TEXT;
    member_since_val TEXT;
    next_billing_ts TIMESTAMP WITH TIME ZONE;
    member_since_ts TIMESTAMP WITH TIME ZONE;
BEGIN
    FOR rec IN 
        SELECT uid, plan_details 
        FROM users 
        WHERE plan = 'pro' AND plan_details IS NOT NULL
    LOOP
        -- Extract nextBillingAt from JSONB
        next_billing_val := rec.plan_details->>'nextBillingAt';
        -- Extract memberSince from JSONB
        member_since_val := rec.plan_details->>'memberSince';
        
        next_billing_ts := NULL;
        member_since_ts := NULL;
        
        -- Try to parse nextBillingAt (could be ISO string or epoch ms)
        IF next_billing_val IS NOT NULL THEN
            BEGIN
                -- Try as ISO timestamp first
                next_billing_ts := next_billing_val::TIMESTAMP WITH TIME ZONE;
            EXCEPTION WHEN OTHERS THEN
                BEGIN
                    -- Try as epoch milliseconds
                    next_billing_ts := to_timestamp((next_billing_val::BIGINT) / 1000.0);
                EXCEPTION WHEN OTHERS THEN
                    NULL; -- Skip if can't parse
                END;
            END;
        END IF;
        
        -- Try to parse memberSince (epoch milliseconds)
        IF member_since_val IS NOT NULL THEN
            BEGIN
                -- Try as epoch milliseconds
                member_since_ts := to_timestamp((member_since_val::BIGINT) / 1000.0);
            EXCEPTION WHEN OTHERS THEN
                BEGIN
                    -- Try as ISO timestamp
                    member_since_ts := member_since_val::TIMESTAMP WITH TIME ZONE;
                EXCEPTION WHEN OTHERS THEN
                    NULL; -- Skip if can't parse
                END;
            END;
        END IF;
        
        -- Update the columns if we got valid timestamps
        IF next_billing_ts IS NOT NULL OR member_since_ts IS NOT NULL THEN
            UPDATE users 
            SET 
                next_billing_at = COALESCE(next_billing_ts, next_billing_at),
                member_since = COALESCE(member_since_ts, member_since)
            WHERE uid = rec.uid;
            
            RAISE NOTICE 'Backfilled uid=%: next_billing=%, member_since=%', 
                rec.uid, next_billing_ts, member_since_ts;
        END IF;
    END LOOP;
END $$;

-- Show results
SELECT 
    COUNT(*) as total_pro_users,
    COUNT(next_billing_at) as users_with_next_billing,
    COUNT(member_since) as users_with_member_since
FROM users 
WHERE plan = 'pro';

-- Verify columns were added
SELECT column_name, data_type 
FROM information_schema.columns 
WHERE table_name = 'users' 
AND column_name IN ('next_billing_at', 'member_since')
ORDER BY column_name;
