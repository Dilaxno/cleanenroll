-- Add conversion_rate and avg_completion_time columns to forms table
-- These will be updated whenever submissions or analytics events occur

ALTER TABLE forms 
ADD COLUMN IF NOT EXISTS conversion_rate DECIMAL(5,2) DEFAULT 0.0,
ADD COLUMN IF NOT EXISTS avg_completion_time DECIMAL(10,2) DEFAULT 0.0;

-- Add comment to explain the columns
COMMENT ON COLUMN forms.conversion_rate IS 'Cached conversion rate percentage (submissions/views * 100)';
COMMENT ON COLUMN forms.avg_completion_time IS 'Cached average completion time in seconds (time from form_started to submission)';

-- Create index for analytics queries
CREATE INDEX IF NOT EXISTS idx_analytics_type_session ON analytics(type, session_id, form_id);
CREATE INDEX IF NOT EXISTS idx_analytics_form_type ON analytics(form_id, type);

-- Backfill existing forms with calculated metrics
-- This may take a while for large datasets
DO $$
DECLARE
    form_record RECORD;
    total_starts INTEGER;
    total_subs INTEGER;
    calc_conversion_rate DECIMAL(5,2);
    calc_avg_time DECIMAL(10,2);
BEGIN
    FOR form_record IN SELECT id FROM forms LOOP
        -- Count views
        SELECT COUNT(*) INTO total_starts
        FROM analytics
        WHERE form_id = form_record.id AND type = 'view';
        
        -- Get submissions count
        SELECT COUNT(*) INTO total_subs
        FROM submissions
        WHERE form_id = form_record.id;
        
        -- Calculate conversion rate (submissions/views * 100)
        IF total_starts > 0 THEN
            calc_conversion_rate := (total_subs::DECIMAL / total_starts::DECIMAL * 100);
        ELSE
            calc_conversion_rate := 0.0;
        END IF;
        
        -- Calculate average completion time
        SELECT AVG(EXTRACT(EPOCH FROM (c.end_time - st.start_time))) INTO calc_avg_time
        FROM (
            SELECT session_id, form_id, MIN(created_at) as start_time
            FROM analytics
            WHERE form_id = form_record.id
              AND type = 'form_started'
              AND session_id IS NOT NULL
            GROUP BY session_id, form_id
        ) st
        INNER JOIN (
            SELECT session_id, form_id, submitted_at as end_time
            FROM submissions
            WHERE form_id = form_record.id
              AND session_id IS NOT NULL
        ) c ON st.session_id = c.session_id AND st.form_id = c.form_id
        WHERE c.end_time > st.start_time;
        
        -- Update the form with calculated metrics
        UPDATE forms
        SET 
            conversion_rate = COALESCE(calc_conversion_rate, 0.0),
            avg_completion_time = COALESCE(calc_avg_time, 0.0),
            updated_at = NOW()
        WHERE id = form_record.id;
        
    END LOOP;
END $$;
