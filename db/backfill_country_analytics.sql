-- Backfill form_countries_analytics from existing submissions
-- This populates country analytics for submissions that were created before the analytics tracking was added

INSERT INTO form_countries_analytics (form_id, day, country_iso2, count)
SELECT 
    form_id,
    DATE(submitted_at) as day,
    UPPER(country_code) as country_iso2,
    COUNT(*) as count
FROM submissions
WHERE country_code IS NOT NULL AND country_code != ''
GROUP BY form_id, DATE(submitted_at), UPPER(country_code)
ON CONFLICT (form_id, day, country_iso2) 
DO UPDATE SET count = form_countries_analytics.count + EXCLUDED.count;
