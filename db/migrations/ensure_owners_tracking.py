"""
Script to ensure owners_tracking table exists in the database
Run this to fix the admin live visitors tracker
"""
import asyncio
from sqlalchemy import text
import sys
import os

# Add parent directory to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

from db.database import async_session_maker

async def create_owners_tracking_table():
    """Create owners_tracking table if it doesn't exist"""
    
    sql = """
    -- Create owners_tracking table for tracking site owner activity
    CREATE TABLE IF NOT EXISTS owners_tracking (
        id SERIAL PRIMARY KEY,
        user_id VARCHAR(255) NOT NULL,
        session_id VARCHAR(255) NOT NULL,
        user_email VARCHAR(255),
        ip_address VARCHAR(45),
        city VARCHAR(255),
        country VARCHAR(255),
        country_code VARCHAR(2),
        latitude DECIMAL(10, 8),
        longitude DECIMAL(11, 8),
        current_page TEXT,
        referrer TEXT,
        user_agent TEXT,
        device_type VARCHAR(50),
        browser VARCHAR(100),
        os VARCHAR(100),
        screen_width INTEGER,
        screen_height INTEGER,
        metadata JSONB,
        first_seen TIMESTAMP NOT NULL,
        last_seen TIMESTAMP NOT NULL,
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    -- Index for fast lookups by user_id and active status
    CREATE INDEX IF NOT EXISTS idx_owners_tracking_user_active 
    ON owners_tracking(user_id, is_active, last_seen);

    -- Index for session_id lookups
    CREATE INDEX IF NOT EXISTS idx_owners_tracking_session 
    ON owners_tracking(session_id);

    -- Index for cleanup queries (remove old inactive sessions)
    CREATE INDEX IF NOT EXISTS idx_owners_tracking_last_seen 
    ON owners_tracking(last_seen);

    -- Index for country-based analytics
    CREATE INDEX IF NOT EXISTS idx_owners_tracking_country 
    ON owners_tracking(country_code);

    -- Index for user email lookups
    CREATE INDEX IF NOT EXISTS idx_owners_tracking_email 
    ON owners_tracking(user_email);
    """
    
    try:
        async with async_session_maker() as session:
            print("Creating owners_tracking table...")
            await session.execute(text(sql))
            await session.commit()
            print("✓ Table created successfully!")
            
            # Check if table has any data
            result = await session.execute(text("SELECT COUNT(*) FROM owners_tracking"))
            count = result.scalar()
            print(f"✓ Table has {count} records")
            
    except Exception as e:
        print(f"✗ Error: {e}")
        raise

if __name__ == "__main__":
    print("=== Owners Tracking Table Setup ===")
    asyncio.run(create_owners_tracking_table())
    print("=== Setup Complete ===")
