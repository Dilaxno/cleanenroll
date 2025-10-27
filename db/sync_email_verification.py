#!/usr/bin/env python3
"""
Sync email verification status from Firebase Auth to Neon PostgreSQL
This script fetches all users from Firebase Auth and updates the email_verified column in Neon
"""

import os
import sys
from firebase_admin import auth, credentials, initialize_app
import psycopg2
from dotenv import load_dotenv
from tqdm import tqdm

# Load environment variables
load_dotenv()

# Initialize Firebase Admin
try:
    cred = credentials.Certificate('cleanenroll-fd36a-firebase-adminsdk-fbsvc-7d79b92b3f.json')
    initialize_app(cred)
    print("✓ Firebase Admin initialized")
except Exception as e:
    print(f"Error initializing Firebase Admin: {e}")
    sys.exit(1)

# Connect to PostgreSQL
try:
    conn = psycopg2.connect(os.getenv('DATABASE_URL'))
    print("✓ Connected to PostgreSQL")
except Exception as e:
    print(f"Error connecting to PostgreSQL: {e}")
    sys.exit(1)

def sync_email_verification():
    """Sync email verification status from Firebase Auth to PostgreSQL"""
    print("\nSyncing email verification status...")
    cursor = conn.cursor()
    
    # Get all users from Firebase Auth
    page = auth.list_users()
    users = []
    
    while page:
        users.extend(page.users)
        page = page.get_next_page()
    
    print(f"Found {len(users)} users in Firebase Auth")
    
    updated = 0
    verified_count = 0
    unverified_count = 0
    
    for user in tqdm(users, desc="Syncing users"):
        try:
            uid = user.uid
            email_verified = user.email_verified
            
            # Update email_verified in PostgreSQL
            cursor.execute(
                "UPDATE users SET email_verified = %s WHERE uid = %s",
                (email_verified, uid)
            )
            
            if cursor.rowcount > 0:
                updated += 1
                if email_verified:
                    verified_count += 1
                else:
                    unverified_count += 1
        
        except Exception as e:
            print(f"\nError syncing user {uid}: {e}")
    
    conn.commit()
    cursor.close()
    
    print(f"\n✓ Synced {updated} users")
    print(f"  - Verified: {verified_count}")
    print(f"  - Unverified: {unverified_count}")
    return updated

def verify_sync():
    """Verify the sync by showing current state"""
    print("\nVerifying sync...")
    cursor = conn.cursor()
    
    cursor.execute("""
        SELECT 
            COUNT(*) as total_users,
            SUM(CASE WHEN email_verified = TRUE THEN 1 ELSE 0 END) as verified_count,
            SUM(CASE WHEN email_verified = FALSE THEN 1 ELSE 0 END) as unverified_count
        FROM users
    """)
    
    result = cursor.fetchone()
    total, verified, unverified = result
    
    print(f"\nCurrent state in PostgreSQL:")
    print(f"  Total users: {total}")
    print(f"  Verified: {verified}")
    print(f"  Unverified: {unverified}")
    
    cursor.close()

if __name__ == "__main__":
    try:
        sync_email_verification()
        verify_sync()
    except Exception as e:
        print(f"\nError: {e}")
        sys.exit(1)
    finally:
        conn.close()
        print("\n✓ Done!")
