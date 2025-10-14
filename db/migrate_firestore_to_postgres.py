#!/usr/bin/env python
"""
Migration script to transfer data from Firestore to PostgreSQL
"""

import os
import json
import time
from datetime import datetime
import firebase_admin
from firebase_admin import credentials, firestore
import psycopg2
import psycopg2.extras
from dotenv import load_dotenv
from tqdm import tqdm

# Load environment variables
load_dotenv()

# Database connection parameters
DB_NAME = os.getenv("POSTGRES_DB", "cleanenroll")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "Esstafa00uni@")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

# Firebase credentials
FIREBASE_CREDS = os.getenv("FIREBASE_CREDENTIALS", "cleanenroll-fd36a-firebase-adminsdk-fbsvc-7d79b92b3f.json")

# Initialize Firebase
try:
    cred = credentials.Certificate(FIREBASE_CREDS)
    firebase_admin.initialize_app(cred)
    db = firestore.client()
    print("Firebase initialized successfully")
except Exception as e:
    print(f"Error initializing Firebase: {e}")
    exit(1)

# Connect to PostgreSQL
try:
    conn = psycopg2.connect(
        dbname=DB_NAME,
        user=DB_USER,
        password=DB_PASSWORD,
        host=DB_HOST,
        port=DB_PORT
    )
    print("Connected to PostgreSQL successfully")
except Exception as e:
    print(f"Error connecting to PostgreSQL: {e}")
    exit(1)

def migrate_users():
    """Migrate users from Firestore to PostgreSQL"""
    print("\nMigrating users...")
    cursor = conn.cursor()
    
    # Get all users from Firestore
    users_ref = db.collection('users')
    users = users_ref.stream()
    
    # Count documents for progress bar
    user_count = sum(1 for _ in users_ref.stream())
    users = users_ref.stream()  # Reset stream
    
    migrated = 0
    for user in tqdm(users, total=user_count, desc="Users"):
        user_data = user.to_dict()
        user_id = user.id
        
        # Extract user fields with defaults for missing data
        fields = {
            'uid': user_id,
            'email': user_data.get('email', None),
            'display_name': user_data.get('displayName', None),
            'photo_url': user_data.get('photoURL', None),
            'plan': user_data.get('plan', 'free'),
            'forms_count': user_data.get('formsCount', 0),
            'signup_ip': user_data.get('signupIP', None),
            'signup_country': user_data.get('signupCountry', None),
            'signup_geo_lat': user_data.get('signupGeoLat', None),
            'signup_geo_lon': user_data.get('signupGeoLon', None),
            'signup_user_agent': user_data.get('signupUserAgent', None),
            'signup_at': user_data.get('signupAt', None),
            'created_at': user_data.get('createdAt', None),
            'updated_at': user_data.get('updatedAt', None)
        }
        
        # Handle timestamps properly
        for field in ['created_at', 'updated_at']:
            if field in fields:
                if fields[field] and hasattr(fields[field], 'timestamp'):
                    # Convert Firestore timestamp to Python datetime
                    fields[field] = fields[field].timestamp()
                elif isinstance(fields[field], dict) and '_methodName' in fields[field]:
                    # Handle SERVER_TIMESTAMP placeholder
                    fields[field] = None
        
        # Insert user into PostgreSQL
        try:
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['%s'] * len(fields))
            values = list(fields.values())
            
            query = f"INSERT INTO users ({columns}) VALUES ({placeholders}) ON CONFLICT (uid) DO UPDATE SET "
            query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'uid'])
            
            cursor.execute(query, values)
            migrated += 1
        except Exception as e:
            print(f"Error migrating user {user_id}: {e}")
    
    conn.commit()
    print(f"Migrated {migrated} users")
    return migrated

def migrate_forms():
    """Migrate forms from Firestore to PostgreSQL"""
    print("\nMigrating forms...")
    cursor = conn.cursor()
    
    # Get all forms from Firestore
    forms_ref = db.collection('forms')
    
    # Count documents for progress bar
    form_count = sum(1 for _ in forms_ref.stream())
    forms = forms_ref.stream()  # Reset stream
    
    migrated = 0
    for form in tqdm(forms, total=form_count, desc="Forms"):
        form_data = form.to_dict()
        form_id = form.id
        
        # Extract form fields with defaults for missing data
        fields = {
            'id': form_id,
            'user_id': form_data.get('userId', None),
            'title': form_data.get('title', None),
            'name': form_data.get('name', None),
            'description': form_data.get('description', None),
            'form_type': form_data.get('formType', 'simple'),
            'is_published': form_data.get('isPublished', False),
            'views': form_data.get('views', 0),
            'submissions': form_data.get('submissions', 0),
            'submission_limit': form_data.get('submissionLimit', 0),
            'fields': json.dumps(form_data.get('fields', {})),
            'theme': json.dumps(form_data.get('theme', {})),
            'branding': json.dumps(form_data.get('branding', {})),
            'allowed_domains': json.dumps(form_data.get('allowedDomains', [])),
            'idempotency_key': form_data.get('idempotencyKey', None),
            'created_at': form_data.get('createdAt', None),
            'updated_at': form_data.get('updatedAt', None)
        }
        
        # Convert Firestore timestamps to datetime objects
        for field in ['created_at', 'updated_at']:
            if field in fields and fields[field]:
                if hasattr(fields[field], 'timestamp'):
                    # Convert Firestore timestamp to Python datetime
                    fields[field] = datetime.fromtimestamp(fields[field].timestamp())
                elif isinstance(fields[field], dict) and '_methodName' in fields[field]:
                    # Handle SERVER_TIMESTAMP placeholder
                    fields[field] = None
                elif isinstance(fields[field], (int, float)):
                    # Handle numeric timestamps (milliseconds since epoch)
                    fields[field] = datetime.fromtimestamp(fields[field] / 1000.0)
        
        # Skip forms without user_id or with user_id not in the users table
        if not fields['user_id']:
            print(f"Skipping form {form_id} without user_id")
            continue
            
        # Check if user exists in the database
        cursor.execute("SELECT uid FROM users WHERE uid = %s", (fields['user_id'],))
        if cursor.rowcount == 0:
            print(f"Error migrating form {form_id}: user_id {fields['user_id']} not found in users table")
            continue
        
        # Convert any dictionary fields to JSON strings
        for key, value in fields.items():
            if isinstance(value, dict):
                fields[key] = json.dumps(value)
        
        # Insert form into PostgreSQL
        try:
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['%s'] * len(fields))
            values = list(fields.values())
            
            query = f"INSERT INTO forms ({columns}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET "
            query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'id'])
            
            cursor.execute(query, values)
            conn.commit()  # Commit after each successful form insertion
            migrated += 1
            
            # Migrate form submissions in separate transactions
            try:
                migrate_form_submissions(form_id, fields['user_id'])
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error migrating submissions for form {form_id}: {e}")
            
            # Migrate form analytics in separate transactions
            try:
                migrate_form_analytics(form_id)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error migrating analytics for form {form_id}: {e}")
            
            # Migrate form versions in separate transactions
            try:
                migrate_form_versions(form_id)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error migrating versions for form {form_id}: {e}")
            
            # Migrate form abandons in separate transactions
            try:
                migrate_form_abandons(form_id)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error migrating abandons for form {form_id}: {e}")
            
            # Migrate form sessions in separate transactions
            try:
                migrate_form_sessions(form_id)
                conn.commit()
            except Exception as e:
                conn.rollback()
                print(f"Error migrating sessions for form {form_id}: {e}")
            
        except Exception as e:
            conn.rollback()
            print(f"Error migrating form {form_id}: {e}")
    
    print(f"Migrated {migrated} forms")
    return migrated

def migrate_form_submissions(form_id, form_owner_id):
    """Migrate submissions for a specific form"""
    cursor = conn.cursor()
    
    # Get submissions for this form
    submissions_ref = db.collection('forms').document(form_id).collection('responses')
    submissions = submissions_ref.stream()
    
    migrated = 0
    for submission in submissions:
        submission_data = submission.to_dict()
        submission_id = submission.id
        
        # Extract submission fields
        fields = {
            'id': submission_id,
            'form_id': form_id,
            'form_owner_id': form_owner_id,
            'data': json.dumps(submission_data.get('data', {})),
            'metadata': json.dumps(submission_data.get('metadata', {})),
            'ip_address': submission_data.get('ipAddress', None),
            'country_code': submission_data.get('countryCode', None),
            'user_agent': submission_data.get('userAgent', None),
            'submitted_at': submission_data.get('submittedAt', None)
        }
        
        # Convert Firestore timestamps to datetime objects
        if fields['submitted_at'] and hasattr(fields['submitted_at'], 'timestamp'):
            fields['submitted_at'] = fields['submitted_at']
        
        # Insert submission into PostgreSQL
        try:
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['%s'] * len(fields))
            values = list(fields.values())
            
            query = f"INSERT INTO submissions ({columns}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET "
            query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'id'])
            
            cursor.execute(query, values)
            migrated += 1
        except Exception as e:
            print(f"Error migrating submission {submission_id} for form {form_id}: {e}")
    
    return migrated

def migrate_form_analytics(form_id):
    """Migrate analytics for a specific form"""
    cursor = conn.cursor()
    
    # Get analytics for this form
    analytics_ref = db.collection('forms').document(form_id).collection('analytics')
    analytics = analytics_ref.stream()
    
    migrated = 0
    for event in analytics:
        event_data = event.to_dict()
        event_id = event.id
        
        # Extract analytics fields
        fields = {
            'id': event_id,
            'form_id': form_id,
            'event_type': event_data.get('eventType', None),
            'data': json.dumps(event_data.get('data', {})),
            'ip_address': event_data.get('ipAddress', None),
            'country_code': event_data.get('countryCode', None),
            'user_agent': event_data.get('userAgent', None),
            'created_at': event_data.get('createdAt', None)
        }
        
        # Convert Firestore timestamps to datetime objects
        if fields['created_at'] and hasattr(fields['created_at'], 'timestamp'):
            fields['created_at'] = fields['created_at']
        
        # Insert analytics event into PostgreSQL
        try:
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['%s'] * len(fields))
            values = list(fields.values())
            
            query = f"INSERT INTO analytics ({columns}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET "
            query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'id'])
            
            cursor.execute(query, values)
            migrated += 1
        except Exception as e:
            print(f"Error migrating analytics event {event_id} for form {form_id}: {e}")
    
    return migrated

def migrate_form_versions(form_id):
    """Migrate versions for a specific form"""
    cursor = conn.cursor()
    
    # Get versions for this form
    versions_ref = db.collection('forms').document(form_id).collection('versions')
    versions = versions_ref.stream()
    
    migrated = 0
    for version in versions:
        version_data = version.to_dict()
        version_id = version.id
        
        # Extract version fields
        fields = {
            'id': version_id,
            'form_id': form_id,
            'version_number': version_data.get('versionNumber', 1),
            'data': json.dumps(version_data.get('data', {})),
            'created_at': version_data.get('createdAt', None)
        }
        
        # Convert Firestore timestamps to datetime objects
        if fields['created_at'] and hasattr(fields['created_at'], 'timestamp'):
            fields['created_at'] = fields['created_at']
        
        # Insert version into PostgreSQL
        try:
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['%s'] * len(fields))
            values = list(fields.values())
            
            query = f"INSERT INTO form_versions ({columns}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET "
            query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'id'])
            
            cursor.execute(query, values)
            migrated += 1
        except Exception as e:
            print(f"Error migrating version {version_id} for form {form_id}: {e}")
    
    return migrated

def migrate_form_abandons(form_id):
    """Migrate form abandons for a specific form"""
    cursor = conn.cursor()
    
    # Get abandons for this form
    abandons_ref = db.collection('form_abandons').document(form_id).collection('entries')
    abandons = abandons_ref.stream()
    
    migrated = 0
    for abandon in abandons:
        abandon_data = abandon.to_dict()
        abandon_id = abandon.id
        
        # Extract abandon fields
        fields = {
            'id': abandon_id,
            'form_id': form_id,
            'data': json.dumps(abandon_data.get('data', {})),
            'ip_address': abandon_data.get('ipAddress', None),
            'country_code': abandon_data.get('countryCode', None),
            'user_agent': abandon_data.get('userAgent', None),
            'created_at': abandon_data.get('createdAt', None)
        }
        
        # Convert Firestore timestamps to datetime objects
        if fields['created_at'] and hasattr(fields['created_at'], 'timestamp'):
            fields['created_at'] = fields['created_at']
        
        # Insert abandon into PostgreSQL
        try:
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['%s'] * len(fields))
            values = list(fields.values())
            
            query = f"INSERT INTO form_abandons ({columns}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET "
            query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'id'])
            
            cursor.execute(query, values)
            migrated += 1
        except Exception as e:
            print(f"Error migrating abandon {abandon_id} for form {form_id}: {e}")
    
    return migrated

def migrate_form_sessions(form_id):
    """Migrate sessions and chunks for a specific form"""
    cursor = conn.cursor()
    
    # Get sessions for this form
    sessions_ref = db.collection('forms').document(form_id).collection('sessions')
    sessions = sessions_ref.stream()
    
    migrated_sessions = 0
    migrated_chunks = 0
    
    for session in sessions:
        session_data = session.to_dict()
        session_id = session.id
        
        # Extract session fields
        fields = {
            'id': session_id,
            'form_id': form_id,
            'metadata': json.dumps(session_data.get('metadata', {})),
            'ip_address': session_data.get('ipAddress', None),
            'country_code': session_data.get('countryCode', None),
            'user_agent': session_data.get('userAgent', None),
            'created_at': session_data.get('createdAt', None)
        }
        
        # Convert Firestore timestamps to datetime objects
        if fields['created_at'] and hasattr(fields['created_at'], 'timestamp'):
            fields['created_at'] = fields['created_at']
        
        # Insert session into PostgreSQL
        try:
            columns = ', '.join(fields.keys())
            placeholders = ', '.join(['%s'] * len(fields))
            values = list(fields.values())
            
            query = f"INSERT INTO sessions ({columns}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET "
            query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'id'])
            
            cursor.execute(query, values)
            migrated_sessions += 1
            
            # Migrate session chunks
            chunks_ref = sessions_ref.document(session_id).collection('chunks')
            chunks = chunks_ref.stream()
            
            for chunk in chunks:
                chunk_data = chunk.to_dict()
                chunk_id = chunk.id
                
                # Extract chunk fields
                chunk_fields = {
                    'id': chunk_id,
                    'session_id': session_id,
                    'form_id': form_id,
                    'chunk_number': int(chunk_id) if chunk_id.isdigit() else 0,
                    'events': json.dumps(chunk_data.get('events', [])),
                    'created_at': chunk_data.get('createdAt', None)
                }
                
                # Convert Firestore timestamps to datetime objects
                if chunk_fields['created_at'] and hasattr(chunk_fields['created_at'], 'timestamp'):
                    chunk_fields['created_at'] = chunk_fields['created_at']
                
                # Insert chunk into PostgreSQL
                try:
                    chunk_columns = ', '.join(chunk_fields.keys())
                    chunk_placeholders = ', '.join(['%s'] * len(chunk_fields))
                    chunk_values = list(chunk_fields.values())
                    
                    chunk_query = f"INSERT INTO session_chunks ({chunk_columns}) VALUES ({chunk_placeholders}) ON CONFLICT (id) DO UPDATE SET "
                    chunk_query += ", ".join([f"{col} = EXCLUDED.{col}" for col in chunk_fields.keys() if col != 'id'])
                    
                    cursor.execute(chunk_query, chunk_values)
                    migrated_chunks += 1
                except Exception as e:
                    print(f"Error migrating chunk {chunk_id} for session {session_id}: {e}")
            
        except Exception as e:
            print(f"Error migrating session {session_id} for form {form_id}: {e}")
    
    return migrated_sessions, migrated_chunks

def migrate_notifications():
    """Migrate user notifications from Firestore to PostgreSQL"""
    print("\nMigrating notifications...")
    cursor = conn.cursor()
    
    # Get all users from Firestore
    users_ref = db.collection('users')
    users = users_ref.stream()
    
    total_migrated = 0
    
    for user in users:
        user_id = user.id
        
        # Get notifications for this user
        notifications_ref = db.collection('notifications').document(user_id).collection('items')
        notifications = notifications_ref.stream()
        
        migrated = 0
        for notification in notifications:
            notification_data = notification.to_dict()
            notification_id = notification.id
            
            # Extract notification fields
            fields = {
                'id': notification_id,
                'user_id': user_id,
                'title': notification_data.get('title', None),
                'message': notification_data.get('message', None),
                'type': notification_data.get('type', 'info'),
                'is_read': notification_data.get('isRead', False),
                'data': json.dumps(notification_data.get('data', {})),
                'created_at': notification_data.get('createdAt', None)
            }
            
            # Convert Firestore timestamps to datetime objects
            if fields['created_at'] and hasattr(fields['created_at'], 'timestamp'):
                fields['created_at'] = fields['created_at']
            
            # Insert notification into PostgreSQL
            try:
                columns = ', '.join(fields.keys())
                placeholders = ', '.join(['%s'] * len(fields))
                values = list(fields.values())
                
                query = f"INSERT INTO notifications ({columns}) VALUES ({placeholders}) ON CONFLICT (id) DO UPDATE SET "
                query += ", ".join([f"{col} = EXCLUDED.{col}" for col in fields.keys() if col != 'id'])
                
                cursor.execute(query, values)
                migrated += 1
            except Exception as e:
                print(f"Error migrating notification {notification_id} for user {user_id}: {e}")
        
        total_migrated += migrated
    
    conn.commit()
    print(f"Migrated {total_migrated} notifications")
    return total_migrated

def main():
    """Main migration function"""
    start_time = time.time()
    print("Starting Firestore to PostgreSQL migration...")
    
    # Migrate users first (they're referenced by other tables)
    user_count = migrate_users()
    
    # Migrate forms and their related collections
    form_count = migrate_forms()
    
    # Migrate notifications
    notification_count = migrate_notifications()
    
    # Close connections
    conn.close()
    
    end_time = time.time()
    duration = end_time - start_time
    
    print("\nMigration completed successfully!")
    print(f"Migrated {user_count} users, {form_count} forms, and {notification_count} notifications")
    print(f"Total duration: {duration:.2f} seconds")

if __name__ == "__main__":
    main()