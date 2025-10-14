#!/usr/bin/env python
"""
PostgreSQL database setup script for CleanEnroll
This script creates the database and tables defined in schema.sql
"""

import os
import sys
import psycopg2
from psycopg2.extensions import ISOLATION_LEVEL_AUTOCOMMIT
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Database connection parameters
DB_NAME = os.getenv("POSTGRES_DB", "cleanenroll")
DB_USER = os.getenv("POSTGRES_USER", "postgres")
DB_PASSWORD = os.getenv("POSTGRES_PASSWORD", "Esstafa00uni@")
DB_HOST = os.getenv("POSTGRES_HOST", "localhost")
DB_PORT = os.getenv("POSTGRES_PORT", "5432")

def create_database():
    """Create the database if it doesn't exist"""
    try:
        # Connect to PostgreSQL server
        conn = psycopg2.connect(
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        conn.set_isolation_level(ISOLATION_LEVEL_AUTOCOMMIT)
        cursor = conn.cursor()
        
        # Check if database exists
        cursor.execute("SELECT 1 FROM pg_catalog.pg_database WHERE datname = %s", (DB_NAME,))
        exists = cursor.fetchone()
        
        if not exists:
            print(f"Creating database {DB_NAME}...")
            cursor.execute(f"CREATE DATABASE {DB_NAME}")
            print(f"Database {DB_NAME} created successfully")
        else:
            print(f"Database {DB_NAME} already exists")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Error creating database: {e}")
        return False

def setup_tables():
    """Create tables from schema.sql"""
    try:
        # Connect to the database
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        cursor = conn.cursor()
        
        # Read schema file
        schema_path = os.path.join(os.path.dirname(__file__), "schema.sql")
        with open(schema_path, "r") as f:
            schema_sql = f.read()
        
        # Execute schema SQL
        print("Creating tables...")
        cursor.execute(schema_sql)
        conn.commit()
        print("Tables created successfully")
        
        cursor.close()
        conn.close()
        return True
    except Exception as e:
        print(f"Error setting up tables: {e}")
        return False

if __name__ == "__main__":
    print("Setting up CleanEnroll PostgreSQL database...")
    
    if create_database():
        if setup_tables():
            print("Database setup completed successfully")
        else:
            sys.exit(1)
    else:
        sys.exit(1)