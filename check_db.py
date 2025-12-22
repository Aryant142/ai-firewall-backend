import os
from sqlalchemy import create_engine
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

# Get database URL from environment variables
DB_NAME = os.getenv("DB_NAME")
DB_USER = os.getenv("DB_USER")
DB_PASSWORD = os.getenv("DB_PASSWORD")
DB_HOST = os.getenv("DB_HOST")
DB_PORT = os.getenv("DB_PORT")

# First, try to connect to the default 'postgres' database to check if the target database exists
try:
    # Connect to the default 'postgres' database
    engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/postgres")
    conn = engine.connect()
    conn.close()
    print("✅ Successfully connected to PostgreSQL server")
    
    # Now check if our database exists
    engine = create_engine(f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/postgres")
    conn = engine.connect()
    result = conn.execute(f"SELECT 1 FROM pg_database WHERE datname = '{DB_NAME}'")
    db_exists = result.scalar()
    
    if not db_exists:
        print(f"❌ Database '{DB_NAME}' does not exist.")
        create = input(f"Would you like to create database '{DB_NAME}'? (y/n): ")
        if create.lower() == 'y':
            conn.execute(f"CREATE DATABASE {DB_NAME}")
            print(f"✅ Database '{DB_NAME}' created successfully!")
    else:
        print(f"✅ Database '{DB_NAME}' exists and is accessible")
    
    conn.close()
    
except Exception as e:
    print(f"❌ Error connecting to PostgreSQL: {e}")
    print("\nPlease check your PostgreSQL settings in the .env file:")
    print(f"DB_USER: {DB_USER}")
    print(f"DB_PASSWORD: {'*' * len(DB_PASSWORD) if DB_PASSWORD else 'Not set'}")
    print(f"DB_HOST: {DB_HOST}")
    print(f"DB_PORT: {DB_PORT}")
    print("\nMake sure PostgreSQL is running and the credentials are correct.")
