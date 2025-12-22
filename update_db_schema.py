"""
Script to update the database schema with new columns.

Run this script after updating the models to apply changes to the database.
"""
import sys
import os
from sqlalchemy import text

# Add the parent directory to the path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import engine, Base
from app.models import TrafficLog, BlockedIP, ZeroTrustLog


def update_schema():
    """Update the database schema to match the models."""
    print("Updating database schema...")
    
    # Create all tables (this will only create tables that don't exist)
    Base.metadata.create_all(bind=engine)
    
    # Check if ml_confidence column exists, if not add it
    with engine.connect() as conn:
        # Check if the column exists
        result = conn.execute(
            text("""
            SELECT column_name 
            FROM information_schema.columns 
            WHERE table_name='traffic_logs' AND column_name='ml_confidence'
            """)
        ).fetchone()
        
        if not result:
            print("Adding ml_confidence column to traffic_logs table...")
            conn.execute(
                text("ALTER TABLE traffic_logs ADD COLUMN ml_confidence FLOAT")
            )
            conn.commit()
            print("Successfully added ml_confidence column.")
        else:
            print("ml_confidence column already exists.")
    
    print("Database schema update complete!")


if __name__ == "__main__":
    update_schema()