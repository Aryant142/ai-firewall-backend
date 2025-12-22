import os
import sys
from sqlalchemy import create_engine
from dotenv import load_dotenv

# Add the parent directory to the path so we can import app
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.database import Base, engine
from app.models import TrafficLog, BlockedIP, ZeroTrustLog

def init_db():
    print("Creating database tables...")
    Base.metadata.create_all(bind=engine)
    print("Database tables created successfully!")

if __name__ == "__main__":
    load_dotenv()
    init_db()
