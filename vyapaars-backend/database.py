
import os
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from dotenv import load_dotenv

# Load environment variables from a .env file for local development
load_dotenv()

# Get the database URL from environment variables.
# This makes it easy to switch between local SQLite and production PostgreSQL.
DATABASE_URL = os.environ.get("DATABASE_URL", "sqlite:///./vyapaars_local.db")

engine = create_engine(
    DATABASE_URL,
    # The connect_args are only for SQLite. They won't be used for PostgreSQL.
    connect_args={"check_same_thread": False} if "sqlite" in DATABASE_URL else {}
)

# Each instance of the SessionLocal class will be a new database session.
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

# Base class for our database models
Base = declarative_base()

# Dependency to get a DB session in API endpoints
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
