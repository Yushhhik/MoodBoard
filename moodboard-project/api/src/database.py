from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
import os
from pathlib import Path

current_dir = Path(__file__).parent
project_root = current_dir.parent.parent

from dotenv import load_dotenv
load_dotenv(project_root / '.env')

DATABASE_URL = os.getenv("DATABASE_URL")

engine = create_engine(DATABASE_URL)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)