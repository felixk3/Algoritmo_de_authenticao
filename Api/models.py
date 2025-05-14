from sqlalchemy import create_engine, Column, Integer, String, Boolean
from database import Base,engine

# --------------------------
# Modelos SQLAlchemy (models.py)
# --------------------------
class UserDB(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True)
    email = Column(String, unique=True, index=True)
    full_name = Column(String)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)

# Cria as tabelas no banco de dados
Base.metadata.create_all(bind=engine)

