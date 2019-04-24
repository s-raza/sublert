# Database intergration by s-raza (@pyrod)
from sqlalchemy import *
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import ForeignKey
from sqlalchemy.orm import relationship


Base = declarative_base()

class Domain(Base):
    
    __tablename__ = "domains"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(127), unique=True)
    date_added = Column(DateTime, default=func.now())
    date_updated = Column(DateTime)
    
    
    
class SubDomain(Base):
    
    __tablename__ = "subdomains"
    
    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(127), unique=True)
    date_added = Column(DateTime, default=func.now())

    
    domain_id = Column(Integer, ForeignKey('domains.id'))
    
    domain = relationship("Domain", back_populates="subdomains")
    
Domain.subdomains = relationship("SubDomain", back_populates="domain",  cascade = "all, delete, delete-orphan")
