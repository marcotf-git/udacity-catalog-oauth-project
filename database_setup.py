"""
This file is used to setup and configurate the database.
It will use the SQLAlchemy modules, and has four parts:
- The configuration code, wich is what we use to import all necessary modules
- The class code, that we use to represent our data in Pythom
- The table that represents the specific table in our database
- The mapper, that connects the columns of our table to the class that represents it
This creates three tables:
    item, user, category
The 'item' table is related to the 'user' and 'category' tables, so for each item,
we have reference to an user and to a category.
"""
#Configuration
from sqlalchemy import (Column,
                        ForeignKey,
                        Integer,
                        String,
                        create_engine)
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from passlib.apps import custom_app_context as pwd_context

# The declarative_base will let SQLAlchemy know that our classes are special
# SQLAlchemy classes that correspond to tables in our database.
Base = declarative_base()
#End of Configuration


#Class
class User(Base):
    #Table
    __tablename__ = 'user'
    #Mapper
    id = Column(Integer, primary_key=True)
    name = Column(String(80))
    email = Column(String(80))
    picture = Column(String(250))
    username = Column(String(32))
    password_hash = Column(String(64))

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)


class Category(Base):
    __tablename__ = 'category'

    id = Column(Integer, primary_key=True)
    name = Column(String(80), nullable=False)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)  #relationship to find the foreign key

    @property
    def serialize(self):
        #Return object data in easily serializeable format
        return {
            'id'    : self.id,
            'name'  : self.name,
        }


class Item(Base):
    __tablename__ = 'item'

    id = Column(Integer, primary_key=True)
    title = Column(String(80), nullable=False)
    description = Column(String(250))
    category_id = Column(Integer, ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
        #Return object data in easily serializeable format
        return {
            'cat_id'           : self.category_id,
            'description'      : self.description,
            'id'               : self.id,
            'title'            : self.title,
        }


#Configuration
#Create a new file database
engine = create_engine('sqlite:///catalog.db')
#Go into the database and add the classes
Base.metadata.create_all(engine)
#End of Configuration
