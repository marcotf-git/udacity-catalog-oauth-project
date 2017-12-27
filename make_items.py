from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()


# Create dummy user
user1 = User(name="Robo Cataloger", email="user1@testing.com",
             picture='https://pbs.twimg.com/profile_images/2671170543/18debd694829ed78203a5a36dd364160_400x400.png')
session.add(user1)
session.commit()

# Create categories and items
category1 = Category(name="Athletics")
session.add(category1)
session.commit()

category2 = Category(name="Baseball")
session.add(category2)
session.commit()

category3 = Category(name="Basketball")
session.add(category3)
session.commit()

category4 = Category(name="Football")
session.add(category4)
session.commit()

category5 = Category(name="Surfing")
session.add(category5)
session.commit()

category6 = Category(name="Tennis")
session.add(category6)
session.commit()

#Create items
description = "2 pack running socks mens with an confortable and ergonomic fit."
item1 = Item(title="Socks Mens", description=description, category=category1, \
             user=user1)
session.add(item1)
session.commit()

description = "Long jump mens running spikes designed for the Triple Jump." + \
    " Have a foam midsole to cushion landings."
item2 = Item(title="Running Spikes", description=description, category=category1, \
             user=user1)
session.add(item2)
session.commit()

description = "Fielding mitt mens crafted in soft PVC with soft fleece lining" + \
    " accross the wrist."
item3 = Item(title="Fielding Mitt", description=description, category=category2, \
             user=user1)
session.add(item3)
session.commit()

description = "Styled jersey with a lightweight fabric, 100% polyester."
item4 = Item(title="Basketball Jersey", description=description, category=category3, \
             user=user1)
session.add(item4)
session.commit()

description = "Surfboard made of expanded polyestyrene foam (EPS), that is stronger" + \
    " and lighter than traditional PU/PE construction."
item5 = Item(title="Surfboard", description=description, category=category5, \
             user=user1)
session.add(item5)
session.commit()

description = "Surfboard leash made of uretane cord."
item6 = Item(title="Leash", description=description, category=category5, \
             user=user1)
session.add(item6)
session.commit()

print "added items!"
