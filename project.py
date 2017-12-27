"""
Catalog Item App

This program is a web application that provides a list of items within a variety
of categories and integrate third party user registration and authentication.

Authenticated users have ability to create, edit and delete their own items.

The program uses SQLAlchemy to make CRUD operations in the database 'catalog.db'.
https://www.sqlalchemy.org/

It also uses Flask framework to run the server, to map the routes, to render the
templates, to extract data from forms, and to control the session, mainly.
http://flask.pocoo.org/

There is the option to authenticate the users with third party via Oauth2 protocol.
The program uses the Google provider (mixed protocol).
For the setup, it is necessary to proceed according to the instructions on
https://developers.google.com/identity/protocols/OAuth2
to create a client_secrets file and download it into the app folder.
This will give to the app the client id necessary for the oauth protocol.

"""

import random
import string
import json
from collections import OrderedDict
from flask import  (Flask,
                    render_template,
                    request,
                    redirect,
                    jsonify,
                    url_for,
                    flash,
                    make_response,
                    session as login_session)
from sqlalchemy import (create_engine,
                        asc)
from sqlalchemy.orm import sessionmaker
from database_setup import (Base,
                            Category,
                            Item,
                            User)
from oauth2client.client import (flow_from_clientsecrets,
                                 FlowExchangeError)
import httplib2
import requests


app = Flask(__name__)

# Configure Flask JSON to not sort the dictionary when serialize to JSON,
# so we can choose the order of variables to show.
app.config.update(
    JSON_SORT_KEYS=False,
)

#client id to access the one session token at oauth protocol
CLIENT_ID = json.loads(open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog Application"

#Connect to Database and create database session
engine = create_engine('sqlite:///catalog.db')
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
session = DBSession()


#Render Login page
@app.route('/login')
def showLogin():
    print('in showLogin')
    # Create a state token to prevent request forgery.
    # Store it in the session for later validation.
    state = ''.join(random.choice(string.ascii_uppercase + string.digits) \
        for x in range(32))
    login_session['state'] = state
    #return "The current session state is %s" % login_session['state']
    #Render the login template, to obtain the auth code from Google
    return render_template('login.html', state=state, CLIENT_ID=CLIENT_ID)


#Local login
@app.route('/local_login', methods=['POST'])
def local_login():
    print('at local login')
    print(request.form)

    #Test for valid state token (unique session anti-forgery atack code)
    print('testing for valid state token')
    if request.form.get('state') != login_session.get('state'):
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    username_or_email = request.form.get('username_or_email')
    password = request.form.get('password')

    #Check to see if there are arguments
    if not username_or_email or not password:
        print("missing arguments")
        return "<!DOCTYPE html><h2>Missing arguments.</br>" + \
                "Please, verify the data informed.</br>" + \
                "Redirecting...</h2><script>" + \
                "setTimeout(function(){window.location.href='/';}, 4000);" + \
                "</script><style>h2{width: 50%; margin: 15% auto;}</style>"

    #Check if the user exists
    print('verifying username or email')
    user = session.query(User).filter_by(username=username_or_email).first()
    if not user:
        user = session.query(User).filter_by(email=username_or_email).first()

    if not user:
        return  "<!DOCTYPE html><h2>Login is not possible for this username or"+\
                " email.</br>The username or the email is not known.</br>" + \
                "Redirecting...</h2>" + \
                "<script>setTimeout(function(){window.location.href='/';}, 4000);" + \
                "</script><style>h2{width: 50%; margin: 15% auto;}</style>"

    #Check the password
    print('verifying the password')
    if user.verify_password(password):
        #Loggin the user
        login_session['user_id'] = user.id
        login_session['name'] = user.name
        login_session['email'] = user.email
        login_session['username'] = user.username
        login_session['provider'] = 'local'
        return  "<!DOCTYPE html><h2>Login Successful for: " + user.name + \
                "<br> having the username: "  + user.username + "<br>" + \
                " and email : "  + user.email + "<br>Redirecting...</h2><script>" + \
                "setTimeout(function(){window.location.href='/';}, 4000);" + \
                "</script><style>h2{width: 50%; margin: 15% auto;}</style>"
    else:
        return  "<!DOCTYPE html><h2>Login is not possible. Verify the password " + \
                "informed.<br>Redirecting...</h2>" + \
                "<script>setTimeout(function(){window.location.href='/';}, 4000);" + \
                "</script><style>h2{width: 50%; margin: 15% auto;}</style>"


#Register new users
@app.route('/new_user', methods=['GET', 'POST'])
def new_user():
    print('at new user')

    if request.method == 'GET':
        state = ''.join(random.choice(string.ascii_uppercase + string.digits) \
            for x in range(32))
        login_session['state'] = state
        return render_template('newUser.html', STATE=state)

    print(request.form)

    if request.method == 'POST':
        #Test for valid state token (unique session anti-forgery atack code)
        print('testing for valid state token')
        if request.form.get('state') != login_session.get('state'):
            response = make_response(json.dumps('Invalid state parameter'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        name = request.form.get('name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        conf_password = request.form.get('conf_password')

        if (not username and not email) or not password:
            print("missing arguments")
            return "<!DOCTYPE html><h2>User registration is not possible. " + \
                    "Missing arguments.</br>" + \
                    "It is necessary username or email, and password. "+ \
                    "Redirecting...</h2><script>" + \
                    "setTimeout(function(){window.location.href='/';}, 4000);" + \
                    "</script><style>h2{width: 50%; margin: 15% auto;}</style>"

        #Check to see if password matches
        if password != conf_password:
            print("password does not match")
            return "<!DOCTYPE html><h2>User registration is not possible.</br>" + \
                    "Password does not match. "+\
                    "Redirecting...</h2><script>" + \
                    "setTimeout(function(){window.location.href='/new_user';}, 4000);" + \
                    "</script><style>h2{width: 50%; margin: 15% auto;}</style>"

        #Check if user with that username already exist
        if session.query(User).filter_by(username=username).first() is not None:
            print("existing username")
            user = session.query(User).filter_by(username=username).first()
            #return jsonify({'message':'user already exists'}), 200
            return  "<!DOCTYPE html><h2>User with username '"  + user.username + \
                    "' already exist.</br>" + \
                    "Login is not possible. Redirecting...</h2>" + \
                    "<script>setTimeout(function(){window.location.href='/';}, 4000);" + \
                    "</script><style>h2{width: 50%; margin: 15% auto;}</style>"

        #Check if user with that email already exist
        if session.query(User).filter_by(email=email).first() is not None:
            print("existing email")
            user = session.query(User).filter_by(email=email).first()
            #return jsonify({'message':'user already exists'}), 200
            return  "<!DOCTYPE html><h2>User with email '"  + user.email + \
                    "' already exist.</br>" + \
                    "Login is not possible. Redirecting...</h2>" + \
                    "<script>setTimeout(function(){window.location.href='/';}, 4000);" + \
                    "</script><style>h2{width: 50%; margin: 15% auto;}</style>"

        #Create new user
        user = User(name=name, username=username, email=email)
        user.hash_password(password)
        print('username', user.username, ' created')
        session.add(user)
        session.commit()
        #return jsonify({ 'username': user.username, 'email': user.email }), 201
        return  "<!DOCTYPE html><h2>User '" + user.username + \
                "' Successfully Created!</br>" + \
                "Redirecting to the login page...</h2>" + \
                "<script>setTimeout(function(){window.location.href='/login';}, 4000);" + \
                "</script><style>h2{width: 50%; margin: 15% auto;}</style>"


# CONNECT - Obtain a current user's token by upgrading the authorization code
# sent by the user to the server (auth code obtained from Google)
@app.route('/gconnect', methods=['POST'])
def gconnect():
    #Test for valid state token (unique session anti-forgery atack code)
    print('testing for valid state token')
    if request.args.get('state') != login_session.get('state'):
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    #Parse authorization code (that was obtained from Google)
    code = request.data

    try:
        print('upgrading the authorization code into a credentials object')
        #Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        print('failed to upgrade the authorization')
        response = make_response(json.dumps('Failed to upgrade the authorization'+\
            ' code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    #Check that the access token is valid.
    print('checking that the access token is valid')
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    #If there was an error in the access token info, abort.
    if result.get('error') is not None:
        print('access token is not valid')
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    #Verify that the access token is used for the intended user
    print('verifying that the access token is used for the intended user')
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        print('access token invalid for this user')
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    #Verify that the access token is valid for this app
    print('verifying that the access token is valid for this app')
    if result['issued_to'] != CLIENT_ID:
        print('access token invalid for this app')
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print("Token's client ID does not match app's.")
        response.headers['Content-Type'] = 'application/json'
        return response

    #Check to see if user is already logged in
    print('checking to see if user is already logged in')
    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        print('current user already connected')
        response = make_response(json.dumps('Current user is already'+\
            ' connected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    #Store the access token in the session for later use.
    print('storing the access token in the session for later use')
    login_session['provider'] = 'google'
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = credentials.id_token['sub']

    #Get user info from oauth provider
    print('getting user info')
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)
    data = json.loads(answer.text)

    login_session['name'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']

    # Check to see if user exists (by the email). If it doesn't, create new user.
    # The email will be the main parameter to distinguish between users
    print('checking to see if user exists')
    user_id = getUserID(login_session['email'])

    if not user_id:
        print('creating new user')
        user_id = createUser(login_session)
        newUser = session.query(User).filter_by(id=user_id).one()
        print('New User %s Successfully Created' % newUser.name)

    #Write the user.id in the session (this will be used for the session control)
    login_session['user_id'] = user_id

    #Make login message
    print('making login message')
    output = ''
    output += '<!DOCTYPE html><h2>Welcome, '
    output += login_session['name']
    output += '!</h2>'
    output += '<img src="'
    output += login_session.get('picture')
    output += '" style = "width: 150px; height: 150px; border-radius: 75px;'+\
        ' -webkit-border-radius: 75px; -moz-border-radius: 75px;"> '
    output += '<br><h3>Redirecting... </h3>'
    flash("you are now logged as %s" % login_session['name'])
    print("loggin done!")
    return output


#Return a user object associated with the email
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None

#Return a user object associated with the id
def getUserInfo(user_id):
    try:
        user = session.query(User).filter_by(id=user_id).one()
        return user
    except:
        return None

#Create a new user and return the user id
def createUser(loginSession):
    newUser = User(name=loginSession.get('username'),
                   email=loginSession.get('email'),
                   picture=loginSession.get('picture'))
    session.add(newUser)
    session.commit()
    # The id is associated with the email in getUserInfo. So is not possible
    # to create another user with the same email because the app checks if
    # there is the id before calling createUser. Because of this, the following
    # query can find only one user for the gived email.
    return newUser.id


#DISCONNECT - Revoke a current user's Google token
@app.route('/gdisconnect')
def gdisconnect():
    access_token = login_session.get('access_token')
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    #revoke the token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] == '200':
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        return response
    else:
        response = make_response(json.dumps('Failed to revoke token for given'+\
            ' user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


# Disconnect based in provider
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        #This is for connections via Google oauth
        if login_session['provider'] == 'google':
            print('deleting user registered with Google oauth')
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
            del login_session['picture']
        #This is for a locally registered user
        if login_session['provider'] == 'local':
            print('deleting user locally registered')
            #only locally registered users have a username loaded
            del login_session['username']
        #This is for all users
        del login_session['user_id']
        del login_session['name']
        del login_session['email']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCategories'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCategories'))


#JSON API
@app.route('/catalog.json')
def catalogJSON():
    catalog_list = []
    categories = session.query(Category).all()
    for category in categories:
        category_dict = OrderedDict(category.serialize)
        items = session.query(Item).filter_by(category_id=category.id).all()
        items_list = [item.serialize for item in items]
        category_dict["Item"] = items_list
        catalog_list.append(category_dict)
    print(catalog_list)
    return jsonify(Category=catalog_list)


#Show all categories
@app.route('/')
def showCategories():
    print('in showCategories')
    categories = session.query(Category).order_by(asc(Category.name)).all()
    print('render categories')
    return render_template('categories.html', categories=categories)


#Create a new category
@app.route('/category/new/', methods=['GET', 'POST'])
def newCategory():
    print('in new category')
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        #Create new category
        new_category = Category(name=request.form['name'],
                                user_id=login_session.get('user_id'))
        session.add(new_category)
        session.commit()
        flash('New Category "%s" Successfully Created' % new_category.name)
        return redirect(url_for('showCategories'))
    else:
        return render_template('newCategory.html')


#Edit a category
@app.route('/category/<int:category_id>/edit/', methods=['GET', 'POST'])
def editCategory(category_id):
    print('in edit category')
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect('/login')
    #Protect category pages from unauthorized users
    categoryToEdit = session.query(Category).filter_by(id=category_id).one()
    if categoryToEdit.user_id != login_session['user_id']:
        print('message of not authorized: not the creator')
        return  "<!DOCTYPE html><script>alert('You are not authorized " + \
                "to edit this category because you are not the creator of it. " + \
                "Please create your own category in order to proceed.');" + \
                "setTimeout(function(){window.location.href='/';}, 100);" + \
                "</script>"
    #Search if there are items in category. Only edit if it is empty.
    items = session.query(Item).filter_by(category_id=category_id).all()
    if items:
        print('message of not authorized: category not empty')
        return "<!DOCTYPE html><script>alert('It is not possible " + \
                "to edit this category. It is not empty. " + \
                "Please delete items before to edit the category.');" + \
                "setTimeout(function(){window.location.href='/';}, 100);" + \
                "</script>"

    if request.method == 'POST':
        if request.form['name']:
            categoryToEdit.name = request.form['name']
        session.add(categoryToEdit)
        session.commit()
        flash('Category "%s" successfully edited!' % categoryToEdit.name)
        return redirect(url_for('showCategories'))
    else:
        return render_template('editCategory.html', category=categoryToEdit)


#Delete a category
@app.route('/category/<int:category_id>/delete/', methods=['GET', 'POST'])
def deleteCategory(category_id):
    print('in delete category')
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect('/login')
    #Protect category pages from unauthorized users
    categoryToDelete = session.query(Category).filter_by(id=category_id).one()
    if categoryToDelete.user_id != login_session['user_id']:
        print('message of not authorized: not the creator')
        return  "<!DOCTYPE html><script>alert('You are not authorized " + \
                "to delete this category because you are not the creator of it. " + \
                "Please create your own category in order to proceed.');" + \
                "setTimeout(function(){window.location.href='/';}, 100);" + \
                "</script>"
    #Search if there are items in category. Only delete if it is empty.
    items = session.query(Item).filter_by(category_id=category_id).all()
    if items:
        print('message of not authorized: category not empty')
        return "<!DOCTYPE html><script>alert('It is not possible "+\
                "to delete this category. It is not empty. "+\
                "Please delete items before to delete the category.');"+ \
                "setTimeout(function(){window.location.href='/';}, 100);" + \
                "</script>"

    if request.method == 'POST':
        session.delete(categoryToDelete)
        flash('"%s" Successfully Deleted' % categoryToDelete.name)
        session.commit()
        return redirect(url_for('showCategories'))
    else:
        return render_template('deleteCategory.html', category=categoryToDelete)


#Show category items
@app.route('/category/<int:category_id>/items')
def showCategoryItems(category_id):
    category = session.query(Category).filter_by(id=category_id).one()
    items = session.query(Item).filter_by(category_id=category_id).all()
    #Require logged users
    print('login_session user_id', login_session.get('user_id'))
    return render_template('items.html', items=items, category=category)


#Create a new item
@app.route('/category/item/new', methods=['GET', 'POST'])
def newCategoryItem():
    print('in new category item')
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect('/login')

    if request.method == 'POST':
        #Create the new item in the category selected
        newItem = Item(title=request.form['title'], \
                       description=request.form['description'], \
                       category_id=request.form['category_id'], \
                       user_id=login_session.get('user_id'))
        session.add(newItem)
        session.commit()
        flash('New Item "%s" Successfully Created' % (newItem.title))
        return redirect(url_for('showCategoryItems', \
                        category_id=request.form['category_id']))
    else:
        categories = session.query(Category).order_by(asc(Category.name))
        return render_template('newCategoryItem.html', categories=categories)


#Edit an item
@app.route('/category/<int:category_id>/item/<int:item_id>/edit', \
           methods=['GET', 'POST'])
def editCategoryItem(category_id, item_id):
    print('in edit category item')
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect('/login')
    #Protect item pages from unauthorized users
    editedItem = session.query(Item).filter_by(id=item_id).one()
    if editedItem.user_id != login_session['user_id']:
        print('message of not authorized: not the creator')
        return  "<!DOCTYPE html><script>alert('You are not authorized " + \
                "to edit this item because you are not the creator of it. " + \
                "Please create your own item in order to proceed.');" + \
                "setTimeout(function(){window.location.href='/category/" + \
                str(category_id) + "/items';}, 100);</script>"

    if request.method == 'POST':
        if request.form['title']:
            editedItem.title = request.form['title']
        if request.form['description']:
            editedItem.description = request.form['description']
        session.add(editedItem)
        session.commit()
        flash("Item '%s' Successfully Edited" % editedItem.title)
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('editCategoryItem.html', category_id=category_id, \
                                item=editedItem)


#Delete an item
@app.route('/category/<int:category_id>/item/<int:item_id>/delete', \
           methods=['GET', 'POST'])
def deleteCategoryItem(category_id, item_id):
    print('in delete category item')
    #Grant access only to logged users
    if 'user_id' not in login_session:
        return redirect('/login')
    #Protect item pages from unauthorized users
    itemToDelete = session.query(Item).filter_by(id=item_id).one()
    if itemToDelete.user_id != login_session['user_id']:
        print('message of not authorized: not the creator')
        return  "<!DOCTYPE html><script>alert('You are not authorized " + \
                "to delete this item because you are not the creator of it. " + \
                "Please create your own item in order to proceed.');" + \
                "setTimeout(function(){window.location.href='/category/" + \
                str(category_id) + "/items';}, 100);</script>"

    if request.method == 'POST':
        session.delete(itemToDelete)
        session.commit()
        flash("Item '%s' Successfully Deleted" % itemToDelete.title)
        return redirect(url_for('showCategoryItems', category_id=category_id))
    else:
        return render_template('deleteCategoryItem.html', category_id=category_id, \
                                item=itemToDelete)


if __name__ == '__main__':
    #Secret key automatically generated, used by Flask to encrypt the session cookies
    app.secret_key = ''.join(random.choice(string.ascii_uppercase + string.digits) \
        for x in range(32))
    #Debug mode on
    app.debug = True
    #Server URL, '0.0.0.0' means all public ip addresses
    app.run(host='0.0.0.0', port=8000)
