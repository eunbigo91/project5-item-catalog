from flask import Flask, render_template, request, redirect
from flask import url_for, flash, jsonify
from sqlalchemy import create_engine, asc, desc, func
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

from flask import session as login_session
import random, string

from oauth2client.client import flow_from_clientsecrets
from oauth2client.client import FlowExchangeError
import httplib2
import json
from flask import make_response
import requests

app = Flask(__name__)


CLIENT_ID = json.loads(
    open('client_secrets.json', 'r').read())['web']['client_id']
APPLICATION_NAME = "Item Catalog"

# Connect to Database and create database session
engine = create_engine('sqlite:///catalogitem.db')
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# JSON APIs to view catalog information
@app.route('/catalog/JSON')
def catalogJSON():
    output_json = []
    categories = session.query(Category).all()
    for c in categories:
        items = session.query(Item).filter_by(category_id=c.id)
        category_output = {}
        category_output["id"] = c.id
        category_output["name"] = c.name
        category_output["items"] = [i.serialize for i in items]
        output_json.append(category_output)
    return jsonify(Categories=output_json)


# JSON APIs to view category information
@app.route('/catalog/category/JSON')
def categoriesJSON():
    categories = session.query(Category).all()
    return jsonify(categories=[c.serialize for c in categories])


# JSON APIs to view all items information
@app.route('/catalog/allitems/JSON')
def allItemsJSON():
    items = session.query(Item).all()
    return jsonify(items=[i.serialize for i in items])


# JSON APIs to view items by categories information
@app.route('/catalog/<string:category_name>/JSON')
def itemByCategoryJSON(category_name):
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    return jsonify(Category=[category.serialize],
                   Items=[item.serialize for item in items])


# Show all items
@app.route('/')
@app.route('/catalog/')
def showCatalog():
    categories = session.query(Category).order_by(asc(Category.name))
    items = session.query(Item).order_by(desc(Item.edited_At))
    if 'username' not in login_session:
        return render_template('publicCatalog.html',
                               categories=categories, items=items)
    else:
        return render_template('catalog.html',
                               categories=categories, items=items)


@app.route('/catalog/<string:category_name>/', methods=['GET'])
def showCategoryItem(category_name):
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    items = session.query(Item).filter_by(category_id=category.id).all()
    count = session.query(func.count(Item.id)).filter_by(category_id=category.id).scalar()
    if 'username' not in login_session:
        return render_template('publicItem.html', categories=categories,
                               category=category, items=items)
    else:
        return render_template('item.html', categories=categories,
                               category=category, items=items, count=count)


@app.route('/catalog/<string:category_name>/<string:item_name>',
           methods=['GET'])
def showItem(category_name, item_name):
    category = session.query(Category).filter_by(name=category_name).one()
    item = session.query(Item).filter_by(name=item_name,
                                         category_id=category.id).one()
    if 'username' not in login_session:
        return render_template('publicOneItem.html', item=item)
    else:
        return render_template('oneItem.html', item=item)


# Create a new category
@app.route('/catalog/newCategory/', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        return redirect('/login')
    if request.method == 'POST':
        categories = session.query(Category).order_by(asc(Category.name))
        for c in categories:
            if c.name == request.form['name']:
                error = "That category exists already!"
                return render_template('newCategory.html', error=error)
        newCategory = Category(name=request.form['name'],
                               user_id=login_session['user_id'])
        session.add(newCategory)
        session.commit()
        flash(str(newCategory.name) + " has been created!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template('newCategory.html')


# Edit a category
@app.route('/catalog/<string:category_name>/edit',
           methods=['GET', 'POST'])
def editCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    editCategory = session.query(Category).filter_by(name=category_name).one()
    if editCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this category. Please create your own category in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        categories = session.query(Category).order_by(asc(Category.name))
        for c in categories:
            if c.name == request.form['name']:
                error = "That category exists already!"
                return render_template('editCategory.html', error=error)
        editCategory.name = request.form['name']
        session.add(editCategory)
        session.commit()
        flash(str(editCategory.name)+ " has been edited!")
        return redirect(url_for('showCategoryItem',
                        category_name=editCategory.name))
    else:
        return render_template('editCategory.html', category=editCategory)


# Delete a category
@app.route('/catalog/<string:category_name>/delete',
           methods=['GET', 'POST'])
def deleteCategory(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    deleteCategory = session.query(Category).filter_by(name=category_name).one()
    if deleteCategory.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this category. Please create your own category in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(deleteCategory)
        session.commit()
        items = session.query(Item).filter_by(category_id=deleteCategory.id).all()
        for i in items:
            session.delete(i)
            session.commit()
        flash(str(deleteCategory.name) + " has been deleted!")
        return redirect(url_for('showCatalog'))
    else:
        return render_template('deleteCategory.html', category=deleteCategory,
                               item=deleteCategory)


# Create a new item
@app.route('/catalog/newItem/', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        tmp_category = request.form['category']
        new_c = session.query(Category).filter_by(name=tmp_category).one()
        newItem = Item(
            name=request.form['title'], category_id=new_c.id,
            user_id=login_session['user_id'],
            description=request.form['description'])
        session.add(newItem)
        session.commit()
        flash(str(newItem.name) + "(" + str(newItem.category.name) + ")" + " has been created!")
        return redirect(url_for('showItem',
                        category_name=newItem.category.name,
                        item_name=newItem.name))
    else:
        return render_template('newItem.html', categories=categories)


@app.route('/catalog/<string:category_name>/new/', methods=['GET', 'POST'])
def newCategoryItem(category_name):
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).order_by(asc(Category.name))
    if request.method == 'POST':
        tmp_category = request.form['category']
        new_c = session.query(Category).filter_by(name=tmp_category).one()
        newItem = Item(
            name=request.form['title'], category_id=new_c.id,
            user_id=login_session['user_id'],
            description=request.form['description'])
        session.add(newItem)
        session.commit()
        flash(str(newItem.name) + "(" + str(editItem.category.name) + ")" + " has been created!")
        return redirect(url_for('showItem',
                        category_name=newItem.category.name,
                        item_name=newItem.name))
    else:
        return render_template('newItem.html', categories=categories,
                               category_name=category_name)


# Edit a item
@app.route('/catalog/<string:category_name>/<string:item_name>/edit',
           methods=['GET', 'POST'])
def editItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    categories = session.query(Category).order_by(asc(Category.name))
    category = session.query(Category).filter_by(name=category_name).one()
    editItem = session.query(Item).filter_by(name=item_name,
                                             category_id=category.id).one()
    if editItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to edit this item. Please create your own item in order to edit.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        if request.form['title']:
            editItem.name = request.form['title']
        if request.form['description']:
            editItem.description = request.form['description']
        if request.form['category']:
            tmp_category = request.form['category']
            new_c = session.query(Category).filter_by(name=tmp_category).one()
            editItem.category_id = new_c.id
        session.add(editItem)
        session.commit()
        flash(str(editItem.name) + "(" + str(editItem.category.name) + ")" + " has been edited!")
        return redirect(url_for('showItem',
                        category_name=editItem.category.name,
                        item_name=editItem.name))
    else:
        return render_template('editItem.html', category=category,
                               item=editItem, categories=categories)


# Delete a item
@app.route('/catalog/<string:category_name>/<string:item_name>/delete',
           methods=['GET', 'POST'])
def deleteItem(category_name, item_name):
    if 'username' not in login_session:
        return redirect('/login')
    category = session.query(Category).filter_by(name=category_name).one()
    deleteItem = session.query(Item).filter_by(name=item_name,
                                               category_id=category.id).one()
    if deleteItem.user_id != login_session['user_id']:
        return "<script>function myFunction() {alert('You are not authorized to delete this item. Please create your own item in order to delete.');}</script><body onload='myFunction()''>"
    if request.method == 'POST':
        session.delete(deleteItem)
        session.commit()
        flash(str(deleteItem.name) + " has been deleted!")
        return redirect(url_for('showCategoryItem',
                        category_name=category_name))
    else:
        return render_template('deleteItem.html', category=category,
                               item=deleteItem)


# Create anti-forgery state token
@app.route('/login/')
def showLogin():
    state = ''.join(random.choice(string.ascii_uppercase + string.digits)
                    for x in xrange(32))
    login_session['state'] = state
    return render_template('login.html', STATE=state)


@app.route('/gconnect', methods=['POST'])
def gconnect():
    # Validate state token
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    # Obtain authorization code
    code = request.data

    try:
        # Upgrade the authorization code into a credentials object
        oauth_flow = flow_from_clientsecrets('client_secrets.json', scope='')
        oauth_flow.redirect_uri = 'postmessage'
        credentials = oauth_flow.step2_exchange(code)
    except FlowExchangeError:
        response = make_response(
            json.dumps('Failed to upgrade the authorization code.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Check that the access token is valid.
    access_token = credentials.access_token
    url = ('https://www.googleapis.com/oauth2/v1/tokeninfo?access_token=%s'
           % access_token)
    h = httplib2.Http()
    result = json.loads(h.request(url, 'GET')[1])
    # If there was an error in the access token info, abort.
    if result.get('error') is not None:
        response = make_response(json.dumps(result.get('error')), 500)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is used for the intended user.
    gplus_id = credentials.id_token['sub']
    if result['user_id'] != gplus_id:
        response = make_response(
            json.dumps("Token's user ID doesn't match given user ID."), 401)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Verify that the access token is valid for this app.
    if result['issued_to'] != CLIENT_ID:
        response = make_response(
            json.dumps("Token's client ID does not match app's."), 401)
        print "Token's client ID does not match app's."
        response.headers['Content-Type'] = 'application/json'
        return response

    stored_access_token = login_session.get('access_token')
    stored_gplus_id = login_session.get('gplus_id')
    if stored_access_token is not None and gplus_id == stored_gplus_id:
        response = make_response(json.dumps('Current user is already connected.'),
                                 200)
        response.headers['Content-Type'] = 'application/json'
        return response

    # Store the access token in the session for later use.
    login_session['access_token'] = credentials.access_token
    login_session['gplus_id'] = gplus_id

    # Get user info
    userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
    params = {'access_token': credentials.access_token, 'alt': 'json'}
    answer = requests.get(userinfo_url, params=params)

    data = answer.json()

    login_session['username'] = data['name']
    login_session['picture'] = data['picture']
    login_session['email'] = data['email']
    # Add provider to login session
    login_session['provider'] = 'google'

    # See if a user exists, if it doesn't make a new one
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']
    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '
    flash("you are now logged in as %s" % login_session['username'])
    print "done!"
    return output


@app.route('/gdisconnect/')
def gdisconnect():
    # Only disconnect a connected user.
    credentials = login_session.get('credentials')
    if credentials is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = credentials.access_token
    url = 'https://accounts.google.com/o/oauth2/revoke?token=%s' % access_token
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    if result['status'] != '200':
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.'), 400)
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/fbconnect', methods=['POST'])
def fbconnect():
    if request.args.get('state') != login_session['state']:
        response = make_response(json.dumps('Invalid state parameter'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    access_token = request.data

    # Exchange client token for long-lived server-side token
    app_id = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_id']
    app_secret = json.loads(open('fb_client_secrets.json', 'r').read())['web']['app_secret']
    url = 'https://graph.facebook.com/oauth/access_token?grant_type=fb_exchange_token&client_id=%s&client_secret=%s&fb_exchange_token=%s' % (
        app_id, app_secret, access_token)
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]

    # Use token to get user info from API
    userinfo_url = "https://graph.facebook.com/v2.4/me"
    # strip expire tag from access token
    token = result.split("&")[0]

    url = 'https://graph.facebook.com/v2.4/me?%s&fields=name,id,email' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    # print "url sent for API access:%s"% url
    # print "API JSON result: %s" % result
    data = json.loads(result)
    login_session['provider'] = 'facebook'
    login_session['username'] = data["name"]
    login_session['email'] = data["email"]
    login_session['facebook_id'] = data["id"]

    # The token must be stored in the login_session in order to properly logout
    # Let's strip out the information before the equals sign in our token
    stored_token = token.split("=")[1]
    login_session['access_token'] = stored_token

    # Get user picture
    url = 'https://graph.facebook.com/v2.4/me/picture?%s&redirect=0&height=200&width=200' % token
    h = httplib2.Http()
    result = h.request(url, 'GET')[1]
    data = json.loads(result)

    login_session['picture'] = data["data"]["url"]

    # see if user exists
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id

    output = ''
    output += '<h1>Welcome, '
    output += login_session['username']

    output += '!</h1>'
    output += '<img src="'
    output += login_session['picture']
    output += ' " style = "width: 300px; height: 300px;border-radius: 150px;'
    output += '-webkit-border-radius: 150px;-moz-border-radius: 150px;"> '

    flash("Now logged in as %s" % login_session['username'])
    return output


@app.route('/fbdisconnect')
def fbdisconnect():
    facebook_id = login_session['facebook_id']
    # The access token must me included to successfully logout
    access_token = login_session['access_token']
    url = 'https://graph.facebook.com/%s/permissions?access_token=%s' % (facebook_id, access_token)
    h = httplib2.Http()
    result = h.request(url, 'DELETE')[1]
    return "you have been logged out"


# User Helper Functions
def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user


def createUser(login_session):
    newUser = User(name=login_session['username'],
                   email=login_session['email'],
                   picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


# DISCONNECT - Revoke a current user's token and reset their login_session
@app.route('/disconnect')
def disconnect():
    if 'provider' in login_session:
        if login_session['provider'] == 'google':
            gdisconnect()
            del login_session['gplus_id']
            del login_session['access_token']
        if login_session['provider'] == 'facebook':
            fbdisconnect()
            del login_session['facebook_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        del login_session['user_id']
        del login_session['provider']
        flash("You have successfully been logged out.")
        return redirect(url_for('showCatalog'))
    else:
        flash("You were not logged in")
        return redirect(url_for('showCatalog'))


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=8000)
