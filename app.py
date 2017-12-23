from flask import Flask, request, make_response, render_template, jsonify,\
    session, url_for, redirect, flash, send_from_directory
from flask_login import LoginManager, UserMixin, login_user, login_required,\
                        logout_user, current_user
from flask_admin import Admin, BaseView, expose
import uuid
from uuid import getnode as get_mac
from flask.ext.bcrypt import Bcrypt
from bson.objectid import ObjectId
from functools import wraps
from difflib import SequenceMatcher
from datetime import datetime, timedelta
import time
import datetime
import traceback
import flask_login
import flask
import json
import jwt
import os
from db import Mdb

app = Flask(__name__)

bcrypt = Bcrypt(app)
mdb = Mdb()


#############################################
#                                           #
#              WORKING  SESSION             #
#                                           #
#############################################
@app.before_request
def before_request():
    flask.session.permanent = True
    app.permanent_session_lifetime = datetime.timedelta(minutes=30)
    flask.session.modified = True
    flask.g.user = flask_login.current_user


app.config['secretkey'] = 'some-strong+secret#key'
app.secret_key = 'F12Zr47j\3yX R~X@H!jmM]Lwf/,?KT'

# setup login manager
login_manager = LoginManager()
login_manager.init_app(app)


#############################################
#                                           #
#        _id of mongodb record was not      #
#           getting JSON encoded, so        #
#           using this custom one           #
#                                           #
#############################################
class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return json.JSONEncoder.default(self, o)


#############################################
#                                           #
#                SESSION COUNTER            #
#                                           #
#############################################
def sumSessionCounter():
    try:
        session['counter'] += 1
    except KeyError:
        session['counter'] = 1


##############################################
#                                            #
#           Login Manager                    #
#                                            #
##############################################
@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/')


#############################################
#                                           #
#              TOKEN REQUIRED               #
#                                           #
#############################################
app.config['secretkey'] = 'some-strong+secret#key'


def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.args.get('token')

        # ensure that token is specified in the request
        if not token:
            return jsonify({'message': 'Missing token!'})

        # ensure that token is valid
        try:
            data = jwt.decode(token, app.config['secretkey'])
        except:
            return jsonify({'message': 'Invalid token!'})
        return f(*args, **kwargs)
    return decorated


############################################################################
#                                                                          #
#                                WHO AM I ROUTE                            #
#                                                                          #
############################################################################
@app.route('/user/whoami')
def whoami():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        ret['User'] = (" hii i am %s !!" % session['name'])
        email = session['email']
        ret['Session'] = email
        ret['err'] = 0
        ret['User_Id'] = mdb.get_user_id_by_session(email)
    except Exception as exp:
        ret['err'] = 1
        ret['user'] = 'user is not login'
    return JSONEncoder().encode(ret)


@app.route('/')
@app.route('/user/login')
def home():
    templeteData = {'title': 'Home'}
    return render_template('user/login.html', **templeteData)


@app.route('/user/signup')
def signup():
    templeteData = {'title': 'Signup page'}
    return render_template('user/signup.html', **templeteData)


############################################################################
#                                                                          #
#          CHECK CANDIDATE ALREADY REGISTERED OR NOT THEN REGISTER         #
#                            PASSWORD  BCRYPT                              #
#                                                                          #
############################################################################
@app.route('/user/register', methods=['POST'])
def add_user():
    try:
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        # password bcrypt  #
        pw_hash = bcrypt.generate_password_hash(password)
        passw = bcrypt.check_password_hash(pw_hash, password)

        check = mdb.check_email(email)
        if check:
            templateData = {'title': 'Signup Page'}
            return render_template('user/signup.html', **templateData)

        else:
            mdb.add_user(name, email, pw_hash)
            return render_template('user/login.html', session=session)
    except Exception as exp:
        print('add_user() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return render_template('user/signup.html', **templateData)


############################################################################
#                                                                          #
#                              CANDIDATE LOGIN                             #
#        STORED INFORMATION[SESSION_ID, MAC_ADDRESS, IP OR BROWSER]        #
#     SEESION TIME 30 MIN (SEESION LOGOUT AUTOMATICALLY AFTER 30 MINs      #
#                                                                          #
############################################################################
@app.route('/user/login', methods=['POST'])
def login():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']
        if mdb.user_exists(email):
            pw_hash = mdb.get_password(email)
            print('password in server, get from db class', pw_hash)
            passw = bcrypt.check_password_hash(pw_hash, password)

            if passw == True:
                name = mdb.get_name(email)
                session['name'] = name
                session['email'] = email

                # Login Successful!
                expiry = datetime.datetime.utcnow() + datetime.\
                    timedelta(minutes=30)

                token = jwt.encode({'user': email, 'exp': expiry},
                                   app.config['secretkey'], algorithm='HS256')
                # flask_login.login_user(user, remember=False)
                ret['msg'] = 'Login successful'
                ret['err'] = 0
                ret['token'] = token.decode('UTF-8')
            else:
                return render_template('user/login.html', session=session)

        else:
            # Login Failed!
            return render_template('user/login.html', session=session)

            ret['msg'] = 'Login Failed'
            ret['err'] = 1

        LOGIN_TYPE = 'User Login'
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr

        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)

    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    return render_template('user/login.html', session=session)


############################################################################
#                                                                          #
#                                    ADD POST                              #
#                                                                          #
############################################################################
@app.route('/user/posting')
def posting():
    templeteData = {'title': 'Posting'}
    return render_template('user/posting.html', **templeteData)


@app.route('/user/ad_post', methods=['POST'])
def ad_post():
    try:
        title = request.form['title']
        price = request.form['price']
        category = request.form['category']
        description = request.form['description']
        email = session['email']
        name = session['name']
        city = request.form['city']

        mdb.ad_post(title, price, category, description, email, name, city)
        return render_template('user/save_ad.html', session=session)

    except Exception as exp:
        print('ad_post() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return render_template('user/posting.html', session=session)


############################################################################
#                                                                          #
#                                MY ADs                                    #
#                                                                          #
############################################################################
@app.route('/user/my_ads', methods=['GET'])
def my_ads():
    try:
        email = session['email']
        result = mdb.my_ad(email)
        templateData = {'title': 'result', 'result': result}
        return render_template('user/my_ads.html', **templateData)

    except Exception as exp:
        print('search() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return render_template('user/my_ads.html')


############################################################################
#                                                                          #
#                                SEND MSG                                  #
#                                                                          #
############################################################################
@app.route("/user/send_msg", methods=['GET'])
def create_msg():
    id = request.args.get("id")
    msg = mdb.get_msg_by_id(id)
    post = mdb.get_post(id)

    temp_data = {'title': 'post msg', 'post': post,  'msg': msg}
    return render_template('user/create_msg.html', **temp_data)


############################################################################
#                                                                          #
#                      Search Product By Category Route                    #
#                                                                          #
############################################################################
@app.route('/user/search_product')
def search_product():
    templeteData = {'title': 'search product'}
    return render_template('user/search_product.html', **templeteData)


############################################################################
#                                                                          #
#                      Search Product By Category                          #
#                                                                          #
############################################################################
@app.route('/user/search_cat', methods=['POST'])
def search_cat():
    try:
        text = request.form['category']
        result = mdb.search_cat(text)

        templateData = {'title': 'Searching..', 'result': result}
        return render_template('user/search_product.html', **templateData)

    except Exception as exp:
        print('search_cat() :: Got exception: %s' % exp)
        print(traceback.format_exc())


############################################################################
#                                                                          #
#                                SAVE MSG                                  #
#                                                                          #
############################################################################
@app.route("/user/save_msg", methods=['POST'])
def save_msg():
    try:
        title = request.form['title']
        user = request.form['user']
        id = request.form['id']
        msg = request.form['msg']

        mdb.add_msg(title, user, id, msg)
        return render_template('user/login.html')

    except Exception as exp:
        print('save_msg() :: Got exception: %s' % exp)
        print(traceback.format_exc())
        return render_template('user/search_product.html')


############################################################################
#                                                                          #
#                                SEND MSG                                  #
#                                                                          #
############################################################################
# @app.route('/user/save_msg', methods=['POST'])
# def save_msg():
#     try:
#         title = request.form['title']
#         price = request.form['price']
#         category = request.form['category']
#         description = request.form['description']
#
#         email = session['email']
#         name = session['name']
#         city = request.form['city']
#
#         mdb.ad_post(title, price, category, description, email, name, city)
#         return render_template('user/save_ad.html', session=session)
#
#     except Exception as exp:
#         print('ad_post() :: Got exception: %s' % exp)
#         print(traceback.format_exc())
#
#


@app.route('/user/myaccount')
def myaccount():
    templeteData = {'title': 'MyAccount'}
    return render_template('user/myaccount.html', **templeteData)


############################################################################
#                                                                          #
#                                 SEARCH POST                              #
#                                                                          #
############################################################################
@app.route('/user/search', methods=['POST'])
def search():
    try:
        city = request.form['city']
        product = request.form['product']
        result = mdb.search_ad(city, product)

        templateData = {'title': 'Searching..', 'result': result}
        return render_template('user/search.html', **templateData)

    except Exception as exp:
        print('search() :: Got exception: %s' % exp)
        print(traceback.format_exc())


############################################################################
#                                                                          #
#                       USER SESSION LOGOUT                                #
#       STOREED USER INFORMATION WHEN USER LOGOUT ALL DEATAILS.            #
#                                                                          #
############################################################################
@app.route('/user/logout')
def clearsession():
    try:
        LOGIN_TYPE = 'User Logout'
        sumSessionCounter()
        email = session['email']
        user_email = email
        mac = get_mac()
        ip = request.remote_addr
        agent = request.headers.get('User-Agent')
        mdb.save_login_info(user_email, mac, ip, agent, LOGIN_TYPE)
        session.clear()
        return 'Logout Done!'
    except Exception as exp:
        return render_template('user/login.html')


##############################################################################
#                                                                            #
#                                   ADMIN LOGIN                              #
#                                                                            #
##############################################################################
@app.route('/admin/login', methods=['POST'])
def admin_login():
    ret = {'err': 0}
    try:
        sumSessionCounter()
        email = request.form['email']
        password = request.form['password']

        if mdb.admin_exists(email, password):
            # name = mdb.get_admin_name(email)
            session['email'] = email

            expiry = datetime.datetime.utcnow() + datetime.\
                timedelta(minutes=30)
            token = jwt.encode({'user': email, 'exp': expiry},
                               app.config['secretkey'], algorithm='HS256')
            ret['msg'] = 'Login successful'
            ret['err'] = 0
            ret['token'] = token.decode('UTF-8')
            return 'Login Done!'
        else:
            # Login Failed!
            return 'Login Failed!'
            ret['msg'] = 'Login Failed'
            ret['err'] = 1
    except Exception as exp:
        ret['msg'] = '%s' % exp
        ret['err'] = 1
        print(traceback.format_exc())
    return json.dumps(ret)


##############################################
#                                            #
#                 ADMIN LOGOUT               #
#                                            #
##############################################
@app.route('/admin/logout')
def clearsession1():
    session.clear()
    return 'Admin Logout!'



##############################################################################
#                                                                            #
#                               MAIN SERVER                                  #
#                                                                            #
##############################################################################
if __name__ == '__main__':
    # port = int(os.environ.get('PORT', 5000))
    # app.run(host='0.0.0.0', port=port, debug=True, threaded=True)
    app.run(debug=True)
