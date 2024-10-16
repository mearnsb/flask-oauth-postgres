# Python standard libraries
import json
import os
import sqlite3
import logging
from gunicorn.app.base import BaseApplication

#from dotenv import load_dotenv
#load_dotenv()
# Third-party libraries
from flask import Flask, redirect, request, url_for, jsonify, make_response, session
from flask_login import (LoginManager,current_user,login_required,login_user,logout_user, )
#import flask_login

from oauthlib.oauth2 import WebApplicationClient
import requests
from itsdangerous.url_safe import URLSafeSerializer
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
import psycopg2

# Internal imports
from db import init_db_command, close_db
from user import User

# Configuration
SK = os.environ.get('SECRET_KEY')

GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", None)
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", None)
GOOGLE_DISCOVERY_URL = ("https://accounts.google.com/.well-known/openid-configuration")

# Edit Dev Mode#WEB_APP_URL = os.environ.get("WEB_APP_URL", "http://127.0.0.1:8501")
WEB_APP_URL = os.environ.get("WEB_APP_URL", "https://login.bmearns.com")

HTTP="http://"
HTTPS="https://"

# Edit Dev
if "http://" in WEB_APP_URL:
    HTTPS="http://"
    
# Flask app setup
app = Flask(__name__)
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'
app.config['REMEMBER_COOKIE_HTTPONLY'] = False
app.config['REMEMBER_COOKIE_NAME'] = 'streamlit_remember' 
app.secret_key = SK or os.urandom(24)

# User session management setup
login_manager = LoginManager()
login_manager.init_app(app)

# Database setup
try:
    #init_db_command()
    print("got pool") 
except Exception as e: 
    print(str(e))
    print("error with postgres") 
    # Assume it's already been created
    pass

# OAuth 2 client setup
client = WebApplicationClient(GOOGLE_CLIENT_ID)

# Flask-Login helper to retrieve a user from our db
@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

@login_manager.request_loader
def load_user_from_request(request):

    auth_headers = request.headers.get('Authorization', '').split()
    if len(auth_headers) != 2:
        return None
    try:
        enc_str=auth_headers[1]
        s = URLSafeSerializer(SK)
        dec_str = s.loads(enc_str)
        user_id = dec_str['user_id']
        db_user = User.get(user_id)
        #user = User.by_email(data)
        #token = auth_headers[1]
        #data = jwt.decode(token, current_app.config['SECRET_KEY'])
        #user = User.by_email(data['sub'])
        if db_user:
            print(User.get(user_id).email_verified)
            if User.get(user_id).email_verified == 'True':
                print("active user")
                return db_user
            else:
                print("no active user")
                return None
            
    except Exception as e:
        return None
    except jwt.ExpiredSignatureError:
        return None
    except (jwt.InvalidTokenError, Exception) as e:
        return None
    return None

@app.route('/session')
def show_session():
    header = request.headers.get("X-Forwarded-For")
    address = request.headers.get("X-Forwarded-For", request.remote_addr)
    #flask_login.utils.encode_cookie(session['_user_id']))
    #token = current_user.get_auth_token()
    
    # An 'X-Forwarded-For' header includes a comma separated list of the
    # addresses, the first address being the actual remote address.
    if address is not None:    
        address = address.encode("utf-8").split(b",")[0].strip()
    user_agent = request.headers.get("User-Agent")
    
    response = make_response(str(session.items())) 
    s = URLSafeSerializer(SK)
    enc_str = s.dumps({'user_id' : current_user.id, 'name' :  current_user.name, 'email' : current_user.email}) #dec_str = s.loads(enc_str)
    response.set_cookie('x-session_id', enc_str)
    return response
     
@app.route("/")
def index():
    if current_user.is_authenticated:
        verified = "Not verified" 
        if current_user.email_verified == "True":
            verified = "Email Verfified"
        return (
            "<p>Hello, {}! You're logged in! Email: {}</p>"
            "<div><p>Google Profile Picture:</p>"
            '<img src="{}" alt="Google profile pic"></img></div>'
            '<p>Authentication Status: "{}" </p>'

            '<h2>Access</h2>'
            '<a class="button" href="https://login.bmearns.com/logout">logout</a>'
            
            '<h2>Apps</h2>'
            '<a class="button" href="https://login.bmearns.com">login.bmearns.com (Oauth)</a>'
            '<p></p>'
            '<a class="button" href="https://app.bmearns.com">app.bmearns.com (Personal Profile)</a>'
            '<p></p>'
            '<a class="button" href="https://chat.bmearns.com">chat.bmearns.com (Chat with Documentation)</a>'
            '<p></p>'
            '<a class="button" href="https://gitlit.bmearns.com">gitlit.bmearns.com (Fake Data Generator)</a>'
            '<p></p>'
            '<a class="button" href="https://sqlsaw.bmearns.com">sqlsaw.bmearns.com (Data Playground)</a>'
            '<p></p>'
            '<a class="button" href="https://duckdq.bmearns.com">duckdq.bmearns.com (LangGraph)</a>'

            # Edit Dev
            # '<h2>Dev</h2>'
            # '<a class="button" href="http://127.0.0.1:5001/logout">logout</a>'
            # '<p></p>'
            # '<a class="button" href="http://127.0.0.1:8501">app</a>'
        ).format(current_user.name, current_user.email, current_user.profile_pic, verified )
    else:
        return (
            '<h2>Access</h2>'
            '<a class="button" href="https://login.bmearns.com/login">Login</a>'
            
            '<h2>Apps</h2>'
            '<a class="button" href="https://login.bmearns.com">login.bmearns.com (Oauth)</a>'
            '<p></p>'
            '<a class="button" href="https://app.bmearns.com">app.bmearns.com (Personal Profile)</a>'
            '<p></p>'
            '<a class="button" href="https://chat.bmearns.com">chat.bmearns.com (Chat with Documentation)</a>'
            '<p></p>'
            '<a class="button" href="https://gitlit.bmearns.com">gitlit.bmearns.com (Fake Data Generator)</a>'
            '<p></p>'
            '<a class="button" href="https://sqlsaw.bmearns.com">sqlsaw.bmearns.com (Data Playground)</a>'
            '<p></p>'
            '<a class="button" href="https://duckdq.bmearns.com">duckdq.bmearns.com (LangGraph)</a>'
            
            # '<h2>Dev</h2>'
            # '<a class="button" href="http://127.0.0.1:5001/login">login</a>'
            # '<p></p>'
            # '<a class="button" href="http://127.0.0.1:8501">app</a>'
       )

def get_google_provider_cfg():
    return requests.get(GOOGLE_DISCOVERY_URL).json()

@app.route("/userinfo")
def userinfo():
    try:
        # print("userinfo:")
        # print("current_user: " + str(current_user.email))
        # print("current_user: " + str(current_user.is_authenticated))
        # print("current_user: " + str(current_user.email_verified))
        if current_user.is_authenticated == True and current_user.email_verified == 'True':
            return current_user.__dict__
    except Exception as e:
        print(str(e))
        return {}
    except jwt.ExpiredSignatureError:
        return {}
    except (jwt.InvalidTokenError, Exception) as e:
        return None
    return {}

@app.route("/login")
def login():
    # Find out what URL to hit for Google login
    google_provider_cfg = get_google_provider_cfg()
    authorization_endpoint = google_provider_cfg["authorization_endpoint"]

    # Use library to construct the request for Google login and provide
    print(request.base_url)
    print("base_url: " + request.base_url)
    print("base_url_replace: " + request.base_url.replace(HTTP, HTTPS))
    request_uri = client.prepare_request_uri(
        authorization_endpoint,
        redirect_uri= request.base_url.replace(HTTP, HTTPS) + "/callback", #"https://flask-oauth-uc.a.run.app/login/callback", #
        scope=["openid", "email", "profile"],
    )
    print(request.base_url)
    print(request.base_url.replace(HTTP, HTTPS))
    return redirect(request_uri)


@app.route("/login/callback")
def callback():
    # Get authorization code Google sent back to you
    code = request.args.get("code")

    # Find out what URL to hit to get tokens that allow you to ask for things on behalf of a user
    google_provider_cfg = get_google_provider_cfg()
    token_endpoint = google_provider_cfg["token_endpoint"]
    
    # Prepare and send a request to get tokens! Yay tokens!
    token_url, headers, body = client.prepare_token_request(
        token_endpoint,
        authorization_response=request.url,
        redirect_url=str(request.base_url).replace(HTTP, HTTPS),
        code=code
    )
    
    # print(request.url)
    # print(request.base_url)
    # print("base_url: " + str(request.base_url).replace(HTTP, HTTPS))
    # print(headers)
    # print(body)
    # print(token_url)
    
    token_response = requests.post(
        token_url,
        headers=headers,
        data=body,
        auth=(GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET),
    )
    
    # Parse the tokens!
    client.parse_request_body_response(json.dumps(token_response.json()))
    
    # from Google that gives you the user's profile information
    userinfo_endpoint = google_provider_cfg["userinfo_endpoint"]
    uri, headers, body = client.add_token(userinfo_endpoint)
    userinfo_response = requests.get(uri, headers=headers, data=body)
    
    #logging
    #print(headers)
    #print(body)
    #print(userinfo_endpoint)
    #print(json.dumps(token_response.json()))
    #print(userinfo_response.json())
    #print(json.dumps(userinfo_response.json()))
    
    # You want to make sure their email is verified.
    # The user authenticated with Google, authorized your
    # you've verified their email through Google!
    if userinfo_response.json().get("email_verified"):
        unique_id = userinfo_response.json()["sub"]
        users_email = userinfo_response.json()["email"]
        picture = userinfo_response.json()["picture"]
        users_name = userinfo_response.json()["given_name"]
        email_verified = userinfo_response.json()["email_verified"]
    else:
        return "User email not available or not verified by Google.", 400
    
    # Create a user in your db 
    user = User(id_=unique_id, name=users_name, email=users_email, profile_pic=picture, email_verified=1)

    # Doesn't exist? Add it to the database.
    if not User.get(unique_id):
        User.create(unique_id, users_name, users_email, picture, email_verified)

    # Begin user session by logging the user in
    login_user(user, remember=True)
    User.login(unique_id)
    print("BASE_URL: " + str(request.base_url))
    print("BASE_URL: " + str(request.base_url).replace(HTTP, HTTPS))
    print("WEB_APP_URL: " + str(WEB_APP_URL))
    
    # set cookie
    #response = make_response(redirect("https://flask-oauth-uc.a.run.app"))
    response = make_response(redirect("/?email="+users_email)) #WEB_APP_URL
    s = URLSafeSerializer(SK)
    enc_str = s.dumps({'user_id' : unique_id, 'name' :  users_name, 'email' : users_email})
    response.set_cookie('x-session_id', enc_str, domain="bmearns.com")
    response.set_cookie('x-session_id', enc_str, domain="127.0.0.1")
    
    # Send user back to homepage
    return response  #return redirect(url_for("index"))

def get_current_user():
    return current_user
    
@app.route("/logout")
@login_required
def logout():
    curr_user = get_current_user()
    print(curr_user.id)
    User.logout(curr_user.id)
    logout_user()
    try:
        response = make_response(redirect("/")) 
        response.set_cookie('x-session_id', '', expires=0, domain="bmearns.com")
        response.set_cookie('x-session_id', '', expires=0, domain="127.0.0.1")
        #response.set_cookie('x-session_id', '', expires=0, domain="flask-oauth-uc.a.run.app")
        #print("cookie_deleted") 
        
    except Exception as e:
        print(str(e))
    return response

#if __name__ == "__main__":
#    app.run(port=5000, debug=True)
#    #app.run(ssl_context="adhoc")

class StandaloneApplication(BaseApplication):
    def __init__(self, app, options=None):
        self.application = app
        self.options = options or {}
        super().__init__()

    def load_config(self):
        config = {
            key: value
            for key, value in self.options.items()
            if key in self.cfg.settings and value is not None
        }
        for key, value in config.items():
            self.cfg.set(key.lower(), value)

    def load(self):
        return self.application

# Do not remove the main function while updating the app.
if __name__ == "__main__":
    options = {"bind": "0.0.0.0:5001", "workers": 1, "loglevel": "info"}
    StandaloneApplication(app, options).run()