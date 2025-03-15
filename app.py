import uuid
import eventlet
eventlet.monkey_patch()

from datetime import datetime, timezone
import hashlib
from flask import Blueprint, Flask, request, jsonify, session, render_template,make_response,redirect,send_from_directory,url_for,abort, copy_current_request_context
from appwrite.services.databases import Databases
from flask_limiter.util import get_remote_address
from flask import Response
from flask_socketio import SocketIO, join_room, leave_room, rooms
from skipData import get_skip_data
from appwrite.services.account import Account
from collections import defaultdict
from appwrite.client import Client
from appwrite.services.users import Users
from appwrite.services.teams import Teams
from dateutil.relativedelta import relativedelta
from appwrite.exception import AppwriteException
from werkzeug.exceptions import HTTPException
from logging.handlers import RotatingFileHandler
from flask_compress import Compress
from flask_sitemap import Sitemap
from flask_limiter import Limiter
from appwrite.query import Query
from flask_caching import Cache
from collections import Counter
from datetime import timedelta
from dotenv import load_dotenv
from functools import wraps,lru_cache
from flask_cors import CORS
from appwrite.id import ID
from pytz import timezone as tz
from pytz import UTC as Fuck
import websockets
import traceback
import threading
import requests
import logging
import asyncio
import dotenv
import json
import html
import time as shitl
import math
import pytz
import base64
import os
import re
from urllib.parse import urlparse, urljoin
import redis
import logging
from nacl.public import PrivateKey, PublicKey, Box
import xml.etree.ElementTree as ET
from threading import Thread
from queue import Queue
import random

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False
ALLOWED_DOMAINS = {"https://kuudere.to"}
os.environ['no_proxy'] = 'localhost,127.0.0.1'
POINTS_LIKES = 25

tor_proxy = {
    "http": "socks5h://127.0.0.1:9050",
}

def get_user_agent():
    """Retrieve the User-Agent from the request headers."""
    return request.headers.get('User-Agent')

# Custom function to get the client's real IP behind a proxy
def get_real_ip():
    # Check the X-Forwarded-For header if it's behind a proxy
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    # X-Forwarded-For can contain multiple IPs, we take the first one
    return client_ip.split(',')[0]

load_dotenv()
app = Flask(__name__, static_folder='static')
app.secret_key = os.getenv('FLASK_SECRET_KEY')  # Set a secure secret key for session management
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,  # Prevent JavaScript access
    SESSION_COOKIE_SAMESITE='Lax'  # Restrict cross-site cookie usage
)
app.config['SESSION_PERMANENT'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=365) 
auth_bp = Blueprint("anilistauth", __name__, url_prefix="/anilist")

limiter = Limiter(
    get_real_ip,
    app=app,
    default_limits=["500 per hour"],
    storage_uri="memory://",
)

socketio = SocketIO(app,cors_allowed_origins="*",ping_interval=10,ping_timeout=20, async_mode='eventlet')
redis_client = redis.Redis(host='localhost', port=os.getenv('REDIS_PORT'),password=os.getenv('REDIS_PASS'), decode_responses=True)
connected_users = {}
room_counts = defaultdict(int)
lock = threading.Lock()
CORS(app)
Compress(app)
ext = Sitemap(app)
cache = Cache(app, config={'CACHE_TYPE': 'simple'})
def get_client(header=None,session_id=None, secret=None, jwt=None):
    client = Client()
    client.set_endpoint(os.getenv('PROJECT_ENDPOINT'))
    client.set_project(os.getenv('PROJECT_ID') )

    if header:
        client.add_header('User-Agent',header) 

    if session_id:
        client.set_session(session_id)
    elif secret:
        client.set_key(secret)
    elif jwt:
        client.set_jwt(jwt)
    
    return client

# Custom log format similar to your example
log_format = '%(remote_addr)s - - [%(asctime)s] "%(request_line)s" %(status_code)s -'

# Set up the logger
def setup_logging():
    # Create a rotating file handler to manage log file size
    handler = RotatingFileHandler('appAccess.log', maxBytes=10000, backupCount=3)
    handler.setLevel(logging.INFO)
    
    # Create a custom formatter with the log format
    formatter = logging.Formatter(log_format, datefmt='%d/%b/%Y %H:%M:%S')
    handler.setFormatter(formatter)
    
    # Add the handler to the Flask app's logger
    app.logger.addHandler(handler)

def get_acc_info(acc):

    secret =  os.getenv('SECRET') 

    try:
        client = get_client(None,None,secret)
        databases = Databases(client)
        
        user = databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                document_id=acc.get('$id'),
                queries=[Query.select(['pfp'])]
            )
        
        pfp = user.get('pfp')
    except Exception as e:
        pfp = None
    userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email"),
                "joined":datetime.fromisoformat(acc.get('$createdAt').replace("Z", "+00:00")).strftime("%Y-%m-%d"),
                "verified":acc.get('status'),
                "pfp":pfp,
            }
    
    return userInfo
def get_user_info(key=None,secret=None):
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        try:
            

            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(None,key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)
        except Exception as e:
            userInfo = None  
    else:
        userInfo = None   

    return userInfo

def verify_api_request(request):
    base_url = request.referrer or ""  # Ensure base_url is always a string

    # Extract only the scheme + netloc (ignoring path & query parameters)
    parsed_referrer = urlparse(base_url)
    referrer_domain = f"{parsed_referrer.scheme}://{parsed_referrer.netloc}"

    # Check if JSON request but missing referrer (possible direct request)
    if request.is_json and not base_url:
        data = request.get_json(silent=True) or {}

        key = data.get('key')
        secret = data.get('secret')

        if not key or not secret:
            print("Missing key or secret in JSON request")
            return True, None, None, None, None
        
        secret = decrypt(secret)
        key = decrypt(key)

        try:
            client = get_client(None,key, None)
            account = Account(client)

            acc = account.get()
            if not acc:
                print("Invalid account")
                return True, None, secret, None, None

            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email"),
            }
            print("Authenticated successfully")
            client = get_client(None,None, secret)
            users = Users(client)

            result = users.get(user_id=acc.get("$id"))
            return True, key, secret, userInfo, acc  # Authentication successful
        
        except Exception as e:
            print(f"Authentication error: {e}")
            return True, None, None, None, None

    # Check if request referrer (only domain) is allowed
    elif referrer_domain not in ALLOWED_DOMAINS and any(sub in request.path for sub in ['/api', '/save','/watch-api','/anime/comment/']):
        print(f"Unauthorized referrer '{referrer_domain}' trying to access API")
        return True, None, None, None, None

    return False, None, None, None, None  # Valid request, proceed

def encrypt(data):
    # Get keys from the environment variables
        private_key_hex = os.getenv('PRIVATE_KEY')
        public_key_hex = os.getenv('PUBLIC_KEY')

        # Convert the hex strings back to bytes
        private_key_bytes = bytes.fromhex(private_key_hex)
        public_key_bytes = bytes.fromhex(public_key_hex)

        # Deserialize the keys using PyNaCl
        private_key = PrivateKey(private_key_bytes)
        public_key = PublicKey(public_key_bytes)

        # Create a Box (this is what you use for encryption and decryption)
        box = Box(private_key, public_key)

        message = data.encode('utf-8')

        # Encrypt the message
        encrypted = box.encrypt(message)

        # Base64 encode the encrypted message for easy storage
        encrypted_base64 = base64.b64encode(encrypted).decode()

        return encrypted_base64

def decrypt(data):

    # Get keys from the environment variables
    private_key_hex = os.getenv('PRIVATE_KEY')
    public_key_hex = os.getenv('PUBLIC_KEY')

    # Convert the hex strings back to bytes
    private_key_bytes = bytes.fromhex(private_key_hex)
    public_key_bytes = bytes.fromhex(public_key_hex)

    # Deserialize the keys using PyNaCl
    private_key = PrivateKey(private_key_bytes)
    public_key = PublicKey(public_key_bytes)

    # Create a Box (this is what you use for encryption and decryption)
    box = Box(private_key, public_key)

    encrypted_base64 = data

    # Base64 decode the encrypted message
    encrypted_bytes = base64.b64decode(encrypted_base64)

    # Decrypt the message using the private key
    decrypted = box.decrypt(encrypted_bytes)

    return decrypted.decode()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated by using Appwrite's session service
        try:
            # Get session data
            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            if not acc:
                return redirect('/home')  # Redirect to login if not authenticated
        except Exception as e:
            print(f"Error: {e}")
            return redirect('/home')  # Redirect to login in case of error

        return f(*args, **kwargs)
    return decorated_function

@lru_cache(maxsize=1000)
def get_file_hash(filepath):
    """
    Calculate MD5 hash of a file for versioning.
    Includes both file content and modification time.
    """
    if not os.path.exists(filepath):
        return None

    with open(filepath, 'rb') as f:
        content = f.read()

    # Append modification time to ensure unique hash on file updates
    mtime = str(os.path.getmtime(filepath))
    content += mtime.encode()

    return hashlib.md5(content).hexdigest()[:8]

def clear_file_hash_cache():
    """Clear the file hash cache"""
    get_file_hash.cache_clear()

def versioned_url_for(endpoint, **values):
    """
    Add a version hash to static file URLs for cache busting.
    """
    if endpoint == 'static':
        filename = values.get('filename', None)
        if filename:
            filepath = os.path.join(app.static_folder, filename)
            file_hash = get_file_hash(filepath)
            if file_hash:
                values['v'] = file_hash
    return url_for(endpoint, **values)

@app.after_request
def add_cache_control_headers(response):
        # Log the request details: IP, request method, URL, status code
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]

    scheme = request.headers.get('X-Forwarded-Proto', request.scheme)
    
    # Use request.host to get the original host
    host = request.headers.get('X-Forwarded-Host', request.host)
    
    # Reconstruct the original URL
    original_url = f"{scheme}://{host}{request.path}"
    secret = os.getenv('SECRET')  # Default value
    print("Key is missing or empty, setting default secret.")

        # Initialize client and database
    client = get_client(None,None, secret)
    databases = Databases(client)
    
    vid = ID.unique()

    """
    Add Cache-Control and ETag headers for static files.
    """
    if request.path.startswith('/static/'):
        # Check if the request is for a static file
        is_static_file = request.path.endswith(('.css', '.js', '.png', '.jpg', '.jpeg', '.gif', '.svg', '.ico'))
        
        if is_static_file:
            # Set cache duration based on file type
            max_age = int(timedelta(days=365).total_seconds())
            response.headers['Cache-Control'] = f'public, max-age={max_age}'

            # Generate and set ETag
            try:
                filepath = os.path.join(app.static_folder, request.path.replace('/static/', '', 1))
                file_hash = get_file_hash(filepath)
                if file_hash:
                    response.set_etag(file_hash)
            except (OSError, IOError):
                pass
    
    
    excluded_routes = ['/api/', '/save/progress','/proxy/','/static/','/anilist/','/callback/']
    if any(request.path.startswith(route) for route in excluded_routes):
        # Skip logging for excluded routes
        return response
    
    view = databases.create_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('LOG'),
        document_id=vid,
        data={
            "logId": vid,
            "requestIp":client_ip,
            "path":request.path, 
            "type":request.method,
            "code": response.status_code,
        }
    )
    app.logger.info(
        'Request: %s %s %s', 
        request.method, 
        request.full_path, 
        response.status_code
    )

    return response

# Clear cache periodically (optional)
@app.before_request
def clear_expired_cache():
    """
    Clear the file hash cache periodically or under specific conditions.
    """
    # Example: Clear cache every 1 hour
    if datetime.now().minute == 0:
        get_file_hash.cache_clear()
# Override Flask's url_for with our versioned version
app.jinja_env.globals['url_for'] = versioned_url_for

# API to get all room counts
@app.route('/rooms/counts', methods=['GET'])
def get_room_counts():
    with lock:
        return jsonify(room_counts)

# Background WebSocket client to listen to Appwrite WebSocket
async def websocket_listener(ss=None):
    url = f"ws://localhost/v1/realtime?project={os.getenv('PROJECT_ID')}&channels[]=documents,'user':{ss}"

    while True:  # Reconnection loop
        try:
            async with websockets.connect(url, ping_interval=30) as ws:
                print("Connected to Appwrite Realtime WebSocket!")
                async for message in ws:
                    print(f"Raw Message: {message}")
                    parsed_message = process_message(message)
                    if parsed_message:
                        doc_id = parsed_message.get("doc_id")
                        chat_id = parsed_message.get("chatId")
                        if doc_id:
                            socketio.emit('new_data', parsed_message, to=doc_id)
                        if chat_id:
                            socketio.emit('new_data', parsed_message, to=chat_id)
        except (websockets.exceptions.ConnectionClosedError, ConnectionResetError) as e:
            print(f"WebSocket connection closed: {e}")
            print("Attempting to reconnect...")
            await asyncio.sleep(5)
        except Exception as e:
            print(f"Unexpected error: {e}")
            await asyncio.sleep(5)

# Process incoming WebSocket message
def process_message(message):
    try:
        data = json.loads(message)
        if data.get("type") == "event" and "payload" in data.get("data", {}):
            payload = data["data"]["payload"]
            return {
                "event_type": data["data"].get("events"),
                "timestamp": data["data"].get("timestamp"),
                "doc_id": payload.get("$id"),
                "isPublic": payload.get("isPublic"),
                "startTime": payload.get("startTime"),
                "isPaused": payload.get("isPaused"),
                "lastAction": payload.get("lastAction"),
                "lastActionId": payload.get("lastActionId"),
                "chatId": payload.get("chatId"),
                "message": payload.get("message"),
                "removed": payload.get("removed"),
                "time": payload.get("time"),
            }
    except Exception as e:
        print(f"Error processing message: {e}")
    return None

# SocketIO route for joining a room
@socketio.on('join')
def on_join(data):
    room = data.get('doc_id') or data.get('chatId') or data.get('other_id')
    if room:
        join_room(room)
        update_room_count(room)
        print(f"User joined room: {room}")
    
@socketio.on('connect')
def handle_connect():
    user_id = request.args.get("user_id")
    if user_id:
        connected_users[user_id] = request.sid
        logger.info(f"✅ User {user_id} connected with session ID {request.sid}")
        # Send any pending notifications
        pending_notifications = redis_client.lrange(f"pending_notifications:{user_id}", 0, -1)
        for notification in pending_notifications:
            socketio.emit("new_notification", {"message": notification}, room=request.sid)
        redis_client.delete(f"pending_notifications:{user_id}")
def redis_listener():
    pubsub = redis_client.pubsub()
    pubsub.subscribe("notifications")
    logger.info("🎧 Started Redis listener")

    for message in pubsub.listen():
        try:
            if message["type"] == "message":
                data = json.loads(message["data"])
                user_ids = data.get("user_ids", [])
                notification = data.get("message")
                title = data.get("title")
                image = data.get("image_url")
                
                if not notification:
                    continue

                logger.info(f"📨 Received notification: {notification} for users: {user_ids}")

                # Send to connected users or store for later
                for user_id in user_ids:
                    if user_id in connected_users:
                        socketio.emit(
                            "new_notification",
                            {
                                "message": notification,
                                "title":title,
                                "image_url":image,
                             },
                            room=connected_users[user_id]
                        )
                        logger.info(f"✉️ Sent notification to user {user_id}")
                    else:
                        # Store notification for later delivery
                        redis_client.rpush(f"pending_notifications:{user_id}", notification)
                        logger.info(f"📝 Stored pending notification for user {user_id}")

        except Exception as e:
            logger.error(f"❌ Error processing message: {e}")
# Start the background task
socketio.start_background_task(redis_listener)

@socketio.on('disconnect')
def on_disconnect():
    for room in rooms(sid=request.sid):
        if room != request.sid:  # Exclude the personal room
            leave_room(room)
            update_room_count(room)

# Update the count for a specific room
def update_room_count(room):
    with lock:
        room_clients = socketio.server.manager.rooms.get('/', {}).get(room, set())
        count = len(room_clients)

        if count == 0:
            if room in room_counts:
                del room_counts[room]
            print(f"Room {room} destroyed (no listeners).")
        else:
            room_counts[room] = count

    # Emit updated count for the specific room
    socketio.emit('update_counts', {'room': room, 'count': count}, to=room)

# Emit count for a specific room upon request
@socketio.on('get_current_room_count')
def send_current_room_count(data):
    room = data.get('room')
    if room:
        with lock:
            count = room_counts.get(room, 0)
        socketio.emit('current_room_count', {'room': room, 'count': count}, to=request.sid)

# Emit all counts periodically (optional)
@socketio.on('get_all_counts')
def send_all_counts():
    with lock:
        counts = dict(room_counts)
    socketio.emit('all_room_counts', counts)

@app.route('/register', methods=['POST'])
@limiter.limit("5 per minute")  # Allow 5 requests per minute per IP
def register():
    data = request.json
    name = data.get('username')
    email = data.get('email')
    password = data.get('password')
    secret = data.get('secret')
    user_agent = get_user_agent()

    if not name and email and password:
        return jsonify({'success': False, 'message': 'Complete the form'}),400


    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
    print(secret)
    
    try:
        client = get_client(user_agent,None,secret)
        databases = Databases(client)
        user_check = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Users'),
            queries=[
                Query.equal("username",name),
                Query.select(['username'])
            ]
        )

        if user_check['total'] > 0:
            return jsonify({'success': False, 'message': "Username already exists"}),400
        
        account = Account(client)
        result = account.create(ID.unique(), email=email, password=password, name=name)

        session_data = account.create_email_password_session(email=email, password=password)

        client = get_client(user_agent,session_data['secret'],None)
        databases = Databases(client)

        user = f"user:{session_data['userId']}",

        result = databases.create_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Users'),
            document_id = session_data['userId'],
            data = {
                'userId': session_data['userId'],
                'username': name,
                'email': email,
                'online':False,
                'banned': False,
            },
            permissions = [       
                f"update(\"user:{session_data['userId']}\")"     
            ] # optional
        )
                # Store both session ID and secret
        session.permanent = True
        session['session_id'] = session_data['$id']  # Store the session ID for logout
        session['session_secret'] = session_data['secret']  # Store the secret for authentication
        session_info = {
                "userId":session_data['userId'],
                "session":session_data['secret'],
                "expire":session_data['expire']
            }
        data = {
            "defaultComments": 'false',
            "defaultLang": 'japanese',
            "autoNext": True,
            "autoPlay": False,
            "autoSkipIntro": False,
            "autoSkipOutro": False,
        }
        session_info = {
            "userId":session_data['userId'],
            "session":encrypt(session_data['secret']),
            "expire":session_data['expire'],
            "sessionId":session_data['$id'],
        }
        
        return jsonify({
            'success': True, 
            'message': 'Registerd in successfully',
            'pref': data,
            "session":session_info
        }),200
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}),400

@app.route('/login', methods=['POST'])
@limiter.limit("3 per minute") 
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    secret = data.get('secret')
    print(secret)

    user_agent = get_user_agent()
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
    print(secret)
    
    try:
        client = get_client(user_agent,None,secret)
        account = Account(client)
        session_data = account.create_email_password_session(email=email, password=password)
        
        # Store both session ID and secret
        session.clear()
        session.permanent = True
        session['session_id'] = session_data['$id']  # Store the session ID for logout
        session['session_secret'] = session_data['secret']  # Store the secret for authentication

        client = get_client(None,session_data['secret'], None)
        databases = Databases(client)

        try:
            settings_response = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('SETTINGS'),
                queries=[
                    Query.order_desc("$updatedAt"),
                    Query.equal("userId", session_data['userId']),
                ]
            )

            print(f"lol{settings_response}")

            # Check if any documents exist and extract data
            if settings_response['total'] > 0 and settings_response['documents']:
                settings_data = settings_response['documents'][0]  # Safely get the first document
                data = {
                    "defaultComments": (
                        'true' if settings_data.get('defaultComments') is True 
                        else 'false' if settings_data.get('defaultComments') is False 
                        else settings_data.get('defaultComments')
                    ),
                    "defaultLang": (
                        'japanese' if settings_data.get('defaultLang') == True
                        else 'english' if settings_data.get('defaultLang') == False
                        else 'japanese'  # Default to Japanese if invalid or missing
                    ),
                    "autoNext": settings_data.get('autoNext', True),
                    "autoPlay": settings_data.get('autoPlay', False),
                    "autoSkipIntro": settings_data.get('skipIntro', False),
                    "autoSkipOutro": settings_data.get('skipOutro', False),
                }
            else:
                # Default values if no settings exist
                data = {
                    "defaultComments": 'false',
                    "defaultLang": 'japanese',
                    "autoNext": True,
                    "autoPlay": False,
                    "autoSkipIntro": False,
                    "autoSkipOutro": False,
                }
            session_info = {
                "userId":session_data['userId'],
                "session":encrypt(session_data['secret']),
                "expire":session_data['expire'],
                "sessionId":session_data['$id'],
            }
        except AppwriteException as e:
            print(e)
        
        return jsonify({
            'success': True, 
            'message': 'Logged in successfully',
            'pref': data,
            "session":session_info
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Invalid email or password'}),401
    
@app.route('/logout', methods=['POST'])
def logout():
    sessionId = None
    
    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
            else:
                sessionId = request.json.get('sessionId')
                if not sessionId:
                    return jsonify({'success': False, 'message': "Unauthorized"}), 401
            
    isKey = bool(secret)
    if isKey:
        secret = secret
    else:
        secret = os.getenv('SECRET')  # Default value

    if bool(key):
        key = key
    else:
        key = session['session_secret']
    
    if not bool(sessionId):
        sessionId = session['session_id']
    
    try:
        client = get_client(None,key,secret)
        account = Account(client)
        session_data = account.delete_session(
           session_id= sessionId
        )

        if not  isApi:
            session.clear()
        
        return jsonify({
            'success': True, 
            'message': 'Logged Out successfully',
        })
    except Exception as e:
        return jsonify({'success': False, 'message': e}),500 
    
@app.route('/user', methods=['POST'])
def get_user():
    referer = request.headers.get('Referer')  # Referer header
    origin = request.headers.get('Origin')    # Origin header
    
    # Prioritize Origin if Referer is not available
    domain = referer or origin
    if domain:
        domain = domain.split('/')[2]
    print(f"fuucl{domain}")
    data = request.json
    email = data.get('email')
    password = data.get('password')
    secret = data.get('secret')
    key = decrypt(data.get('key'))
    print(data)
    
    try:
        client = get_client(None,key,None)
        account = Account(client)
        result = account.get()
        dat = result['$id']

        databases = Databases(client)

        result = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Users'),
            document_id = dat,
            queries=[
                Query.select(['username'])
            ]
        )
        print(result)
        return jsonify({'success': True, 'userId': result})
    except Exception as e:
        return jsonify({'success': False, 'message': "str(e)"}), 500
    
def recreate_url(base_url, url_code):
    """Recreate the full shortened URL from the base URL and code."""
    return f"{base_url.rstrip('/')}/{url_code.lstrip('/')}"   

@app.route('/home', methods=['GET','POST'])
def load_home():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401

    encoded = request.args.get('spc')
    isKey = bool(secret)
    ctotal = None
    Surl = None
    base_url = "https://tinyurl.com"
    if encoded:
        Surl = recreate_url(base_url, encoded)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        try:
            

            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(None,key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)
            
        except Exception as e:
            userInfo = None  
    else:
        userInfo = None     
    
    try:
        client = get_client(None,None,secret)
        databases = Databases(client)

        Notice = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Notices'),
            queries=[
                Query.order_desc('$createdAt'),
                Query.equal("Type","web"),
                Query.limit(1)
            ]
        )

        nData = Notice['documents'][0]

        if userInfo:

            search = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('CONTINUE_WATCHING'),
                    queries=[
                        Query.equal("userId",acc.get("$id")),
                        Query.order_desc('$updatedAt'),
                        Query.select(['continueId']),
                        Query.limit(1),
                    ]
                )
            
            ctotal = search['total']
        
        result = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime'),
            queries = [
                Query.equal("public",True),
                Query.or_queries([Query.greater_than_equal("subbed", 1), Query.greater_than_equal("dubbed", 1)]),
                Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms", "type", "year", "description","subbed","dubbed"]),
                Query.order_desc("lastUpdated"),
                Query.limit(12)
            ] # optional
        )

        topAiring = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime'),
            queries = [
                Query.equal("public",True),
                Query.equal("year",[2025,2024]),
                Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms", "type", "year", "description","subbed","dubbed"]),
                Query.equal("status","RELEASING"),
                Query.order_desc("lastUpdated"),
                Query.limit(12)
            ] # optional
        )


        topUpcoming = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime'),
            queries = [
                Query.equal("public",True),
                Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms", "type", "year", "description","subbed","dubbed"]),
                Query.equal("status","NOT_YET_RELEASED"),
                Query.order_asc("lastUpdated"),
                Query.limit(12)
            ] # optional
        )

        # Fetch the latest episodes
        latest_eps = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime_Episodes'),
            queries = [
                Query.select("animeId"),
                Query.not_equal('animeId','Digimon-Adventure-2020'),
                Query.not_equal('animeId','Kaleido-Star-2003'),
                Query.not_equal('animeId','Sekai-de-Ichiban-Tsuyoku-Naritai-2013'),
                Query.not_equal('animeId','Phi-Brain-Kami-no-Puzzle-2011'),
                Query.not_equal('animeId','Utawarerumono-2006'),
                Query.not_equal('animeId','Angel-Beats-2010'),
                Query.not_equal('animeId','Jewelpet-Sunshine-2011'),
                Query.not_equal('animeId','Duel-Masters-2002'),
                Query.not_equal('animeId','Digimon-Frontier-2002'),
                Query.not_equal('animeId','Kekkaishi-2006'),
                Query.order_desc("aired"),
                Query.limit(50),
            ] # optional
        )

        # Extract unique anime IDs
        documents_eps = latest_eps.get('documents', [])
        anime_ids = list({anime.get("animeId") for anime in documents_eps if anime.get("animeId")})
        documents = result.get('documents', [])
        processed_ids = set()  # Set to track processed anime IDs
        filtered_documents = []
        filtered_documents_eps = []
        documents_top = topAiring.get('documents', [])
        filtered_documents_top = []
        documents_top_upcoming = topUpcoming.get('documents', [])
        filtered_documents_top_upcoming = []
        documents_eps = latest_eps.get('documents', [])
        filtered_documents_eps = []

        latest_ep_data = documents_eps

        for anime in latest_ep_data:
            required_id = anime.get("animeId")
            anime_id = required_id

            # Skip if this anime ID has already been processed
            if anime_id in processed_ids:
                continue

            processed_ids.add(anime_id)

            anii = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('Anime'),
                queries=[
                    Query.not_equal('english','Sword of Coming'),
                    Query.equal("animeId",required_id),
                    Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms", "type", "year", "description","subbed","dubbed"])
                ]
            )

            if not anii['total'] > 0:
                continue

            anii=anii['documents'][0]

            img = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('ANIME_IMGS'),
                document_id=anii.get('mainId'),
                queries=[
                    Query.select(['cover'])
                ]
            )

            ass = anii.get('mainId')

            filtered_documents_eps.append({
                "id": anii.get("mainId"),
                "english": anii.get("english") if anii.get('english') is not None else anii.get("romaji"),
                "romaji": anii.get("romaji"),
                "native": anii.get("native"),
                "ageRating": anii.get("ageRating"),
                "malScore": anii.get("malScore"),
                "averageScore": anii.get("averageScore"),
                "duration": anii.get("duration"),
                "genres": anii.get("genres"),
                "cover": img.get("cover") ,
                "season": anii.get("season"),
                "startDate": datetime.fromisoformat(anii.get("startDate").replace("Z", "+00:00")).strftime("%b %d, %Y") if anii.get("startDate") else None,
                "status": anii.get("status"),
                "synonyms": anii.get("synonyms"),
                "type": anii.get("type"),
                "year": anii.get("year"),
                "epCount": anii.get("subbed"),
                "subbedCount": anii.get("subbed"),
                "dubbedCount": anii.get("dubbed"),
                "description": anii.get("description"),
                "url":f'/watch/{anii.get("mainId")}?ep=latest',
            })

            if len(filtered_documents_eps) >= 12:
                break

                
        for doc in documents:


            img = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('ANIME_IMGS'),
                document_id=doc.get("mainId"),
                queries=[
                    Query.select(['cover'])
                ]
            )


            filtered_documents.append({
                "id": doc.get("mainId"),
                "english": doc.get("english") if doc.get('english') is not None else doc.get("romaji"),
                "romaji": doc.get("romaji"),
                "native": doc.get("native"),
                "ageRating": doc.get("ageRating"),
                "malScore": doc.get("malScore"),
                "averageScore": doc.get("averageScore"),
                "duration": doc.get("duration"),
                "genres": doc.get("genres"),
                "cover": img.get("cover"),
                "season": doc.get("season"),
                "startDate": datetime.fromisoformat(doc.get("startDate").replace("Z", "+00:00")).strftime("%b %d, %Y") if doc.get("startDate") else None,
                "status": doc.get("status"),
                "synonyms": doc.get("synonyms"),
                "type": doc.get("type"),
                "year": doc.get("year"),
                "epCount": doc.get("subbed"),
                "subbedCount": doc.get("subbed"),
                "dubbedCount": doc.get("dubbed"),
                "description": doc.get("description"),
            })

        for air in documents_top:

            img = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('ANIME_IMGS'),
                document_id=air.get("mainId"),
                queries=[
                    Query.select(['cover','banner'])
                ]
            )

            if not img.get('banner'):
                continue


            new_url = img.get('cover').replace("medium", "large")

            filtered_documents_top.append({
                "id": air.get("mainId"),
                "english": air.get("english") if air.get('english') is not None else air.get("romaji"),
                "romaji": air.get("romaji"),
                "native": air.get("native"),
                "ageRating": air.get("ageRating"),
                "malScore": air.get("malScore"),
                "averageScore": air.get("averageScore"),
                "duration": air.get("duration"),
                "genres": air.get("genres"),
                "cover":new_url,
                "banner": img.get("banner") or new_url,
                "season": air.get("season"),
                "startDate": datetime.fromisoformat(air.get("startDate").replace("Z", "+00:00")).strftime("%b %d, %Y") if air.get("startDate") else None,
                "status": air.get("status"),
                "synonyms": air.get("synonyms"),
                "type": air.get("type"),
                "year": air.get("year"),
                "epCount": air.get("subbed"),
                "subbedCount": air.get("subbed"),
                "dubbedCount": air.get("dubbed"),
                "description": air.get("description"),
            })


        for upcoming in documents_top_upcoming:

            img = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('ANIME_IMGS'),
                document_id=upcoming.get("mainId"),
                queries=[
                    Query.select(['cover','banner'])
                ]
            )

            new_url = img.get('cover').replace("medium", "large")

            filtered_documents_top_upcoming.append({
                "id": upcoming.get("mainId"),
                "english": upcoming.get("english") if upcoming.get('english') is not None else upcoming.get("romaji"),
                "romaji": upcoming.get("romaji"),
                "native": upcoming.get("native"),
                "ageRating": upcoming.get("ageRating"),
                "malScore": upcoming.get("malScore"),
                "averageScore": upcoming.get("averageScore"),
                "duration": upcoming.get("duration"),
                "genres": upcoming.get("genres"),
                "cover":new_url,
                "banner": img.get("banner"),
                "season": upcoming.get("season"),
                "startDate": datetime.fromisoformat(upcoming.get("startDate").replace("Z", "+00:00")).strftime("%b %d, %Y") if upcoming.get("startDate") else None,
                "status": upcoming.get("status"),
                "synonyms": upcoming.get("synonyms"),
                "type": upcoming.get("type"),
                "year": upcoming.get("year"),
                "epCount": upcoming.get("subbed"),
                "subbedCount": upcoming.get("subbed"),
                "dubbedCount": upcoming.get("dubbed"),
                "description": upcoming.get("description"),
            })      

        data = {
            "lastUpdated": filtered_documents,
            "latestEps": filtered_documents_eps,
            "topAired": filtered_documents_top,
            "topUpcoming":filtered_documents_top_upcoming,
            "userInfo": userInfo,
            "ctotal": ctotal,
        }    
        
        response = make_response(json.dumps(data, indent=4, sort_keys=False))
        response.headers["Content-Type"] = "application/json"

        if isKey:
            return response
        else:
            return render_template('index.html', last_updated=filtered_documents,latest_eps = filtered_documents_eps, topAiring = filtered_documents_top,topUpcoming=filtered_documents_top_upcoming,userInfo=userInfo,ctotal=ctotal,Surl=Surl,nData=nData)
    except Exception as e:
         return jsonify({'success': False, 'message': str(e)}), 500 
        
@app.route('/search',methods=['POST','GET'])
def filter_results():
    print(request)
    # Get query parameters
    season = request.args.get('season')
    language = request.args.get('language')
    sort = request.args.get('sort', 'default')
    genres = request.args.get('genres')
    year = request.args.get('year', type=int)
    type = request.args.get('type')
    score = request.args.get('score')
    keyword = request.args.get('keyword')
    page = request.args.get('page', default=1, type=int)
    isPage = bool(page)
    results_per_page = 18

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
        
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        try:
            

            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(None,key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None  
    else:
        userInfo = None     

    try:
        # Validate secret 
        client = get_client(None,None, secret)
        databases = Databases(client)

        try: 
            if keyword:
                databases.create_document(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('SEARCH_DATA'),
                    document_id=ID.unique(),
                    data={
                        "sid": ID.unique(),
                        "Keyword": keyword,
                        "user": acc.get('id') if userInfo else None,
                        "Genres": genres.split(',') if genres else []
                    }
                )
        except Exception as e:
            print(e)


        # Build base query list
        # Base query
        base_query_list = [Query.equal("public", True)]

        # Search strategies for keyword
        def get_keyword_search_queries(keyword):
            return [
                Query.or_queries([Query.search("english", keyword), Query.search("romaji", keyword),Query.search("native", keyword),Query.contains("synonyms", keyword)]),
            ]

        # Add filters
        if season and season != "All":
            base_query_list.append(Query.equal("season", season))

        if genres and genres != "All":
            genre_list = genres.split(',')  # Split genres into a list
            for genre in genre_list:
                base_query_list.append(Query.contains("genres", genre))

        if year and year != "All":
            year = int(year)
            base_query_list.append(Query.equal("year", year))

        if language and language == "Japanese":
            base_query_list.append(Query.not_equal("subbed", 0))

        if language and language == "English":
            base_query_list.append(Query.not_equal("dubbed", 0))

        if type and type != "All":
            base_query_list.append(Query.equal("type", type))

        if sort and sort == "default":
            base_query_list.append(Query.order_desc("startDate"))
        elif sort and sort == "Last Updated":
            base_query_list.append(Query.order_desc("lastUpdated"))    

        if score and score != "All":
            base_query_list.append(Query.greater_than_equal("averageScore", float(score)))

        if isPage:
            offset = (page - 1) * results_per_page
            base_query_list.append(Query.offset(offset))
        else:
            base_query_list.append(Query.offset(0))

        if True:
            base_query_list.append(Query.not_equal("status","NOT_YET_RELEASED"))      

        if True:
            base_query_list.append(Query.limit(18))
            base_query_list.append(Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration","studios", "genres", "season", "startDate", "status", "synonyms", "type", "year","subbed","dubbed","description"]))
        # Try different search strategies until results are found
        result = None
        for keyword_query in get_keyword_search_queries(keyword):
            # Combine base queries with the current keyword strategy
            if keyword:
                query_list = base_query_list + [keyword_query]
            else:
               query_list = base_query_list     
            
            # Perform database query
            try:
                result = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=query_list
                )
                
                # Break if results found
                if result['total'] > 0:
                    break
            except Exception as e:
                    print(f"Error occurred during query: {e}")    
    except:
        if isKey:
            return jsonify({
                "total": 0,
                "documents": []
            })
        else:
            return render_template('search.html',userInfo=userInfo)
              

    # If no results found after all strategies
    if not result:
        if isKey:
            return jsonify({
                "total": 0,
                "documents": []
            })
        else:
            return render_template('search.html',userInfo=userInfo)

    # Process documents
    documents = result.get('documents', [])
    filtered_documents = []
    
    for doc in documents:

        img = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('ANIME_IMGS'),
            document_id=doc.get('mainId'),
            queries=[
                Query.select(['cover'])
            ]
        )

            
    # Filter document
        filtered_document = {
            "id":doc.get("mainId"),
            "english": doc.get("english") if doc.get('english') is not None else doc.get("romaji"),
            "romaji": doc.get("romaji"),
            "native": doc.get("native"),
            "ageRating": doc.get("ageRating"),
            "malScore": doc.get("malScore"),
            "averageScore": doc.get("averageScore"),
            "duration": doc.get("duration"),
            "genres": doc.get("genres"),
            "cover":img.get("cover") or "/static/placeholder.svg",
            "season": doc.get("season"),
            "startDate": doc.get("startDate"),
            "status": doc.get("status"),
            "synonyms": doc.get("synonyms"),
            "type": doc.get("type"),
            "year": doc.get("year"),
            "epCount": doc.get("subbed"),
            "subbedCount": doc.get("subbed"),
            "dubbedCount": doc.get("dubbed"),
            "description": doc.get("description"),
        }
        filtered_documents.append(filtered_document)
    # Sorting logic
    if sort == 'score':
        filtered_documents.sort(key=lambda x: x.get('averageScore', 0), reverse=True)
    elif sort == 'year':
        filtered_documents.sort(key=lambda x: x.get('year', 0), reverse=True)
    elif sort == 'episodes':
        filtered_documents.sort(key=lambda x: x.get('epCount', 0), reverse=True)

    # Prepare response
    data = {
        "total": len(filtered_documents),
        "data": filtered_documents,
        "success": True,
        "total_pages": math.ceil(result['total'] / results_per_page)
    }

    response = make_response(json.dumps(data, indent=4, sort_keys=False))
    response.headers["Content-Type"] = "application/json"

    if isKey:
        return response
    else:
        return render_template("search.html",result=filtered_documents,total=result['total'],userInfo=userInfo,page=page,results_per_page=results_per_page)


@app.route('/upcoming',methods=['POST','GET'])
def upcoming():
    page = request.args.get('page', default=1, type=int)
    isPage = bool(page)
    results_per_page = 18

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
        
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        try:
            

            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(None,key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None  
    else:
        userInfo = None     

    try:
        # Validate secret 
        client = get_client(None,None, secret)
        databases = Databases(client)


        # Build base query list
        # Base query
        base_query_list = [Query.equal("public", True)]


        if isPage:
            offset = (page - 1) * results_per_page
            base_query_list.append(Query.offset(offset))
        else:
            base_query_list.append(Query.offset(0))

        if True:
            base_query_list.append(Query.equal("status","NOT_YET_RELEASED"))      

        if True:
            base_query_list.append(Query.limit(18))
            base_query_list.append(Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration","studios", "genres", "season", "startDate", "status", "synonyms", "type", "year","subbed","dubbed","description"]))
        # Try different search strategies until results are found
        result = None
        if True:
            # Combine base queries with the current keyword strategy

            query_list = base_query_list     
            
            # Perform database query
            try:
                result = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=query_list
                )
                
                # Break if results found
                if result['total'] > 0:
                    print('hi')
            except Exception as e:
                    print(f"Error occurred during query: {e}")    
    except:
        if isKey:
            return jsonify({
                "total": 0,
                "documents": []
            })
        else:
            return render_template('search.html',userInfo=userInfo)
              

    # If no results found after all strategies
    if not result:
        if isKey:
            return jsonify({
                "total": 0,
                "documents": []
            })
        else:
            return render_template('search.html',userInfo=userInfo)

    # Process documents
    documents = result.get('documents', [])
    filtered_documents = []
    
    for doc in documents:

        img = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('ANIME_IMGS'),
            document_id=doc.get('mainId'),
            queries=[
                Query.select(['cover'])
            ]
        )

            
    # Filter document
        filtered_document = {
            "id":doc.get("mainId"),
            "english": doc.get("english") if doc.get('english') is not None else doc.get("romaji"),
            "romaji": doc.get("romaji"),
            "native": doc.get("native"),
            "ageRating": doc.get("ageRating"),
            "malScore": doc.get("malScore"),
            "averageScore": doc.get("averageScore"),
            "duration": doc.get("duration"),
            "genres": doc.get("genres"),
            "cover":img.get("cover") or "/static/placeholder.svg",
            "season": doc.get("season"),
            "startDate": doc.get("startDate"),
            "status": doc.get("status"),
            "synonyms": doc.get("synonyms"),
            "type": doc.get("type"),
            "year": doc.get("year"),
            "epCount": doc.get("subbed"),
            "subbedCount": doc.get("subbed"),
            "dubbedCount": doc.get("dubbed"),
            "description": doc.get("description"),
        }
        filtered_documents.append(filtered_document)
    # Sorting logic

    # Prepare response
    data = {
        "total": len(filtered_documents),
        "data": filtered_documents,
        "success": True,
        "total_pages": math.ceil(result['total'] / results_per_page)
    }

    response = make_response(json.dumps(data, indent=4, sort_keys=False))
    response.headers["Content-Type"] = "application/json"

    if isKey:
        return response
    else:
        return render_template("upcoming.html",result=filtered_documents,total=result['total'],userInfo=userInfo,page=page,results_per_page=results_per_page)
    
@app.route('/anime/<id>', methods=['GET','POST'])
def anime_info(id):

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
        
    isKey = bool(secret)
    idz = id
    inWatchlist = False
    folder = None

    # Add error handling for missing parameters
    if not idz:
        return jsonify({"error": "Missing required(id) parameters", "success":False}), 400
    
    if secret:
        isKey = True
    else:
        isKey = False 
        print("bye")  
        secret = os.getenv('SECRET')
    try:
        if 'session_secret' in session:
            

            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            print(0)
            
            userInfo = get_acc_info(acc)

        elif bool(key):
            client = get_client(None,key,None)
            account = Account(client)

            acc = account.get()
            print(1)
            
            userInfo = get_acc_info(acc)

        else:
            print(3)
            userInfo = None

    except Exception as e:
        print(4)
        userInfo = None
     
    try:
        client = get_client(None,key, secret)
        databases = Databases(client)

        try:
        
            result = databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime'),
                document_id=idz,
                queries=[
                    Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration","studios", "genres", "season", "startDate", "status", "synonyms", "type", "year","subbed","dubbed","description"])
                ]
            )
        except Exception as e:

            result = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime'),
                queries=[
                    Query.equal('anilistId',int(id)),
                    Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration","studios", "genres", "season", "startDate", "status", "synonyms", "type", "year","subbed","dubbed","description"])
                ]
            )

            result = result['documents'][0]

        views = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime_Views'),
            queries=[
                Query.equal('animeId',id),
                Query.select(["animeId"])
            ]
        )

        Likes = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_LIKES'),
            queries=[
                Query.equal('isLiked',True),
                Query.equal('animeId',id),
                Query.select(["animeId"])
            ]
        )

        img = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('ANIME_IMGS'),
            document_id=result.get('mainId'),
            queries=[
                Query.select(['cover','banner'])
            ]
        )

        doc = result

        if userInfo:

            wid = generate_unique_id(acc.get("$id"),doc.get('mainId'))

            print(wid)

            wr = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Watchlist'),
                queries=[
                    Query.equal("itemId", wid),
                    Query.select("folder"),
                ]
            )

            if wr['total'] > 0:
                inWatchlist = True
                folder = wr['documents'][0].get('folder')

        title = doc.get('english') if doc.get('english') is not None else doc.get('romaji')
        description = doc.get("description")
        cover = img.get("cover") or "https://kuudere.to/static/placeholder.svg"

        # Calculate subbed and dubbed counts
        filtered_document = {
                "id":doc.get('mainId'),
                "english": doc.get("english") if doc.get('english') is not None else doc.get("romaji"),
                "romaji": doc.get("romaji"),
                "native": doc.get("native"),
                "ageRating": doc.get("ageRating"),
                "malScore": doc.get("malScore"),
                "averageScore": doc.get("averageScore"),
                "duration": doc.get("duration"),
                "genres": doc.get("genres"),
                "cover": img.get("cover"),
                "banner":img.get("banner") or "/static/placeholder.svg",
                "season": doc.get("season"),
                "startDate": doc.get("startDate"),
                "status": doc.get("status"),
                "synonyms": doc.get("synonyms"),
                "studios": doc.get("studios"),
                "type": doc.get("type"),
                "year": doc.get("year"),
                "epCount":doc.get("subbed"),
                "subbedCount": doc.get("subbed"),
                "dubbedCount": doc.get("dubbed"),
                "description": doc.get("description"),
                "in_watchlist": inWatchlist,
                "folder":folder,
                "views":format_views(views['total']),
                "likes":format_likes(Likes['total']),
            }
        
        data = {
            "data": filtered_document,
            "userInfo": userInfo,
            "success": True
        }

        response = make_response(json.dumps(data, indent=4, sort_keys=False))
        response.headers["Content-Type"] = "application/json"

        if isKey:
            return response
        else:
            return render_template("anime.html",anime=filtered_document, userInfo=userInfo,title=title,description=description,cover=cover,canonical_url=f"/anime/{id}")
    
    except Exception as e:
        # Add error handling
        if isKey:
            return jsonify({"error": str(e),"success": False}), 500
        else:
           return render_template('404.html')

@app.route('/watch/<anime_id>/<ep_number>', methods=['GET','POST'])
@app.route('/watch/<anime_id>', methods=['GET','POST'])
def watch_page(anime_id, ep_number=None):
    ep = ep_number
    print(ep)
    secret = None
    key = None
    inWatchlist = False
    folder = None
    epASs =  None
    search = None
    ref = request.args.get('ref')
    latest = request.args.get('ep')

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
        
    nid = request.args.get('nid')
    idz =anime_id
    if ep_number:
        epASs = int(ep)
    isKey = bool(secret)
    isLiked = False
    isUnliked =  False
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

        try:
            if 'session_secret' in session:
                

                client = get_client(None,session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            elif bool(key):
                client = get_client(None,key,None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            else:
                userInfo = None
        except Exception as e:
            userInfo = None       

        # Initialize client and database
    client = get_client(None,None, secret)
    databases = Databases(client)

    # Fetch anime document from the database
    result = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime'),
        document_id=idz,
        queries=[
            Query.select(["mainId","animeId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms","studios", "type", "year", "description","subbed","dubbed","anilistId"]),
        ]
    )

    if not result:
        return {"error": "Anime not found","success": False}, 404
    
    if bool(latest):

        eps = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime_Episodes'),
                queries=[
                    Query.equal("animeId", result.get("animeId")),
                    Query.order_desc('number'),
                    Query.select(["number"]),
                    Query.limit(1)
                ]
            )
        
        epASs = eps['documents'][0].get('number')
    
    elif not epASs:
        eps = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime_Episodes'),
                queries=[
                    Query.equal("animeId", result.get("animeId")),
                    Query.order_asc('number'),
                    Query.select(["number"]),
                    Query.limit(1)
                ]
            )
        
        epASsz = eps['documents'][0].get('number')
        
    
    img = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('ANIME_IMGS'),
            document_id=result.get('mainId'),
            queries=[
                Query.select(['cover','banner'])
            ]
    )
    
    likes = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('ANIME_LIKES'),
                queries=[
                    Query.equal('isLiked', True),
                    Query.equal('animeId', anime_id),
                    Query.select(['animeId']),
                ]
            )
    dislikes = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('ANIME_LIKES'),
                queries=[
                    Query.equal('isLiked', False),
                    Query.equal('animeId', anime_id),
                    Query.select(['animeId']),
                ]
            )
    if userInfo:
                IsUserLiked = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('ANIME_LIKES'),
                    queries=[
                        Query.equal('animeId', anime_id),
                        Query.equal('isLiked', True),
                        Query.equal('userId', acc.get("$id")),
                        Query.select(['userId'])
                    ]
                )

                IsUserunLiked = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('ANIME_LIKES'),
                    queries=[
                        Query.equal('animeId',anime_id),
                        Query.equal('isLiked', False),
                        Query.equal('userId', acc.get("$id")),
                        Query.select(['userId'])
                    ]
                )

                if nid:
                    ns = databases.list_documents(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('Notifications'),
                        queries=[
                            Query.equal('notificationId',nid),
                        ]
                    )

                    if ns['total'] > 0:
                        databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('Notifications'),
                            document_id=nid,
                            data={
                                "isRead":True,
                            }
                        )
                    
                search = databases.list_documents(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('CONTINUE_WATCHING'),
                        queries=[
                            Query.equal("userId",acc.get("$id")),
                            Query.equal("animeId",anime_id),
                            Query.select(['episodeId']),
                        ]
                    )

                if IsUserLiked['total'] > 0:
                    isLiked = True
                elif IsUserunLiked['total'] > 0:
                    isUnliked = True

                wid = generate_unique_id(acc.get("$id"),anime_id)
                wr = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Watchlist'),
                    queries=[
                        Query.equal("itemId", wid),
                        Query.select("folder"),
                    ]
                )

                if wr['total'] > 0:
                    inWatchlist = True
                    folder = wr['documents'][0].get('folder')

    if not epASs:
        if userInfo and  search['total'] > 0:
            eps = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime_Episodes'),
                queries=[
                    Query.equal("animeId", result.get("animeId")),
                    Query.equal("$id", search['documents'][0].get('episodeId')),
                    Query.select(["number"]),
                    Query.limit(1)
                ]
            )

            epASs = eps['documents'][0].get('number')
            ep = eps['documents'][0].get('number')
            ep_number = eps['documents'][0].get('number')
        else:
            ep_number = epASsz
            eps = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime_Episodes'),
                queries=[
                    Query.equal("animeId", result.get("animeId")),
                    Query.equal("number", ep_number),
                    Query.select(["animeId"]),
                    Query.limit(1)
                ]
            )
    else:
        epASs = epASs or epASsz
        ep_number = epASs or epASsz
        eps = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime_Episodes'),
                queries=[
                    Query.equal("animeId", result.get("animeId")),
                    Query.equal("number", epASs),
                    Query.select(["animeId"]),
                    Query.limit(1)
                ]
            )

    epASs = epASs or epASsz
    bitch = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime_Episodes_Links'),
        queries=[
            Query.equal("animeId", result.get("animeId")),
            Query.equal("episodeNumber", epASs),
            Query.select(["serverId", "serverName", "episodeNumber", "dataType", "dataLink", "$id"]),
            Query.limit(99999)
        ]
    )

    if not eps['total'] > 0:
        return render_template('404.html'),404

    likass = bitch.get("documents", [])

    title = result.get('english') if result.get('english') is not None else result.get('romaji')

    title =  f"Watch {title} Sub/Dub Free On Kuudere.to"

    filtered_document = {
                "id":result.get('mainId'),
                "english": result.get("english") if result.get('english') is not None else result.get("romaji"),
                "romaji": result.get("romaji"),
                "native": result.get("native"),
                "ageRating": result.get("ageRating"),
                "malScore": result.get("malScore"),
                "averageScore": result.get("averageScore"),
                "duration": result.get("duration"),
                "genres": result.get("genres"),
                "cover": img.get("cover"),
                "banner":img.get("banner") or "/static/placeholder.svg",
                "season": result.get("season"),
                "startDate": datetime.fromisoformat(result.get("startDate").replace("Z", "+00:00")).strftime("%b %d, %Y") if result.get("startDate") else None,
                "status": result.get("status"),
                "synonyms": result.get("synonyms"),
                "studios": result.get("studios"),
                "type": result.get("type"),
                "year": result.get("year"),
                "epCount":result.get("subbed"),
                "subbedCount": result.get("subbed"),
                "dubbedCount": result.get("dubbed"),
                "description": result.get("description"),
                "ep":epASs,
                "userLiked": isLiked,
                "userUnliked": isUnliked,
                "likes":likes['total'],
                "dislikes":dislikes['total'],
                "inWatchlist": inWatchlist,
                "folder":folder,
                "anilist":result.get('anilistId'),
                "url":f"/anime/{result.get('mainId')}",
            }
            
    response = {
        "anime_info": filtered_document,
        "userInfo":userInfo,
        "success": True
    }
    dec = f"Best site to watch { result.get('english') if result.get('english') is not None else result.get('romaji')} English Sub/Dub online Free and download { result.get('english') if result.get('english') is not None else result.get('romaji')} English Sub/Dub anime"
    cover = img.get("cover") if img.get('cover') is not None else img.get("banner")

    response = make_response(json.dumps(response, indent=4, sort_keys=False))
    response.headers["Content-Type"] = "application/json"

    if isKey:
        return response
    return render_template('watch.html', anime_id=anime_id, ep_number=ep_number,animeInfo = filtered_document,userInfo=userInfo,description=dec,cover=cover, title = title)

@app.route("/api/anime/respond/<id>", methods=['POST'])
def like_anime(id):
    # Get the JSON data from the request body
    data = request.json
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    isKey = bool(secret)
    
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        
        key = session["session_secret"]

        client = get_client(None,session["session_secret"], None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)
        
    elif bool(key):
        client = get_client(None,key, None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)

    else:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401

    lid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(None,key, None)
    databases = Databases(client)

    # Extract the 'type' from the data
    response_type = data.get('type')

    isAnime = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime'),
        document_id=id,
        queries=[Query.select(['mainId'])]
    )

    if isAnime.get('mainId'):
        try:
            isliked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('ANIME_LIKES'),
                queries=[
                    Query.equal('animeId', id),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['likedId', 'userId']),
                ]
            )
        except Exception as e:
            return e    

        # Check if 'type' is provided
        if response_type:
            # Process the request based on 'type' (like or dislike)
            if response_type == 'like':
                try:
                    if isliked['documents']:
                        # If documents exist, update the like status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('ANIME_LIKES'),
                            document_id=isliked['documents'][0]['likedId'],  # Use the document ID here
                            data={
                                "likedId": isliked['documents'][0]['likedId'],
                                "userId": acc.get("$id"),
                                "animeId": id,
                                "timestamp": iso_timestamp,
                                "isLiked": True,
                            }
                        )
                    else:
                        # Create a new like
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('ANIME_LIKES'),
                            document_id=lid,
                            data={
                                "likedId": lid,
                                "userId": acc.get("$id"),
                                "animeId": id,
                                "timestamp": iso_timestamp,
                                "isLiked": True,
                            }
                        )

                        rank_points(client,acc,'Like')

                    return jsonify({"message": "Anime liked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e}"}), 500
            elif response_type == 'dislike':
                try:
                    if isliked['documents']:
                        # If documents exist, update the like status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('ANIME_LIKES'),
                            document_id=isliked['documents'][0]['likedId'],  # Use the document ID here
                            data={
                                "likedId": isliked['documents'][0]['likedId'],
                                "userId": acc.get("$id"),
                                "animeId": id,
                                "timestamp": iso_timestamp,
                                "isLiked": False,
                            }
                        )
                    else:
                        # Create a new like
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('ANIME_LIKES'),
                            document_id=lid,
                            data={
                                "likedId": lid,
                                "userId": acc.get("$id"),
                                "animeId": id,
                                "timestamp": iso_timestamp,
                                "isLiked": False,
                            }
                        )

                        rank_points(client,acc,'Like')

                    return jsonify({"message": "Anime disliked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e}"}), 500
            else:
                return jsonify({"message": "Invalid type!"}), 400
        else:
            return jsonify({"message": "Type is required!"}), 400
    else:
        return jsonify({"message": "Post Not Found!"}), 404

@app.route("/api/anime/comment/respond/<id>", methods=['POST'])
def like_anime_comment(id):
    # Get the JSON data from the request body
    data = request.json
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    isKey = bool(secret)
    
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        
        key = session["session_secret"]

        client = get_client(None,session["session_secret"], None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)
        
    elif bool(key):
        client = get_client(None,key, None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)

    else:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401

    lid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(None,key, None)
    databases = Databases(client)

    # Extract the 'type' from the data
    response_type = data.get('type')

    isAnime = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Episode_Comments'),
        document_id=id,
        queries=[Query.select(['commentId','userId'])]
    )

    if isAnime.get('commentId'):
        try:
            isliked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Episode_Comments_Likes'),
                queries=[
                    Query.equal('relatedEpCommentId', id),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['likeId', 'userId']),
                ]
            )
        except Exception as e:
            return e    

        # Check if 'type' is provided
        if response_type:
            # Process the request based on 'type' (like or dislike)
            if response_type == 'like':
                try:
                    if isliked['documents']:
                        # If documents exist, update the like status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('Episode_Comments_Likes'),
                            document_id=isliked['documents'][0]['likeId'],  # Use the document ID here
                            data={
                                "likeId": isliked['documents'][0]['likeId'],
                                "userId": acc.get("$id"),
                                "relatedEpCommentId": id,
                                "isLiked": True,
                            }
                        )
                    else:
                        # Create a new like
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('Episode_Comments_Likes'),
                            document_id=lid,
                            data={
                                "likeId": lid,
                                "userId": acc.get("$id"),
                                "relatedEpCommentId": id,
                                "isLiked": True,
                            }
                        )

                        rank_points(client,acc,'Like',isAnime.get('userId'))

                    return jsonify({"message": "Anime liked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e}"}), 500
            elif response_type == 'dislike':
                try:
                    if isliked['documents']:
                        # If documents exist, update the like status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('Episode_Comments_Likes'),
                            document_id=isliked['documents'][0]['likeId'],  # Use the document ID here
                            data={
                                "likeId": isliked['documents'][0]['likeId'],
                                "userId": acc.get("$id"),
                                "relatedEpCommentId": id,
                                "isLiked": False,
                            }
                        )
                    else:
                        # Create a new like
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('Episode_Comments_Likes'),
                            document_id=lid,
                            data={
                                "likeId": lid,
                                "userId": acc.get("$id"),
                                "relatedEpCommentId": id,
                                "isLiked": False,
                            }
                        )

                        rank_points(client,acc,'Like',isAnime.get('userId'))

                    return jsonify({"message": "Anime disliked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e}"}), 500
            else:
                return jsonify({"message": "Invalid type!"}), 400
        else:
            return jsonify({"message": "Type is required!"}), 400
    else:
        return jsonify({"message": "Post Not Found!"}), 404   
         
@app.route('/export/json', methods=['GET','POST'])
def export_as_xml():
    try:
        secret = None
        key = None
        if not key:
            key = session.get("session_secret")
        client = get_client(None, key, None)
        account = Account(client)
        result = account.get()
        uid = result['$id']
        databases = Databases(client)
        get_list = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Watchlist'),
            queries=[
                Query.equal("userId", uid),
                Query.select(['animeId','folder']),
                Query.limit(99999)
            ]
        )
        
        anilist_data = {"export_type": "ANILIST_IMPORT", "data": []}
        
        if get_list['total'] > 0:
            for doc in get_list['documents']:
                check_anime = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=[
                        Query.equal("mainId", doc.get('animeId')),
                        Query.select(['malId'])
                    ]
                )
                
                if check_anime['total'] > 0 and check_anime['documents'][0].get('malId'):
                    anilist_id = check_anime['documents'][0].get('malId')
                    folder = doc.get('folder')
                    
                    # Map folder names to AniList status values
                    status_map = {
                        "Watching": "CURRENT",
                        "Plan To Watch": "PLANNING",
                        "Completed": "COMPLETED",
                        "Dropped": "DROPPED",
                        "On Hold": "PAUSED"
                    }
                    
                    status = status_map.get(folder, "PLANNING")
                    
                    anilist_data["data"].append({
                        "id": anilist_id,
                        "status": status
                    })
        
        # Return as downloadable JSON file
        response = make_response(json.dumps(anilist_data, indent=2))
        response.headers["Content-Disposition"] = "attachment; filename=export.json"
        response.headers["Content-Type"] = "application/json"
        
        return response
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/export/xml', methods=['GET','POST'])
def export_watchlist():
    try:
        secret = None
        key = None
        if not key:
            key = session.get("session_secret")
        client = get_client(None, key, None)
        account = Account(client)
        result = account.get()
        uid = result['$id']
        databases = Databases(client)
        get_list = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Watchlist'),
            queries=[
                Query.equal("userId", uid),
                Query.select(['animeId','folder']),
                Query.limit(99999)
            ]
        )
        
        # Create XML structure for AniList
        xml_content = '<?xml version="1.0" encoding="UTF-8"?>\n'
        xml_content += '<myanimelist>\n'
        
        if get_list['total'] > 0:
            for doc in get_list['documents']:
                check_anime = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=[
                        Query.equal("mainId", doc.get('animeId')),
                        Query.select(['malId'])
                    ]
                )
                
                if check_anime['total'] > 0 and check_anime['documents'][0].get('malId'):
                    anilist_id = check_anime['documents'][0].get('malId')
                    folder = doc.get('folder')
                    
                    # Map folder names to AniList/MAL status values
                    status_map = {
                        "Watching": "Watching",
                        "Plan To Watch": "Plan to Watch",
                        "Completed": "Completed",
                        "Dropped": "Dropped",
                        "On Hold": "On-Hold"
                    }
                    
                    status = status_map.get(folder, "Plan to Watch")
                    
                    xml_content += '  <anime>\n'
                    xml_content += f'    <series_animedb_id>{anilist_id}</series_animedb_id>\n'
                    xml_content += f'    <my_status>{status}</my_status>\n'
                    xml_content += '  </anime>\n'
        
        xml_content += '</myanimelist>'
        
        # Return as downloadable XML file
        response = make_response(xml_content)
        response.headers["Content-Disposition"] = "attachment; filename=export.xml"
        response.headers["Content-Type"] = "application/xml"
        
        return response
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
@app.route('/export/text', methods=['GET','POST'])
def export_watchlist_text():
    try:
        secret = None
        key = None
        if not key:
            key = session.get("session_secret")
        client = get_client(None, key, None)
        account = Account(client)
        result = account.get()
        uid = result['$id']
        databases = Databases(client)
        get_list = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Watchlist'),
            queries=[
                Query.equal("userId", uid),
                Query.select(['animeId','folder']),
                Query.limit(99999)
            ]
        )
        
        # Create text content
        text_content = "Kuudere Watchlist Export\n"
        text_content += "==============\n\n"
        
        # Organize by folder
        folders = {"Watching": [], "Plan To Watch": [], "Completed": [], "Dropped": [], "On Hold": []}
        
        if get_list['total'] > 0:
            for doc in get_list['documents']:
                check_anime = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=[
                        Query.equal("mainId", doc.get('animeId')),
                        Query.select(['anilistId','malId', 'romaji', 'english'])
                    ]
                )
                
                if check_anime['total'] > 0:
                    anilist_id = check_anime['documents'][0].get('anilistId')
                    mal_id = check_anime['documents'][0].get('malId')
                    folder = doc.get('folder')
                    title = check_anime['documents'][0].get('english') or check_anime['documents'][0].get('romaji')
            
                    if folder in folders:
                        folders[folder].append((anilist_id,mal_id, title))
                    else:
                        folders["Plan To Watch"].append((anilist_id,mal_id, title))
        
        # Add entries to text content by folder
        for folder, entries in folders.items():
            if entries:
                text_content += f"{folder}:\n"
                for anilist_id, mal_id, title in sorted(entries, key=lambda x: x[2] or ""):
                    text_content += f"- {title} (Mal ID: {mal_id}) & (Anilist ID: {anilist_id})\n"
                text_content += "\n"
        
        # Return as downloadable text file
        response = make_response(text_content)
        response.headers["Content-Disposition"] = "attachment; filename=export.txt"
        response.headers["Content-Type"] = "text/plain"
        
        return response
        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/add-to-watchlist/<folder>/<animeid>', methods=['GET','POST'])
def add_to_watchlist(folder, animeid):
    try:
        secret = None
        key = None

        isApi, key, secret, userInfo, acc = verify_api_request(request)

        if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401

        if not key:
            key = session.get("session_secret")

        valid_folders = ["Plan To Watch", "Watching", "Completed", "On Hold", "Dropped", "Remove"]
        if folder not in valid_folders:
            return jsonify({"error": "Invalid folder", "success": False}), 400

        client = get_client(None,key, None)
        account = Account(client)
        result = account.get()
        uid = result['$id']

        databases = Databases(client)

        check_anime = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime'),
            queries=[
                Query.equal("mainId", animeid),
                Query.select(['mainId','anilistId'])
            ]
        )

        if check_anime['total'] == 0:
            return jsonify({"error": "Anime not found in system", "success": False}), 404
        
        animeid = check_anime['documents'][0].get('mainId')
        anilist = check_anime['documents'][0].get('anilistId')

        wid = generate_unique_id(uid,animeid)

        print(wid)

        wr = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Watchlist'),
            queries=[
                Query.equal("itemId", wid),
                Query.select(['itemId'])
            ]
        )

        if wr['total'] > 0:

            if folder == "Remove":
                result = databases.delete_document(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Watchlist'),
                    document_id=wid,
                )
            else:    

                result = databases.update_document(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Watchlist'),
                    document_id=wid,
                    data={
                        "itemId": wid,
                        "userId":uid,
                        "animeId":animeid,
                        "folder": folder,
                        "lastUpdated": datetime.now(timezone.utc).isoformat(),
                    },
                    permissions=[
                        "read(\"any\")",
                        f"update(\"user:{uid}\")",
                        f"write(\"user:{uid}\")",
                        f"delete(\"user:{uid}\")",
                    ],
                )

        else:
            if folder == "Remove":
                response_data = {
                    "data": {
                        "itemId": wid,
                        "folder": folder,
                        "anime": animeid,
                    },
                    "success": True
                }

                return response_data

            result = databases.create_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Watchlist'),
                document_id=wid,
                data={
                    "itemId": wid,
                    "userId":uid,
                    "animeId":animeid,
                    "folder": folder,
                    "lastUpdated": datetime.now(timezone.utc).isoformat(),
                },
                permissions=[
                    "read(\"any\")",
                    f"update(\"user:{uid}\")",
                    f"write(\"user:{uid}\")",
                    f"delete(\"user:{uid}\")",
                ],
            )
        
        try:
 # Fetch AniList info
            anilist_info = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('ANILIST_INFO'),
                queries=[
                    Query.order_desc("$updatedAt"),
                    Query.equal("user", uid),
                ]
            )

            print("✅ AniList Info Response:", json.dumps(anilist_info, indent=2))
            print("✅ User ID:", uid)

            # Check if data exists
            if anilist_info and anilist_info.get('total', 0) > 0 and anilist_info.get('documents'):
                anilist_data = anilist_info['documents'][0]  # Safely get first document
                updated = anilist_data.get('$updatedAt')
                access_token = decrypt(anilist_data.get('access_token'))
                expire = anilist_data.get('expire')

                print(f"✅ Token Found: {bool(access_token)}, Expire Time: {expire}, Last Updated: {updated}")

                # Check if required fields exist
                if access_token and expire:
                    is_expired = check_expire(updated, expire)
                    
                    if not is_expired:
                        access_token = access_token
                    else:
                        access_token = None
                else:
                    access_token = None
            else:
                access_token = None
            
        except Exception as e:
            access_token = None
            print(f"Unexpected error: {e}")
            traceback.print_exc()  # Print full traceback for debugging

        response_data = {
            "data": {
                "itemId": wid,
                "folder": folder,
                "anime": animeid,
                "token":access_token,
                "anilist":anilist
            },
            "success": True
        }

        response = make_response(json.dumps(response_data, indent=4, sort_keys=False))
        response.headers["Content-Type"] = "application/json"
        return response

    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500


progress_queues = {}

def normalize_folder_name(raw_folder):
    # Explicit mapping for all possible folder names
    valid_folders = ["Plan To Watch", "Watching", "Completed", "On Hold", "Dropped", "Remove"]
    folder_mapping = {
        # From JSON example
        "Completed": "Completed",
        "On-Hold": "On Hold",
        "Plan to watch": "Plan To Watch",
        "Dropped": "Dropped",
        "Watching": "Watching",
        
        # Common variants
        "completed": "Completed",
        "on hold": "On Hold",
        "Plan-to-watch": "Plan To Watch",
        "watching": "Watching",
        "dropped": "Dropped",
        "Plan To Watch": "Plan To Watch",  # Already correct
        "Remove": "Remove"  # For completeness
    }
    
    # Clean and check
    cleaned = raw_folder.replace('-', ' ').strip().title()
    return folder_mapping.get(cleaned, cleaned)

# Existing parsing functions (as provided in previous answers)
def parse_txt(content):
    sections = {}
    current_section = None
    id_pattern = re.compile(r'https://myanimelist.net/anime/(\d+)')

    for line in content.split('\n'):
        line = line.strip()
        if not line:
            continue
        
        if line.startswith('#'):
            raw_folder = line[1:].strip()
            current_section = normalize_folder_name(raw_folder)
            sections[current_section] = []
        elif current_section and '|' in line:
            _, url = line.split('|', 1)
            match = id_pattern.search(url.strip())
            if match:
                sections[current_section].append(match.group(1))
    return sections

def parse_xml(content):
    sections = {}
    root = ET.fromstring(content)
    id_pattern = re.compile(r'https://myanimelist.net/anime/(\d+)')
    
    for folder in root.findall('folder'):
        raw_folder = folder.find('name').text.strip()
        section_name = normalize_folder_name(raw_folder)
        data = folder.find('data')
        items = data.findall('item') if data is not None else []
        sections[section_name] = []
        
        for item in items:
            link = item.find('link').text.strip()
            match = id_pattern.search(link)
            if match:
                sections[section_name].append(match.group(1))
    return sections

def parse_json(content):
    sections = {}
    data = json.loads(content)
    id_pattern = re.compile(r'https://myanimelist.net/anime/(\d+)')
    
    for raw_folder, entries in data.items():
        section_name = normalize_folder_name(raw_folder)
        sections[section_name] = []
        for entry in entries:
            link = entry.get('link', '')
            match = id_pattern.search(link)
            if match:
                sections[section_name].append(match.group(1))
    return sections

def process_file(content, filename, request, progress_queue):
    try:
        # Parse the file based on its format
        if filename.endswith('.xml'):
            sections = parse_xml(content)
        elif filename.endswith('.json'):
            sections = parse_json(content)
        else:
            sections = parse_txt(content)

        total = sum(len(ids) for ids in sections.values())
        processed = 0
        errors = []

        # Try to get key and secret from the original request
        key = None
        secret = None
        
        # Check if form data contains key and secret
        if request.form:
            key = request.form.get('key')
            secret = request.form.get('secret')

        # Create a dummy request object with the necessary JSON data
        class DummyRequest:
            def __init__(self, original_request, key=None, secret=None):
                self.referrer = original_request.referrer
                self.path = original_request.path
                self.is_json = True
                self._json = {}
                
                # Add key and secret to the JSON data if they exist
                if key:
                    self._json['key'] = key
                if secret:
                    self._json['secret'] = secret
                
                # Copy over cookies, session, and other attributes
                self.cookies = original_request.cookies
                
                # If the original request has session data
                if hasattr(original_request, 'session'):
                    self.session = original_request.session
                
            def get_json(self, silent=False):
                return self._json

        # Create a request-like object that passes as JSON
        dummy_request = DummyRequest(request, key, secret)
        
        for folder, ids in sections.items():
            for animeid in ids:
                try:
                    result = add_to_watchlist_z(folder, animeid, dummy_request)
                    
                    # Check if result is a tuple (error response with status code)
                    if isinstance(result, tuple):
                        response_data = result[0]  # The first element is the JSON response
                        
                        # If it's a jsonify response, we need to get the JSON data
                        if hasattr(response_data, 'get_json'):
                            response_data = response_data.get_json()
                            
                        success = response_data.get('success', False)
                    else:
                        # It's a direct dictionary or Response object
                        if hasattr(result, 'get_json'):
                            response_data = result.get_json()
                            success = response_data.get('success', False)
                        else:
                            success = result.get('success', False)
                    
                    if not success:
                        errors.append(f"Failed to add {animeid} to {folder}")
                except Exception as e:
                    errors.append(f"Error processing {animeid}: {str(e)}")
                
                processed += 1
                progress_queue.put({
                    'processed': processed,
                    'total': total,
                    'errors': errors[-10:],  # Keep last 10 errors
                    'current': animeid,
                    'folder': folder
                })

        progress_queue.put({'status': 'complete', 'errors': errors})
    except Exception as e:
        progress_queue.put({'status': 'error', 'message': str(e)})
    finally:
        # Signal end of queue
        progress_queue.put(None)
        
        # Cleanup: Remove the process from the queue tracking
        with queue_lock:
            if hasattr(request, 'process_id') and request.process_id in queue_order:
                queue_order.remove(request.process_id)
        with progress_queues_lock:
            if hasattr(request, 'process_id') and request.process_id in progress_queues:
                del progress_queues[request.process_id]

@app.route('/up')
def upload_form():
    return render_template('upload.html')

@app.route('/results')
def results_page():
    process_id = request.args.get('process_id')
    return render_template('results.html', process_id=process_id)

# Global variables for task management
task_queue = Queue()
processing_lock = threading.Lock()
current_worker = None

# Global variables for queue position tracking
queue_order = []  # Tracks the order of process IDs in the queue
current_processing = None  # Tracks the currently processing process ID
queue_lock = threading.Lock()  # Ensures thread-safe access to queue_order and current_processing

# Global variable for progress tracking
progress_queues = {}  # Maps process_id to its progress queue
progress_queues_lock = threading.Lock()  # Ensures thread-safe access to progress_queues

def worker():
    global current_processing
    while True:
        task = task_queue.get()
        if task is None:
            break
        process_id, task_func = task
        try:
            # Update queue status
            with queue_lock:
                if queue_order and queue_order[0] == process_id:
                    queue_order.pop(0)
                current_processing = process_id
            
            # Execute the task with preserved context
            task_func()
        except Exception as e:
            print(f"Error processing task {process_id}: {str(e)}")
        finally:
            with queue_lock:
                current_processing = None
            task_queue.task_done()

# Start the worker thread when the app starts
def start_worker():
    global current_worker
    with processing_lock:
        if current_worker is None or not current_worker.is_alive():
            current_worker = Thread(target=worker)
            current_worker.daemon = True
            current_worker.start()

# Modify your handle_upload function
@app.route('/processx', methods=['POST'])
def handle_upload():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401

    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    
    process_id = str(uuid.uuid4())
    with progress_queues_lock:
        progress_queues[process_id] = Queue()

    try:
        content = file.read().decode('utf-8')
        filename = file.filename.lower()
        progress_queue = progress_queues[process_id]

        # Create context-preserving task wrapper
        @copy_current_request_context
        def task_wrapper():
            process_file(content, filename, request, progress_queue)

        # Add the context-wrapped task to the queue
        with queue_lock:
            queue_order.append(process_id)
        task_queue.put((process_id, task_wrapper))
        
        # Ensure worker is running
        start_worker()
        
    except Exception as e:
        with queue_lock:
            if process_id in queue_order:
                queue_order.remove(process_id)
        with progress_queues_lock:
            if process_id in progress_queues:
                del progress_queues[process_id]
        return jsonify({'success': False, 'error': str(e)}), 500

    return jsonify({'process_id': process_id}), 202

# Streaming endpoint for progress updates
@app.route('/stream/<process_id>')
def progress_stream(process_id):
    def generate():
        with progress_queues_lock:
            queue = progress_queues.get(process_id)
            if not queue:
                yield 'data: {"status": "error", "message": "Invalid process ID"}\n\n'
                return

        while True:
            msg = queue.get()
            if msg is None:
                break
            yield f"data: {json.dumps(msg)}\n\n"
        
        # Cleanup
        with progress_queues_lock:
            if process_id in progress_queues:
                del progress_queues[process_id]

    return Response(generate(), mimetype='text/event-stream')

# Endpoint to check queue position
@app.route('/queue_status/<process_id>')
def queue_status(process_id):
    def generate():
        while True:
            with queue_lock:
                # Get current position
                if current_processing == process_id:
                    status = "processing"
                    position = 0
                elif process_id in queue_order:
                    status = "queued"
                    position = queue_order.index(process_id) + 1
                else:
                    status = "not_found"
                    position = None
                    
                # Check if processing is complete
                with progress_queues_lock:
                    exists = process_id in progress_queues

            data = {
                "status": status,
                "position": position,
                "exists": exists
            }

            yield f"data: {json.dumps(data)}\n\n"
            
            # Stop streaming if completed
            if not exists and status != "processing":
                break
                
            shitl.sleep(1)

    return Response(generate(), mimetype='text/event-stream')

def add_to_watchlist_z(folder, animeid,request):
    try:
        secret = None
        key = None

        isApi, key, secret, userInfo, acc = verify_api_request(request)

        if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401

        if not key:
            key = session.get("session_secret")

        valid_folders = ["Plan To Watch", "Watching", "Completed", "On Hold", "Dropped", "Remove"]
        if folder not in valid_folders:
            print ("lol")
            return jsonify({"error": "Invalid folder", "success": False}), 400

        client = get_client(None,key, None)
        account = Account(client)
        result = account.get()
        uid = result['$id']
        print(uid)

        try:
            databases = Databases(client)
            animeid = int(animeid)


            check_anime = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Anime'),
                queries=[
                    Query.equal("malId", animeid),
                    Query.select(['mainId'])
                ]
            )
        except Exception as e:
            return jsonify({"error": "Internal Server error", "success": False}), 500

        if check_anime['total'] == 0:
            return jsonify({"error": "Anime not found in system", "success": False}), 404
        
        animeid = check_anime['documents'][0].get('mainId')

        wid = generate_unique_id(uid,animeid)

        print(wid)

        wr = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Watchlist'),
            queries=[
                Query.equal("itemId", wid),
                Query.select(['itemId'])
            ]
        )

        if wr['total'] > 0:

            if folder == "Remove":
                result = databases.delete_document(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Watchlist'),
                    document_id=wid,
                )
            else:    

                result = databases.update_document(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Watchlist'),
                    document_id=wid,
                    data={
                        "itemId": wid,
                        "userId":uid,
                        "animeId":animeid,
                        "folder": folder,
                        "lastUpdated": datetime.now(timezone.utc).isoformat(),
                    },
                    permissions=[
                        "read(\"any\")",
                        f"update(\"user:{uid}\")",
                        f"write(\"user:{uid}\")",
                        f"delete(\"user:{uid}\")",
                    ],
                )

        else:
            if folder == "Remove":
                response_data = {
                    "data": {
                        "itemId": wid,
                        "folder": folder,
                        "anime": animeid,
                    },
                    "success": True
                }

                return response_data

            result = databases.create_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Watchlist'),
                document_id=wid,
                data={
                    "itemId": wid,
                    "userId":uid,
                    "animeId":animeid,
                    "folder": folder,
                    "lastUpdated": datetime.now(timezone.utc).isoformat(),
                },
                permissions=[
                    "read(\"any\")",
                    f"update(\"user:{uid}\")",
                    f"write(\"user:{uid}\")",
                    f"delete(\"user:{uid}\")",
                ],
            )

        response_data = {
            "data": {
                "itemId": wid,
                "folder": folder,
                "anime": animeid,
            },
            "success": True
        }

        response = make_response(json.dumps(response_data, indent=4, sort_keys=False))
        response.headers["Content-Type"] = "application/json"
        return response

    except Exception as e:
        return jsonify({"error": str(e), "success": False}), 500
        
def generate_unique_id(string1, string2):
    combined = string1 + string2
    # Use SHA-256 and truncate to 32 characters
    return hashlib.sha256(combined.encode()).hexdigest()[:32]    

@app.route('/search-api')
def search_api():
    keyword = request.args.get('q', '').lower()
    secret = os.getenv('SECRET')

    try:
        # Validate secret
        client = get_client(None,None, secret)
        databases = Databases(client)

        # Base query list
        base_query_list = [Query.equal("public", True)]
        base_query_list.append(Query.select(["mainId", "english", "romaji", "native", "duration", "type", "year","synonyms"]))

        # Search strategies for the keyword
        def get_keyword_search_queries(keyword):
            return [
                Query.or_queries([Query.search("english", keyword), Query.search("romaji", keyword),Query.search("native", keyword),Query.contains("synonyms", keyword)]),
            ]

        # Result variable
        filtered_documents = []

        # Collect results from all keyword queries
        for keyword_query in get_keyword_search_queries(keyword):
            # Combine base queries with the current keyword strategy
            query_list = base_query_list + [keyword_query, Query.limit(4)]

            try:
                # Perform the database query
                result = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=query_list
                )
                print(result)

                # If results are found, add them to the list
                if result and result['total'] > 0:
                    documents = result.get('documents', [])
                    for doc in documents:
                        # Fetch cover image for each document
                        img = databases.get_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('ANIME_IMGS'),
                            document_id=doc.get('mainId'),
                            queries=[
                                Query.select('cover')
                            ]
                        )

                        # Prepare filtered document
                        filtered_document = {
                            "id": doc.get("mainId"),
                            "title": doc.get("english") if doc.get('english') else doc.get("romaji"),
                            "details": f"{doc.get('year')} • {doc.get('type')}",
                            "coverImage": img.get("cover") or "/static/placeholder.svg"
                        }
                        filtered_documents.append(filtered_document)

            except Exception as e:
                print(f"Error occurred during query: {e}")

        # Deduplicate by mainId
        unique_documents = list({doc['id']: doc for doc in filtered_documents}.values())

        # Limit the results to 4
        limited_results = unique_documents[:6]

        # If no documents found, return a message
        if not limited_results:
            return jsonify({"error": "Nothing Found", "success": False}), 404

        # Return the same output structure
        return jsonify(limited_results), 200

    except Exception as e:
        print(f"Error occurred: {e}")
        return jsonify([{"message": "An error occurred while fetching results."}])

def replace_tld(url,new_tld):
    new_url = re.sub(r"https://[^/]+/", f"https://{new_tld}/", url)
    return new_url

@app.route('/watch-api/<anime_id>/<int:ep_number>',methods=['GET','POST'])
def fetch_episode_info(anime_id,ep_number):
    duration = 0
    current = 0
    intro_start = 0
    intro_end = 0
    outro_start = 0
    outro_end = 0
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    idz = anime_id
    epASs = int(ep_number)
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

        try:
            if 'session_secret' in session:
                

                client = get_client(None,session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            elif bool(key):
                client = get_client(None,key,None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            else:
                userInfo = None
        except Exception as e:
            userInfo = None       
    print("Key is missing or empty, setting default secret.")

        # Initialize client and database
    client = get_client(None,None, secret)
    databases = Databases(client)

        # Fetch anime document from the database
    result = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime'),
        document_id=idz,
        queries=[
            Query.select(["animeId","anilistId","malId","animeId"]),
        ]
    )

    if not result:
        return {"error": "Anime not found","success": False}, 404
    
    vid = ID.unique()
    
    view = databases.create_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime_Views'),
        document_id=vid,
        data={
            "viewId": vid,
            "animeId":anime_id,
            "viwersIp":client_ip,
        }
    )
    
    epiList = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime_Episodes'),
        queries=[
            Query.equal("animeId",result.get("animeId")),
            Query.select(["titles", "number", "aired", "score", "recap", "filler","$id","$updatedAt"]),
            Query.limit(99999)
        ]
    )

    epinfo = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime_Episodes'),
        queries=[
            Query.equal("animeId",result.get("animeId")),
            Query.equal("number",ep_number),
            Query.select(["$id"])
        ]
    )

    skip = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id = os.getenv('EPISODE_SKIP_DATA'),
        queries =[
            Query.equal("animeId", result.get('animeId')),
            Query.equal("episodeId", epinfo['documents'][0].get('$id'),),
            Query.select(['intro_start','intro_end','outro_start','outro_end']),
        ]
    )

    if skip['total'] <= 0:

        skipd=None
    else:
        skipdd = skip['documents'][0]
        skipd = {'anilist_id': f'{result.get("anilistId")}','mal_id': f'{result.get("mal_id")}','intro_start': f'{skipdd.get('intro_start')}', 'intro_end': f'{skipdd.get('intro_end')}', 'outro_start': f'{skipdd.get('outro_start')}', 'outro_end': f'{skipdd.get('outro_end')}'}

    print(skipd)
    try:
        if result.get("anilistId"):
            if skipd.get('anilist_id') == str(result.get("anilistId")):
                intro_start = skipd.get('intro_start')
                intro_end = skipd.get('intro_end')
                outro_start = skipd.get('outro_start')
                outro_end = skipd.get('outro_end')
        elif result.get("malId"):
            if skipd.get('mal_id') == str(result.get("malId")):
                intro_start = skipd.get('intro_start')
                intro_end = skipd.get('intro_end')
                outro_start = skipd.get('outro_start')
                outro_end = skipd.get('outro_end')
    except Exception as e:
        print(e)

    dddd = epinfo['documents'][0].get('$id')

    # Extract episode data
    episodes = epiList.get("documents", [])
    episode_details = []
    ep_links = []

    for episode in episodes:
        titles = episode.get("titles", [])

        # Check if the list is empty OR if all values inside are None
        if not titles or all(t is None for t in titles):
            titles = [f"Episode {episode.get("number")}"]

        episode_info = {
            "id": episode.get("$id"),
            "titles": titles,  # Default title as a list
            "filler": episode.get("filler"),
            "number": episode.get("number"),
            "recap": episode.get("recap"),
            "aired": datetime.fromisoformat(episode.get("aired").replace("Z", "+00:00")).strftime("%b %d, %Y") if episode.get("aired") else None,
            "ago":format_relative_time(episode.get("$updatedAt")),
        }
        episode_details.append(episode_info)

    bitch = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime_Episodes_Links'),
        queries=[
            Query.equal("animeId", result.get("animeId")),
            Query.equal("episodeNumber", epASs),
            Query.select(["serverId", "serverName", "episodeNumber", "dataType", "dataLink", "$id"]),
            Query.limit(99999)
        ]
    )

    likass = bitch.get("documents", [])

    for links in likass:
        cwatching = False
        if links.get("serverName") == "Hianime":
            # Get base components
            original_link = links.get("dataLink")
            clean_path = original_link.replace("https://hianime.to/watch/", "")
            current_domain = request.url_root.strip('/')
            hostname = "http://127.0.0.1:5000"  # Handle port if present
            
            # Construct Hianime URL
            hianime_url = f"{current_domain}/player/Hianime/{clean_path}"
            
            # Add query parameters properly
            parsed = urlparse(hianime_url)
            separator = '?' if not parsed.query else '&'
            
            link_info = {
                "$id": links.get("$id"),
                "serverId": links.get("serverId"),
                "continue":True,
                "serverName": links.get("serverName"),
                "episodeNumber": links.get("episodeNumber"),
                "dataType": links.get("dataType"),
                "dataLink": f"{hianime_url}{separator}episode={epinfo['documents'][0]['$id']}"
                            f"&anime={anime_id}&vide=Hianime&api={hostname}"
            }
            ep_links.append(link_info)

            # Construct Hianime-2 URL
            hianime2_url = f"{current_domain}/player2/Hianime/{clean_path}"
            parsed_h2 = urlparse(hianime2_url)
            separator_h2 = '?' if not parsed_h2.query else '&'
            
            link_info_hianime_2 = {
                "$id": "jvjvh",
                "serverId": 10001,
                "continue":True,
                "serverName": "Hianime-2",
                "episodeNumber": links.get("episodeNumber"),
                "dataType": links.get("dataType"),
                "dataLink": f"{hianime2_url}{separator_h2}episode={epinfo['documents'][0]['$id']}"
                        f"&anime={anime_id}&vide=Hianime-2&api={hostname}"
            }
            ep_links.append(link_info_hianime_2)
        else:    
            hostname = request.host.split(':')[0]  # Handle port if present
            # Handle other servers with validation
            try:
                parsed_link = urlparse(links.get("dataLink"))
                if not parsed_link.netloc:
                    # Convert relative URLs to absolute
                    full_url = urljoin(current_domain, links.get("dataLink"))
                else:
                    full_url = links.get("dataLink")
                    
                # Validate URL
                if not is_valid_url(full_url):
                    raise ValueError("Invalid URL format")
                names  = ["Kumi","HD-0"]

                if links.get("serverName") in names:
                    full_url =f"{full_url}&api=all"
                    cwatching = True

                if links.get("serverName") == "Streamwish" or links.get("serverName") == "StreamWish":

                    full_url = replace_tld(full_url,'fhhgfdstr.site')
                
                if links.get("serverName") == "Vidhide" or links.get("serverName") == "Filelions":
                    full_url = replace_tld(full_url,'sgsgsgsr.site')
                    
                link_info = {
                    "$id": links.get("$id"),
                    "continue":cwatching,
                    "serverId": links.get("serverId"),
                    "serverName": links.get("serverName"),
                    "episodeNumber": links.get("episodeNumber"),
                    "dataType": links.get("dataType"),
                    "dataLink": full_url
                }
                ep_links.append(link_info)
                
            except Exception as e:
                print(f"Skipping invalid URL: {links.get('dataLink')}")
                continue

    ep_links.sort(key=lambda x: x['serverId'])

    coms = []

    comm = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments'),
            queries=[
                Query.equal("animeId", anime_id),
                Query.equal("epNumber", ep_number),  # Ensure episode.get("$id") returns the correct value
                Query.not_equal("removed", True),
                Query.order_desc('$updatedAt'),
                Query.select(["commentId","userId","added_date","comment","spoiller"]),
            ]
        )
    comz = comm.get("documents", [])

    for comment in comz:
        replys = []
        isLiked = False  # Reset to False for each comment
        isUnliked = False  # Reset to False for each comment

        reply = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Replys'),
            queries=[
                Query.equal("replyEpisodeCommentId", comment.get("commentId")),
                Query.not_equal("removed", True),
                Query.select(['userId',"episodeCommentReplyId","content","added_date"])
            ]
        )

        print(reply)

        userifo = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Users'),
            document_id=comment.get('userId'),
            queries=[
                Query.select('username')
            ]
        )

        rz = reply.get("documents", [])
        for rzls in rz:
            userifo0 = databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                document_id=rzls.get('userId'),
                queries=[
                    Query.select('username')
                ]
            )
            data = {
                'id': rzls.get("episodeCommentReplyId"),
                "author": userifo0.get('username'),
                "time": format_relative_time(rzls.get("added_date")),
                "content": rzls.get("content")
            }
            replys.append(data)

        likes = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Likes'),
            queries=[
                Query.equal('isLiked', True),
                Query.equal('relatedEpCommentId', comment.get("commentId")),
                Query.select(['relatedEpCommentId']),
            ]
        )

        dislikes = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Likes'),
            queries=[
                Query.equal('isLiked', False),
                Query.equal('relatedEpCommentId', comment.get("commentId")),
                Query.select(['relatedEpCommentId']),
            ]
        )

        if userInfo:
            IsUserLiked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Episode_Comments_Likes'),
                queries=[
                    Query.equal('relatedEpCommentId', comment.get("commentId")),
                    Query.equal('isLiked', True),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['userId'])
                ]
            )

            IsUserunLiked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Episode_Comments_Likes'),
                queries=[
                    Query.equal('relatedEpCommentId', comment.get("commentId")),
                    Query.equal('isLiked', False),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['userId'])
                ]
            )

            if IsUserLiked['total'] > 0:
                isLiked = True
            elif IsUserunLiked['total'] > 0:
                isUnliked = True

        detail_info = {
            "id": comment.get("commentId"),
            "author": userifo.get('username'),
            "isSpoiller": True,
            "time": format_relative_time(comment.get("added_date")),
            "content": comment.get("comment"),
            "showReplyForm": False,
            "showReplies": False,
            "isLiked": isLiked,
            "isUnliked": isUnliked,
            "likes": likes['total'],
            "replyContent": "",
            "replies": replys,
        }
        coms.append(detail_info)

    if userInfo:

            search = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('CONTINUE_WATCHING'),
                    queries=[
                        Query.equal("userId",acc.get("$id")),
                        Query.equal("animeId",anime_id),
                        Query.equal("episodeId",dddd),
                        Query.select(['continueId','currentTime','duration']),
                    ]
                )
            
            if search['total'] > 0:
                data = search['documents'][0]
                current = data.get('currentTime')
                duration = data.get('duration')

    response = {
                "all_episodes": episode_details,
                "episode_links": ep_links,
                "episode_comments":coms,
                "total_comments":comm['total'],
                "episode_id":dddd,
                "success": True,
                "duration": duration,
                "current":current,
                "intro_start":intro_start,
                "intro_end" :intro_end,
                "outro_start" :outro_start,
                "outro_end" :outro_end,
            }

    response = make_response(json.dumps(response, indent=4, sort_keys=False))
    response.headers["Content-Type"] = "application/json"

    return response

@app.route('/api/anime/comments/<anime_id>/<int:ep_number>',methods=['GET','POST'])
def get_comments(anime_id,ep_number):

    page = request.args.get('page', 1)  # Default to 1 if 'page' is missing
    try:
        page = int(page)
    except ValueError:
        page = 1  # Fallback to a safe default

    per_page = 3
    offset = (page - 1) * per_page

    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    idz = anime_id
    epASs = int(ep_number)
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

        try:
            if 'session_secret' in session:
                

                client = get_client(None,session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            elif bool(key):
                client = get_client(None,key,None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            else:
                userInfo = None
        except Exception as e:
            userInfo = None       
    print("Key is missing or empty, setting default secret.")

        # Initialize client and database
    client = get_client(None,None, secret)
    databases = Databases(client)

    
    coms = []

    comm = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments'),
            queries=[
                Query.equal("animeId", anime_id),
                Query.equal("epNumber", ep_number),  # Ensure episode.get("$id") returns the correct value
                Query.not_equal("removed", True),
                Query.order_desc('$updatedAt'),
                Query.select(["commentId","userId","added_date","comment","spoiller"]),
                Query.limit(per_page),
                Query.offset(offset)
            ]
        )
    comz = comm.get("documents", [])

    for comment in comz:
        replys = []
        isLiked = False  # Reset to False for each comment
        isUnliked = False  # Reset to False for each comment

        reply = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Replys'),
            queries=[
                Query.equal("replyEpisodeCommentId", comment.get("commentId")),
                Query.not_equal("removed", True),
                Query.select(['userId',"episodeCommentReplyId","content","added_date"])
            ]
        )

        print(reply)

        userifo = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Users'),
            document_id=comment.get('userId'),
            queries=[
                Query.select('username')
            ]
        )

        rz = reply.get("documents", [])
        for rzls in rz:
            userifo0 = databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                document_id=rzls.get('userId'),
                queries=[
                    Query.select('username')
                ]
            )
            data = {
                'id': rzls.get("episodeCommentReplyId"),
                "author": userifo0.get('username'),
                "time": format_relative_time(rzls.get("added_date")),
                "content": rzls.get("content")
            }
            replys.append(data)

        likes = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Likes'),
            queries=[
                Query.equal('isLiked', True),
                Query.equal('relatedEpCommentId', comment.get("commentId")),
                Query.select(['relatedEpCommentId']),
            ]
        )

        dislikes = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Likes'),
            queries=[
                Query.equal('isLiked', False),
                Query.equal('relatedEpCommentId', comment.get("commentId")),
                Query.select(['relatedEpCommentId']),
            ]
        )

        if userInfo:
            IsUserLiked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Episode_Comments_Likes'),
                queries=[
                    Query.equal('relatedEpCommentId', comment.get("commentId")),
                    Query.equal('isLiked', True),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['userId'])
                ]
            )

            IsUserunLiked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Episode_Comments_Likes'),
                queries=[
                    Query.equal('relatedEpCommentId', comment.get("commentId")),
                    Query.equal('isLiked', False),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['userId'])
                ]
            )

            if IsUserLiked['total'] > 0:
                isLiked = True
            elif IsUserunLiked['total'] > 0:
                isUnliked = True

        detail_info = {
            "id": comment.get("commentId"),
            "author": userifo.get('username'),
            "isSpoiller": True,
            "time": format_relative_time(comment.get("added_date")),
            "content": comment.get("comment"),
            "showReplyForm": False,
            "showReplies": False,
            "isLiked": isLiked,
            "isUnliked": isUnliked,
            "likes": likes['total'],
            "replyContent": "",
            "replies": replys,
        }
        coms.append(detail_info)

    has_more = offset + per_page < comm['total']
    print(f"lol{has_more}")
    print(f"lol{comm['total']}")
    print(f"lol{offset}")

    data = {
        "comments":coms,
        "has_more":has_more
    }

    response = make_response(json.dumps(data, indent=4, sort_keys=False))
    response.headers["Content-Type"] = "application/json"

    return response

@app.route('/community',methods=['GET','POST'])
def community():
        posts = []
        secret = None
        key = None

        isApi, key, secret, userInfo, acc = verify_api_request(request)

        if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
            
        isMod = False
        isKey = bool(secret)
        if secret:
            isKey = True
            print("Key exists: ", secret)
        else:
            isKey = False
            secret = os.getenv('SECRET')  # Default value
            print("Key is missing or empty, setting default secret.")

        if 'session_secret' in session:
            try:
                

                client = get_client(None,session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            except Exception as e:
                userInfo = None      
        elif bool(key):
            try:
                client = get_client(None,key,None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            except Exception as e:
                userInfo = None  
        else:
            userInfo = None       

        client = get_client(None,None,secret)
        databases = Databases(client)
        # Query for non-pinned posts
        non_pinned = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.not_equal("removed", True),
                Query.not_equal("pinned", True),
                Query.select(['postId']),
            ]
        )
        total = non_pinned.get('total')

        # Query for each category
        Updates = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.equal('category', 'Updates'),
                Query.not_equal("removed", True),
                Query.not_equal("pinned", True),
                Query.select(['postId']),
            ]
        ).get('total')

        General = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.equal('category', 'General'),
                Query.not_equal("removed", True),
                Query.not_equal("pinned", True),
                Query.select(['postId']),
            ]
        ).get('total')

        Suggestion = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.equal('category', 'Suggestion'),
                Query.not_equal("removed", True),
                Query.not_equal("pinned", True),
                Query.select(['postId']),
            ]
        ).get('total')

        Question = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.equal('category', 'Question'),
                Query.not_equal("removed", True),
                Query.not_equal("pinned", True),
                Query.select(['postId']),
            ]
        ).get('total')

        Discussion = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.equal('category', 'Discussion'),
                Query.not_equal("removed", True),
                Query.not_equal("pinned", True),
                Query.select(['postId']),
            ]
        ).get('total')

        Feedback = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.equal('category', 'Feedback'),
                Query.not_equal("removed", True),
                Query.not_equal("pinned", True),
                Query.select(['postId']),
            ]
        ).get('total')

        # Combine into categories
        categories = [
            {"name": "All", "posts": f"{total} posts"},
            {"name": "Updates", "posts": f"{Updates} posts"},
            {"name": "General", "posts": f"{General} posts"},
            {"name": "Suggestion", "posts": f"{Suggestion} posts"},
            {"name": "Question", "posts": f"{Question} posts"},
            {"name": "Discussion", "posts": f"{Discussion} posts"},
            {"name": "Feedback", "posts": f"{Feedback} posts"}
        ]
        for post in non_pinned.get("documents", []):  # Safely access "documents"
            user_id = post.get("userId")
            if not user_id:
                continue  # Skip if userId is missing

            # Fetch user details
            teams = Teams(client)

            client = get_client(None,None,secret)
            tem = teams.list_memberships(
                team_id = os.getenv('MODS'),
            )

                # Extract all userIds from the memberships
            team_user_ids = {member.get("userId") for member in tem.get("memberships", [])}

            # Check if user_id exists in the team
            if user_id in team_user_ids:
                print(f"User {user_id} is in the team.")
                isMod = True
                # Perform actions for team members
            else:
                print(f"User {user_id} is NOT in the team.")
                isMod = False
                # Perform actions for non-team members

            added = format_relative_time(post.get("added"))

            user = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('Users'),
                document_id= user_id,
                queries=[
                    Query.select(['username','userId',"pfp"]),
                ]
            )

            posts.append({
                "id": post.get("postId"),
                "title": post.get("title"),
                "content": post.get("content"),
                "category": post.get("category"),
                "time": added,  # Use relative time
                "author": user.get('username'),
                'authorAvatar': user.get('pfp'),
                'likes': 149,
                'comments': 90,
                'userUnliked':True,
                "pinned": False,
                "isMod": isMod,
            })   

        if isKey:
            return jsonify({
                "categories": categories,
                "total": total, # Use total_for_category to determine hasMore
                "userInfo":userInfo
            }),200
        else:

            return render_template('posts.html',categories=categories,userInfo=userInfo,total=total)


def format_relative_time(iso_timestamp):
    if not iso_timestamp:
        return "unknown time"

    try:
        # Parse the ISO timestamp
        added_time = datetime.fromisoformat(iso_timestamp.replace("Z", "+00:00"))
    except ValueError:
        # Handle invalid timestamp format
        print(f"Invalid timestamp format: {iso_timestamp}")
        return "invalid time"

    # Ensure current time is offset-aware
    current_time = datetime.now(timezone.utc)

    # Calculate the difference
    delta = relativedelta(current_time, added_time)

    # Determine the most significant time unit
    if delta.years > 0:
        return f"{delta.years} year{'s' if delta.years > 1 else ''} ago"
    elif delta.months > 0:
        return f"{delta.months} month{'s' if delta.months > 1 else ''} ago"
    elif delta.days > 0:
        return f"{delta.days} day{'s' if delta.days > 1 else ''} ago"
    elif delta.hours > 0:
        return f"{delta.hours} hour{'s' if delta.hours > 1 else ''} ago"
    elif delta.minutes > 0:
        return f"{delta.minutes} minute{'s' if delta.minutes > 1 else ''} ago"
    else:
        return "just now"

@app.route('/api/posts', methods=['GET','POST'])
def get_posts():
    category = request.args.get('category', 'All')
    page = int(request.args.get('page', 1))
    per_page = 20
    isLiked = False
    isUnliked = False


    valid_folders = ["General", "Suggestion", "Discussion", "Feedback","Question","All","Updates"]
    if category not in valid_folders:
        return jsonify({"error": "Invalid Category", "success": False}), 404

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
        
    posts = []
    isKey = bool(secret)

    # Process secret or key for authentication
    if not secret:
        secret = os.getenv('SECRET')  # Default value if secret is missing

    userInfo = None
    if 'session_secret' in session:
        try:
            client = get_client(None,session["session_secret"], None)
            account = Account(client)
            acc = account.get()
            userInfo = get_acc_info(acc)

        except Exception:
            userInfo = None
    elif isKey:
        try:
            client = get_client(None,key, None)
            account = Account(client)
            acc = account.get()
            userInfo = get_acc_info(acc)

        except Exception:
            userInfo = None

    # Fetch posts from database
    try:
        client = get_client(None,None, secret)
        databases = Databases(client)
        # Fetch posts for the current page
        if category == 'All':
            non_pinned = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Posts'),
                queries=[
                    Query.order_desc('added'),
                    Query.not_equal("removed", True),
                    Query.not_equal("pinned", True),
                    Query.limit(per_page),
                    Query.offset((page - 1) * per_page),
                    Query.select(['postId', 'userId', 'title', 'content', 'category', 'added']),
                ]
            )
        else:
             non_pinned = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Posts'),
                queries=[
                    Query.order_desc('added'),
                    Query.equal('category',category),
                    Query.not_equal("removed", True),
                    Query.not_equal("pinned", True),
                    Query.limit(per_page),
                    Query.offset((page - 1) * per_page),
                    Query.select(['postId', 'userId', 'title', 'content', 'category', 'added']),
                ]
            )


        for post in non_pinned.get("documents", []):
            user_id = post.get("userId")
            print(post.get('postId'))

            comments = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_COMMENTS'),
                queries=[
                    Query.equal('postId', post.get('postId')),
                    Query.select(['postId']),
                ]
            )

            likes = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_LIKES'),
                queries=[
                    Query.equal('isLiked', True),
                    Query.equal('postId', post.get('postId')),
                    Query.select(['postId']),
                ]
            )

            # Reset flags
            isLiked = False
            isUnliked = False

            if not user_id:
                continue

            # Check if user is a moderator
            teams = Teams(client)
            memberships = teams.list_memberships(
                team_id=os.getenv('MODS')
            )
            team_user_ids = {member.get("userId") for member in memberships.get("memberships", [])}
            isMod = user_id in team_user_ids

            # Fetch user details
            user = databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                document_id=user_id,
                queries=[Query.select(['username', 'userId',"pfp"])]
            )

            if userInfo:
                IsUserLiked = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('POST_LIKES'),
                    queries=[
                        Query.equal('postId', post.get("postId")),
                        Query.equal('isLiked', True),
                        Query.equal('userId', acc.get("$id")),
                        Query.select(['userId'])
                    ]
                )

                IsUserunLiked = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('POST_LIKES'),
                    queries=[
                        Query.equal('postId', post.get("postId")),
                        Query.equal('isLiked', False),
                        Query.equal('userId', acc.get("$id")),
                        Query.select(['userId'])
                    ]
                )

                if IsUserLiked['total'] > 0:
                    isLiked = True
                elif IsUserunLiked['total'] > 0:
                    isUnliked = True

            posts.append({
                "id": post.get("postId"),
                "title": post.get("title"),
                "content": post.get("content"),
                "category": post.get("category"),
                "time": format_relative_time(post.get("added")),
                "author": user.get('username'),
                'authorAvatar': user.get('pfp'),
                'likes': likes['total'],
                'comments': comments['total'],
                "pinned": False,
                "isMod": isMod,
                "userLiked": isLiked,
                "userUnliked": isUnliked 
            })

        # Fetch total number of posts for the category
        category_query = []
        if category != 'All':
            category_query.append(Query.equal("category", category))

        all_categories = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            queries=[
                Query.not_equal("removed", True),
                *category_query,  # Apply category filter if not "All"
                Query.select(['category'])
            ]
        )
        total_for_category = len(all_categories.get("documents", []))

    except Exception as e:
        print(f"Error fetching posts: {e}")
        total_for_category = 0

    # Response
    return jsonify({
        "posts": posts,
        "hasMore": (page * per_page) < total_for_category  # Use total_for_category to determine hasMore
    })

@app.route('/api/posts', methods=['POST'])
@limiter.limit("2 per minute") 
def create_post():
    data = request.json
    new_post = request.json
    key = data.get('key')
    secret = data.get('secret')
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    try:
        if 'session_secret' in session:
            

            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)
            
        elif bool(key):
            client = get_client(None,key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        else:
            return jsonify({'success': False, 'message': 'Authentication Fail'}),401
    except Exception as e:
        return jsonify({'success': False, 'message': 'Authentication Fail'}),401
    
    
    try:
        valid_folders = ["General", "Suggestion", "Discussion", "Feedback","Question"]
        if data.get('category') not in valid_folders:
            return jsonify({"error": "Invalid Category", "success": False}), 400
        client = get_client(None,key,secret)
        databases = Databases(client)
        # In a real application, you would save this to a database
        # For now, we'll just return the post as if it was created
        mentions = re.findall(r'@(\w+)', data.get('content', ''))

        did = ID.unique()
        databases.create_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id= os.getenv('Posts'),
            document_id=did,
            data={
                'postId':did,
                'userId':acc.get("$id"),
                'title': data.get('title'),
                'content': data.get('content'),
                'category': data.get('category'),
                'added':iso_timestamp,
                'pinned': False,
            }
        )

        for usernames in mentions:
            user = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Users'),
                queries=[
                    Query.equal('username',usernames),
                    Query.select('userId'),
                    Query.limit(1)
                ]
            )

            print(user['documents'][0]['userId'])

            nid= ID.unique()
            rank_points(client,acc,"post")

            make_nofification = databases.create_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Notifications'),
                document_id=nid,
                data={
                    'notificationId':nid,
                    'userId':user['documents'][0]['userId'],
                    'realtedPostId':did,
                    'message':f"You have been mentioned on post {data.get('title')}",
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                }
            )

            print(user['documents'][0]['userId'])
        new_post['id'] = did  # This would normally be generated by the database
        new_post['author'] = acc.get("name"),
        new_post['authorAvatar'] = userInfo.get('pfp')
        new_post['likes'] = 0
        new_post['comments'] = 0
        new_post['time'] = 'Just now'
        new_post['pinned'] = False
        new_post['isMod'] = False
        return jsonify(new_post), 201

    except Exception as e:
        return jsonify({'success': False, 'message': e}),500
    
@app.route("/api/post/comment/reply/<comment_id>",methods=['POST'])
def reply_post_comment(comment_id):
    data = request.json
    reply_content = data.get('content')
    secret = request.args.get('secret')
    key = request.args.get('key')
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
         

         client = get_client(None,session["session_secret"],None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)
         
    elif bool(key):
         client = get_client(None,key,None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)

    else:
       return jsonify({'success': False, 'message':"Unauthorized"}), 401
    

    if not comment_id or not reply_content:
        return jsonify({"error": "commentId and content are required"}), 400
    
    if comment_filter(reply_content):
        remove = True
    else:
        remove = False

    try:
        client = get_client(None,None,secret)
        databases = Databases(client)
        
        find_comment = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('POST_COMMENTS'),
            queries=[
                Query.equal("postCommentId", comment_id),  # Ensure `anii` is properly defined
                Query.select(["postCommentId","content","userId","postId"]),
            ]
        )

        post = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            document_id=find_comment['documents'][0]['postId'],
            queries=[
                Query.select(["title"])
            ]
        )

        if find_comment['total'] <= 0:
            return jsonify({"error": "Comment Not Found"}), 404

        rid =ID.unique()
        iso_timestamp = datetime.now(timezone.utc).isoformat()

        reply = databases.create_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('POST_COMMENTS_REPLYS'),
            document_id=rid,
            data={
                "postCommentReplyId":rid,
                "userId":acc.get('$id'),
                "replyedPostCommentId":comment_id,
                "content":reply_content,
                "removed":remove,
                "added_date":iso_timestamp,
            }
        )
        rank_points(client,acc,'comment')

        nid= ID.unique()

        make_nofification_l = databases.create_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Notifications'),
                document_id=nid,
                data={
                    'notificationId':nid,
                    'userId':acc.get('$id'),
                    'realtedPostId':find_comment['documents'][0]['postId'],
                    'message':f"{acc.get('name')} replied to your comment on {post.get('title')}",
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                }
            )

        mentions = re.findall(r'@(\w+)', data.get('content', ''))

        for usernames in mentions:
            user = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Users'),
                queries=[
                    Query.equal('username',usernames),
                    Query.select('userId'),
                    Query.limit(1)
                ]
            )

            print(user['documents'][0]['userId'])

            nid= ID.unique()

            make_nofification = databases.create_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Notifications'),
                document_id=nid,
                data={
                    'notificationId':nid,
                    'userId':user['documents'][0]['userId'],
                    'relatedPostCommentId':find_comment['documents'][0]['postCommentId'],
                    'message':f"{acc.get('name')} mentioned you on post comment {find_comment['documents'][0]['content']}",
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                }
            )

            print(user['documents'][0]['userId'])

        # Create the new reply
        new_reply = {
            "id": rid,
            "avatar":f"{url_for('static', filename='placeholder.svg')}?height=32&width=32",
            "author": acc.get("name"),  # Generate a dummy author
            "time": "Just now",
            "content": reply_content
        }
        # Return the newly created reply
        return jsonify(new_reply), 201
    except Exception as e:
          return jsonify({"error": f"Error:{e}"}), 500
    
@app.route("/api/post/respond/<id>", methods=['POST'])
def like_post(id):
    # Get the JSON data from the request body
    data = request.json
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        
        key = session["session_secret"]

        client = get_client(None,session["session_secret"], None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)
        
    elif bool(key):
        client = get_client(None,key, None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)

    else:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401

    lid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(None,key, None)
    databases = Databases(client)

    # Extract the 'type' from the data
    response_type = data.get('type')

    isPost = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Posts'),
        document_id=id,
        queries=[Query.select(['postId', 'title', 'content', 'userId', 'category'])]
    )

    if isPost.get('postId'):
        try:
            isliked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_LIKES'),
                queries=[
                    Query.equal('postId', id),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['postLikeId', 'userId']),
                ]
            )
            print(isliked, "1011")
        except Exception as e:
            return e    

        # Check if 'type' is provided
        if response_type:
            # Process the request based on 'type' (like or dislike)
            if response_type == 'like':
                try:
                    if isliked['documents']:
                        # If documents exist, update the like status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_LIKES'),
                            document_id=isliked['documents'][0]['postLikeId'],  # Use the document ID here
                            data={
                                "postLikeId": isliked['documents'][0]['postLikeId'],
                                "userId": acc.get("$id"),
                                "postId": id,
                                "added_date": iso_timestamp,
                                "isLiked": True,
                            }
                        )
                    else:
                        # Create a new like
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_LIKES'),
                            document_id=lid,
                            data={
                                "postLikeId": lid,
                                "userId": acc.get("$id"),
                                "postId": id,
                                "added_date": iso_timestamp,
                                "isLiked": True,
                            }
                        )

                        rank_points(client,acc,'Like',isPost.get('userId'))

                    return jsonify({"message": "Post liked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e}"}), 500
            elif response_type == 'dislike':
                try:
                    if isliked['documents']:
                        # If documents exist, update the dislike status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_LIKES'),
                            document_id=isliked['documents'][0]['postLikeId'],  # Use the document ID here
                            data={
                                "postLikeId": isliked['documents'][0]['postLikeId'],
                                "userId": acc.get("$id"),
                                "postId": id,
                                "added_date": iso_timestamp,
                                "isLiked": False,
                            }
                        )
                    else:
                        # Create a new dislike entry
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_LIKES'),
                            document_id=lid,
                            data={
                                "postLikeId": lid,
                                "userId": acc.get("$id"),
                                "postId": id,
                                "added_date": iso_timestamp,
                                "isLiked": False,
                            }
                        )

                        rank_points(client,acc,'Like')

                    return jsonify({"message": "Post disliked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e}"}), 500
            else:
                return jsonify({"message": "Invalid type!"}), 400
        else:
            return jsonify({"message": "Type is required!"}), 400
    else:
        return jsonify({"message": "Post Not Found!"}), 404     
    
@app.route("/api/post/comment/respond/<id>", methods=['POST'])
def like_post_comment(id):
    # Get the JSON data from the request body
    data =  request.json
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    isKey = bool(secret)
    
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        
        key = session["session_secret"]

        client = get_client(None,session["session_secret"], None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)
        
    elif bool(key):
        client = get_client(None,key, None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)

    else:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401

    lid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(None,key, None)
    databases = Databases(client)

    # Extract the 'type' from the data
    response_type = data.get('type')

    isAnime = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('POST_COMMENTS'),
        document_id=id,
        queries=[Query.select(['postId','userId'])]
    )

    if isAnime.get('postId'):
        try:
            isliked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_COMMENTS_LIKES'),
                queries=[
                    Query.equal('postCommentId', id),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['postCommentLikesId', 'userId']),
                ]
            )
        except Exception as e:
            return e    

        # Check if 'type' is provided
        if response_type:
            # Process the request based on 'type' (like or dislike)
            if response_type == 'like':
                try:
                    if isliked['documents']:
                        # If documents exist, update the like status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_COMMENTS_LIKES'),
                            document_id=isliked['documents'][0]['postCommentLikesId'],  # Use the document ID here
                            data={
                                "postCommentLikesId": isliked['documents'][0]['postCommentLikesId'],
                                "userId": acc.get("$id"),
                                "postCommentId": id,
                                "liked": True,
                            }
                        )
                    else:
                        # Create a new like
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_COMMENTS_LIKES'),
                            document_id=lid,
                            data={
                                "postCommentLikesId": lid,
                                "userId": acc.get("$id"),
                                "postId":isAnime.get('postId'),
                                "postCommentId": id,
                                "liked": True,
                            }
                        )

                        rank_points(client,acc,'Like',isAnime.get('userId'))

                    return jsonify({"message": "Post liked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e},lol"}), 500
            elif response_type == 'dislike':
                try:
                    if isliked['documents']:
                        print(isliked['documents'][0]['postCommentLikesId'])
                        # If documents exist, update the like status
                        like = databases.update_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_COMMENTS_LIKES'),
                            document_id=isliked['documents'][0]['postCommentLikesId'],  # Use the document ID here
                            data={
                                "postCommentLikesId": isliked['documents'][0]['postCommentLikesId'],
                                "userId": acc.get("$id"),
                                "postCommentId": id,
                                "post_comment": id,
                                "liked": False,
                            }
                        )
                    else:
                        # Create a new like
                        like = databases.create_document(
                            database_id=os.getenv('DATABASE_ID'),
                            collection_id=os.getenv('POST_COMMENTS_LIKES'),
                            document_id=lid,
                            data={
                                "postCommentLikesId": lid,
                                "userId": acc.get("$id"),
                                "postCommentId": id,
                                "post_comment": id,
                                "postId":isAnime.get('postId'),
                                "liked": False,
                            }
                        )

                        rank_points(client,acc,'Like',isAnime.get('userId'))

                    return jsonify({"message": "Post disliked!"}), 200
                except AppwriteException as e:
                    return jsonify({"message": f"Something went wrong: {e},lol2"}), 500
            else:
                return jsonify({"message": "Invalid type!"}), 400
        else:
            return jsonify({"message": "Type is required!"}), 400
    else:
        return jsonify({"message": "Post Not Found!"}), 404        

@app.route('/post/<post_id>', methods=['GET','POST'])
def view_post(post_id):
    try:
        # Get query parameters
        secret = None
        key = None

        isApi, key, secret, userInfo, acc = verify_api_request(request)

        if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
        
        nid = request.args.get('nid')
        
        # Handle secret key logic
        isKey = bool(secret)
        if secret:
            print("Key exists: ", secret)
        else:
            isKey = False
            secret = os.getenv('SECRET')
            print("Key is missing or empty, setting default secret.")

        # Initialize userInfo
        userInfo = None
        
        # Handle session authentication
        if 'session_secret' in session:
            key = session["session_secret"]
            client = get_client(None,session["session_secret"], None)
            account = Account(client)
            acc = account.get()
            
            userInfo = get_acc_info(acc)

        elif bool(key):
            client = get_client(None,key, None)
            account = Account(client)
            acc = account.get()
            
            userInfo = get_acc_info(acc)

        # Get database client
        client = get_client(None,key, secret)
        databases = Databases(client)

        # Fetch post data
        result = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            document_id=post_id,
            queries=[
                Query.select(['postId', 'title', 'content', 'userId', 'category', 'added'])
            ]
        )

        # Check moderator status
        user_id = result.get("userId", "")
        client = get_client(None,None, secret)
        teams = Teams(client)
        tem = teams.list_memberships(team_id=os.getenv('MODS'))
        team_user_ids = {member.get("userId") for member in tem.get("memberships", [])}
        isMod = user_id in team_user_ids

        # Format timestamp
        added = format_relative_time(result.get("added"))

        # Initialize like status
        isLiked = False
        isUnliked = False
        
        # Check user's like status if logged in
        if userInfo:
            IsUserLiked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_LIKES'),
                queries=[
                    Query.equal('postId', result.get("postId")),
                    Query.equal('isLiked', True),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['userId'])
                ]
            )

            IsUserunLiked = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_LIKES'),
                queries=[
                    Query.equal('postId', result.get("postId")),
                    Query.equal('isLiked', False),
                    Query.equal('userId', acc.get("$id")),
                    Query.select(['userId'])
                ]
            )

            # Handle notification
            if nid:
                ns = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Notifications'),
                    queries=[Query.equal('notificationId', nid)]
                )

                if ns.get('total', 0) > 0:
                    databases.update_document(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('Notifications'),
                        document_id=nid,
                        data={"isRead": True}
                    )

            isLiked = IsUserLiked.get('total', 0) > 0
            isUnliked = IsUserunLiked.get('total', 0) > 0

        # Get post author info
        user = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Users'),
            document_id=user_id,
            queries=[Query.select(['username', 'userId',"pfp"])]
        )

        # Get comments
        comms = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('POST_COMMENTS'),
            queries=[
                Query.equal('postId', post_id),
                Query.not_equal('removed', True),
                Query.select(['postCommentId', 'userId', 'postId', 'content', 'added_date'])
            ]
        )

        # Get likes count
        likes = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('POST_LIKES'),
            queries=[
                Query.equal('isLiked', True),
                Query.equal('postId', result.get('postId')),
                Query.select(['postId'])
            ]
        )

        # Process comments
        comments = []
        for cm in comms.get('documents', []):
            isLikedz = False
            isUnlikedz = False
            usercm = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                queries=[
                    Query.equal('userId', cm.get('userId', '')),
                    Query.select(['username', 'userId',"pfp"])
                ]
            )

            replies = []

            reply = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_COMMENTS_REPLYS'),
                queries=[
                    Query.equal("replyedPostCommentId", cm.get('postCommentId', '')),
                    Query.not_equal("removed", True),
                    Query.select(['userId','content','$id','$createdAt'])
                ]
            )

            for rs in reply.get('documents', []):
                userz = databases.get_document(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Users'),
                    document_id=rs.get('userId'),
                    queries=[Query.select(['username', 'userId',"pfp"])]
                )
                data = {
                    "id":rs.get('$id'),
                    "avatar":userz.get('pfp'),
                    "author":userz.get('username', "Unknown"),
                    "time":format_relative_time(rs.get('$createdAt')),
                    "content":rs.get('content'),
                }
                replies.append(data)

            likesz = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_COMMENTS_LIKES'),
                queries=[
                    Query.equal('liked', True),
                    Query.equal('postCommentId', cm.get('postCommentId')),
                    Query.select(['postCommentId']),
                ]
            )
            dislikes = databases.list_documents(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('POST_COMMENTS_LIKES'),
                        queries=[
                            Query.equal('liked', False),
                            Query.equal('postCommentId', cm.get('postCommentId')),
                            Query.select(['postCommentId']),
                        ]
                    )
            if userInfo:
                    IsUserLikedz = databases.list_documents(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('POST_COMMENTS_LIKES'),
                        queries=[
                            Query.equal('postCommentId', cm.get('postCommentId')),
                            Query.equal('liked', True),
                            Query.equal('userId', acc.get("$id")),
                            Query.select(['userId'])
                        ]
                    )

                    IsUserunLikedz = databases.list_documents(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('POST_COMMENTS_LIKES'),
                        queries=[
                            Query.equal('postCommentId',cm.get('postCommentId')),
                            Query.equal('liked', False),
                            Query.equal('userId', acc.get("$id")),
                            Query.select(['userId'])
                        ]
                    )
                            

                    if IsUserLikedz['total'] > 0:
                        isLikedz = True
                    elif IsUserunLikedz['total'] > 0:
                        isUnlikedz = True

            if usercm.get('documents'):
                        comment_data = {
                            "id": cm.get('postCommentId', ''),
                            "author": usercm['documents'][0].get('username', ''),
                            'avatar': usercm['documents'][0].get('pfp'),
                            "content": cm.get('content', ''),
                            "isLiked":isLikedz,
                            "isUnliked":isUnlikedz,
                            "likes":likesz['total'],
                            "time": format_relative_time(cm.get('added_date')),
                            "replies":replies,
                        }
                        comments.append(comment_data)

        print(comments)
        # Prepare post data
        post = {
            'id': result.get("postId", ""),
            'title': result.get("title", ""),
            'content': result.get("content", ""),
            'author': user.get('username', ""),
            'authorAvatar': user.get('pfp'),
            'category': result.get("category", ""),
            'userLiked': bool(isLiked),
            'userUnliked': bool(isUnliked),
            'likes': likes.get('total', 0),
            'comments': comms.get('total', 0),
            'time': format_relative_time(result.get("added", ""))
        }

        if isKey:
            return jsonify({
                "post": post,
                "comments": comments, # Use total_for_category to determine hasMore
                "userInfo":userInfo
            }),200
        else:
            return render_template('post.html', 
                             post=post,
                             comments=comments,
                             userInfo=userInfo)

    except Exception as e:
        print(f"Error in view_post: {str(e)}")
        return jsonify({"success": False, "message": str(e)}), 500
    
@app.route('/post/comment/<post_id>', methods=['POST'])
def add_comment(post_id):
    data = request.json
    secret = request.args.get('secret')
    key = request.args.get('key')
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
         
         key = session["session_secret"]

         client = get_client(None,session["session_secret"],None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)
         
    elif bool(key):
         client = get_client(None,key,None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)

    else:
       return jsonify({'success': False, 'message':"Unauthorized"}), 401
    
    cid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(None,key,None)
    databases = Databases(client)


    if comment_filter(data.get('content')):
            remove = True
    else:
            remove = False

    comm = databases.create_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('POST_COMMENTS'),
        document_id=cid,
        data={
            'postCommentId':cid,
            'userId':acc.get("$id"),
            'postId':post_id,
            'content':data['content'],
            'removed':remove,
            'added_date':iso_timestamp,
        }
    )

    nid = ID.unique()

    result = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Posts'),
            document_id=post_id,
            queries=[
                Query.select(['userId','title'])
            ]
        )

    user_id = result.get("userId")

    usercm = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('Users'),
                queries=[
                    Query.equal('userId',user_id),
                    Query.select(['username','userId']),
                ]
            )


    make_nofification = databases.create_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Notifications'),
                document_id=nid,
                data={
                    'notificationId':nid,
                    'userId':user_id,
                    'realtedPostId':post_id,
                    'message':f"{acc.get('name')} commented on {result.get('title')}",
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                    'realtedPostId':post_id,
                    'relatedPostCommentId':cid,
                }
            )
    rank_points(client,acc,'comment')
    new_comment = {
        "id": cid,
        "author": acc.get("name"),  # In a real app, you'd get this from user authentication
        "avatar": f"{url_for('static', filename='placeholder.svg')}?height=32&width=32",
        "content": data['content'],
        "time": "Just now"
    }
    return jsonify(new_comment), 201    

@app.route('/anime/comment/',methods=['POST'])
@limiter.limit("2 per minute") 
def comment():
    data = request.json
    print(data)
    
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)
    print(f"ll{isApi}")  
    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
      
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
         key  = session["session_secret"]
         

         client = get_client(None,session["session_secret"],None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)

         
    elif bool(key):
         client = get_client(None,key,None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)

    else:
       return jsonify({'success': False, 'message':"Unauthorized"}), 401
    
    try:
        client = get_client(None,None,secret)
        databases = Databases(client)
        print(data.get('anime'))
        anii = data.get('anime')
        
        anime = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime'),
            queries=[
                Query.equal("mainId", anii),  # Ensure `anii` is properly defined
                Query.select(["animeId","english","romaji"])
            ]
        )
        if not anime['documents']:
            return jsonify({'success': False, 'message': "Anime not found"}), 404

        epxx = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime_Episodes'),
            queries=[
                Query.equal("animeId", [anime['documents'][0]['animeId']]),  # Pass the value as a list
                Query.equal("number", [data.get('ep')]),  # Pass the value as a list
            ]
        )

        cid = ID.unique()
        iso_timestamp = datetime.now(timezone.utc).isoformat()
        

        client = get_client(None,key,None)
        databases = Databases(client)

        if comment_filter(data.get('content')):
            remove = True
        else:
            remove = False

        result = databases.create_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments'),
            document_id=cid,
            data={
                "commentId": cid,
                "userId": acc.get("$id"),
                "animeId": data.get('anime'),
                'episodeId':epxx['documents'][0]['$id'],
                "epNumber":data.get('ep'),
                "comment" : data.get('content'),
                "spoiller":data.get('spoiller'),
                "hidden":False,
                "removed":remove,
                "pinned":False,
                "added_date":iso_timestamp,
            }
        )

        rank_points(client,acc,'comment')


        mentions = re.findall(r'@(\w+)', data.get('content', ''))

        for usernames in mentions:
            user = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Users'),
                queries=[
                    Query.equal('username',usernames),
                    Query.select('userId'),
                    Query.limit(1)
                ]
            )

            print(user['documents'][0]['userId'])

            nid= ID.unique()

            make_nofification = databases.create_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Notifications'),
                document_id=nid,
                data={
                    'notificationId':nid,
                    'userId':user['documents'][0]['userId'],
                    'relatedEpId':cid,
                    'message':f"{acc.get('name')} mentioned you on anime {anime['documents'][0]['english'] if anime['documents'][0]['english'] is not None else anime['documents'][0]['romaji']}",
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                }
            )

            print(user['documents'][0]['userId'])

        data = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "commentId": cid,
            "comment" : data.get('content'),
        }

        return jsonify({'success': True, 'message': "Added","data":data}), 200

        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/anime/comments/reply', methods=['POST'])
def post_reply():
    data = request.get_json()  # Get JSON data from the request
    comment_id = data.get('commentId')
    reply_content = data.get('content')
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
         

         client = get_client(None,session["session_secret"],None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)
         
    elif bool(key):
         client = get_client(None,key,None)
         account = Account(client)

         acc = account.get()
         
         userInfo = get_acc_info(acc)
         
    else:
       return jsonify({'success': False, 'message':"Unauthorized"}), 401
    

    if not comment_id or not reply_content:
        return jsonify({"error": "commentId and content are required"}), 400
    
    if comment_filter(reply_content):
        remove = True
    else:
        remove = False

    try:
        client = get_client(None,None,secret)
        databases = Databases(client)
        
        find_comment = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments'),
            queries=[
                Query.equal("commentId", comment_id),  # Ensure `anii` is properly defined
                Query.select(["commentId","comment","userId","episodeId","animeId"]),
            ]
        )

        anime = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime'),
            document_id=find_comment['documents'][0]['animeId'],
            queries=[
                Query.select(["english","romaji"])
            ]
        )

        if find_comment['total'] <= 0:
            return jsonify({"error": "Comment Not Found"}), 404

        rid =ID.unique()
        iso_timestamp = datetime.now(timezone.utc).isoformat()

        reply = databases.create_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Replys'),
            document_id=rid,
            data={
                "episodeCommentReplyId":rid,
                "userId":acc.get('$id'),
                "replyEpisodeCommentId":comment_id,
                "content":reply_content,
                "removed":remove,
                "added_date":iso_timestamp,
            }
        )
        rank_points(client,acc,'comment')

        nid= ID.unique()

        make_nofification_l = databases.create_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Notifications'),
                document_id=nid,
                data={
                    'notificationId':nid,
                    'userId':acc.get('$id'),
                    'relatedEpId':find_comment['documents'][0]['episodeId'],
                    'message':f"{acc.get('name')} replied to your comment on {anime.get('english') if anime.get('english') is not None else anime.get('romaji')}",
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                }
            )

        mentions = re.findall(r'@(\w+)', data.get('content', ''))

        for usernames in mentions:
            user = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Users'),
                queries=[
                    Query.equal('username',usernames),
                    Query.select('userId'),
                    Query.limit(1)
                ]
            )

            print(user['documents'][0]['userId'])

            nid= ID.unique()

            make_nofification = databases.create_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id= os.getenv('Notifications'),
                document_id=nid,
                data={
                    'notificationId':nid,
                    'userId':user['documents'][0]['userId'],
                    'relatedCommentId':find_comment['documents'][0]['commentId'],
                    'message':f"{acc.get('name')} mentioned you on anime comment {find_comment['documents'][0]['comment']}",
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                }
            )

            print(user['documents'][0]['userId'])

        # Create the new reply
        new_reply = {
            "id": rid,
            "author": acc.get("name"),  # Generate a dummy author
            "time": "Just now",
            "content": reply_content
        }
        # Return the newly created reply
        return jsonify(new_reply), 201
    except Exception as e:
          return jsonify({"error": f"Error:{e}"}), 500
# Simulated data (replace with database queries in a real application
   
@app.route('/profile',methods=['POST','GET'])
@app.route('/user/<path:subpath>',methods=['GET','POST'])
@login_required
def user(subpath=None):
    process_id = request.args.get('process_id')
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
            
    userInfo = get_user_info(key,secret)

    if bool(secret):
        return jsonify(userInfo)
    else:
        return render_template('profile.html',userInfo=userInfo, process_id=process_id)
@app.route('/api/profile',methods=['POST','GET'])
def profile():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401

    userInfo = get_user_info(key,secret)
 
    return jsonify(userInfo)
@app.route('/api/settings',methods=['POST','GET'])
def settings():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    userInfo = get_user_info(key, secret)
    isKey = bool(secret)

    if isKey:
        print("Key exists: ", secret)
    else:
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    # Initialize Appwrite client and database
    client = get_client(None,None, secret)
    databases = Databases(client)

    # Query the settings
    try:
        settings_response = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('SETTINGS'),
            queries=[
                Query.order_desc("$updatedAt"),
                Query.equal("userId", userInfo.get('userId')),
            ]
        )
    except Exception as e:
        print(f"Error querying database: {e}")
        return jsonify({
            "error": "Failed to fetch settings. Please try again later."
        }), 500

    # Check if any documents exist and extract data
    if settings_response.get('total', 0) > 0 and settings_response.get('documents'):
        settings_data = settings_response['documents'][0]  # Safely get the first document
        data = {
            "defaultComments": (
                'true' if settings_data.get('defaultComments') is True 
                else 'false' if settings_data.get('defaultComments') is False 
                else settings_data.get('defaultComments')
            ),
            "defaultLang": (
                'japanese' if settings_data.get('defaultLang') == True
                else 'english' if settings_data.get('defaultLang') == False
                else 'japanese'  # Default to Japanese if invalid or missing
            ),
            "autoNext": settings_data.get('autoNext', True),
            "autoPlay": settings_data.get('autoPlay', False),
            "autoSkipIntro": settings_data.get('skipIntro', False),
            "autoSkipOutro": settings_data.get('skipOutro', False),
        }
    else:
        # Default values if no settings exist
        data = {
            "defaultComments": 'true',
            "defaultLang": 'japanese',
            "autoNext": True,
            "autoPlay": False,
            "autoSkipIntro": False,
            "autoSkipOutro": False,
        }

    # Return the response
    return jsonify({
        "data": data,
    }), 200

def check_expire(updated_date_str,expire_seconds):
    # Convert updated_date string to a timezone-aware datetime object
    updated_date = datetime.fromisoformat(updated_date_str)

    # Calculate expiration date
    expiration_date = updated_date + timedelta(seconds=expire_seconds)

    # Get current UTC time (timezone-aware)
    current_time = datetime.now(timezone.utc)

    # Check if expired
    is_expired = current_time > expiration_date
@app.route('/api/sync/info',methods=['POST','GET'])
def sync():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    userInfo = get_user_info(key, secret)
    isKey = bool(secret)

    if isKey:
        print("Key exists: ", secret)
    else:
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    # Initialize Appwrite client and database
    client = get_client(None,None, secret)
    databases = Databases(client)

    # Query the settings
    try:
        anilist_info = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANILIST_INFO'),
            queries=[
                Query.order_desc("$updatedAt"),
                Query.equal("user", userInfo.get('userId')),
            ]
        )
    except Exception as e:
        print(f"Error querying database: {e}")
        return jsonify({
            "error": "Failed to fetch settings. Please try again later."
        }), 500

    # Check if any documents exist and extract data
    if anilist_info.get('total', 0) > 0 and anilist_info.get('documents'):
        anilist_data = anilist_info['documents'][0]  # Safely get the first document
        updated = anilist_data.get('$updatedAt')
        access_token = decrypt(anilist_data.get('access_token'))
        expire = anilist_data.get('expire')

        is_expired = check_expire(updated,expire)

        print(updated)
        print(expire)
        data = {
            "anilist": access_token,
        }
    else:
        # Default values if no settings exist
        data = {
            "anilist": None,
            "mal": None,
        }

    # Return the response
    return jsonify({
        "data": data,
    }), 200

@app.route('/api/save/settings',methods=['POST'])
def save_settings():
    data = request.json
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    userInfo = get_user_info(key,secret)
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")


    client = get_client(None,None,secret)
    databases = Databases(client)

    if data.get('defaultComments') == 'true':
        comments = True
    else:
        comments =  False

    if data.get('defaultLang') == 'japanese':
        lang = True
    else:
        lang =  False

    settings = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('SETTINGS'),
            queries = [
                Query.order_desc("$updatedAt"),
                Query.equal("userId",userInfo.get('userId')),
                Query.select(['userId'])
            ] # optional
    )
    if settings['total'] > 0:
        lol=databases.update_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('SETTINGS'),
            document_id=userInfo.get('userId'),
            data={
                "userId":userInfo.get('userId'),
                "defaultComments":comments,
                "defaultLang":lang,
                "skipOutro":data.get('autoSkipOutro'),
                "skipIntro":data.get('autoSkipIntro'),
                "autoNext":data.get('autoNext'),
                "autoPlay":data.get('autoPlay'),
            }
    )
        print(lol)
    else:
        lol=databases.create_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('SETTINGS'),
            document_id=userInfo.get('userId'),
            data={
                "userId":userInfo.get('userId'),
                "defaultComments":comments,
                "defaultLang":lang,
                "skipOutro":data.get('autoSkipOutro'),
                "skipIntro":data.get('autoSkipIntro'),
                "autoNext":data.get('autoNext'),
                "autoPlay":data.get('autoPlay'),
            }
    )
        print(lol)
    return jsonify({
        "data": data,
    }),200
@app.route('/api/watchlist',methods=['POST','GET'])
def watchlist():
    page = int(request.args.get('page', 1))
    status = request.args.get('status', 'All')
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    per_page = 15
    limit = per_page * page
    userInfo = get_user_info(key,secret)
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")


    client = get_client(None,None,secret)
    databases = Databases(client)

    base_query_list = []
    offset = (page - 1) * per_page
    print(offset)

    base_query_list.append(Query.order_desc("$updatedAt"))
    base_query_list.append(Query.equal("userId",userInfo.get('userId')))
    base_query_list.append(Query.select(["itemId","userId","animeId","folder","lastUpdated"]))
    base_query_list.append(Query.offset(offset))
    base_query_list.append(Query.limit(15))

    if status != 'All':
        base_query_list.append(Query.equal('folder',status))

    watchlist = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Watchlist'),
            queries =base_query_list# optional
    )

    documents = watchlist.get('documents', [])

    watchlist_dataz = []
    
    for data in documents:
        aid = data.get('animeId')

        aniimeData = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime'),
            document_id=aid,
            queries = [
                Query.select(["mainId","english","romaji","lastUpdated","type","subbed","dubbed"]),
            ] # optional
        )

        img = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('ANIME_IMGS'),
            document_id=aniimeData.get('mainId'),
            queries=[
                Query.select(['cover'])
            ]
        )

        output = {
            "id": aniimeData.get("mainId"),
            "title": aniimeData.get("english"),
            "type": aniimeData.get("type"),
            "subbed": aniimeData.get("subbed"),
            "dubbed": aniimeData.get("dubbed"),
            "image": img.get("cover"),
            "status": data.get("folder"),
            "url":f'/watch/{aniimeData.get("mainId")}',
            "duration": "45m", "current": 0, "total": 3,
        }
        watchlist_dataz.append(output)
    
    total_pages = math.ceil(watchlist['total'] / per_page)
    
    return jsonify({
        "data": watchlist_dataz,
        "total_pages": total_pages,
        "current_page": page
    })

@app.route('/save/progress',methods=['POST'])
@limiter.limit("50 per minute")
def save_continue_watching():
    data = request.json
    print(data.get('episode'))
    secret = None
    key = None
    print(data)

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
            
    if not bool(secret):
        secret = os.getenv('SECRET')
    try:
        if 'session_secret' in session:
            
            key = session["session_secret"]

            client = get_client(None,session["session_secret"], None)
            account = Account(client)

            acc = account.get()

            userInfo = get_acc_info(acc)
            
        elif bool(key):
            client = get_client(None,key, None)
            account = Account(client)

            acc = account.get()

            userInfo = get_acc_info(acc)

    except Exception:
        userInfo = None

    if not userInfo:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401


    client = get_client(None,None,secret)
    databases = Databases(client)
    cid = ID.unique()

    server = data.get('category')

    if data.get('category') == 'raw':
        server = 'sub'

    search = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('CONTINUE_WATCHING'),
                queries=[
                    Query.equal("userId",acc.get("$id")),
                    Query.equal("animeId",data.get('anime')),
                    Query.select(['continueId']),
                ]
            )
    
    if search['total'] > 0:

        if data.get('duration') == 0:
                return request.json

    
        cid=search['documents'][0]['continueId']

        databases.update_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('CONTINUE_WATCHING'),
            document_id=cid,
            data={
                "continueId":cid,
                "userId":acc.get("$id"),
                "animeId":data.get('anime'),
                "episodeId":data.get('episode'),
                "removed":False,
                "server":data.get('vide'),
                "language":server,
                "currentTime":data.get('currentTime'),
                "duration":data.get('duration'),
            }
        )

    else:

        databases.create_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('CONTINUE_WATCHING'),
            document_id=cid,
            data={
                "continueId":cid,
                "userId":acc.get("$id"),
                "animeId":data.get('anime'),
                "episodeId":data.get('episode'),
                "removed":False,
                "server":data.get('vide'),
                "language":server,
                "currentTime":data.get('currentTime'),
                "duration":data.get('duration'),
            }
        )

    return request.json

@app.route('/api/continue-watching-home',methods=['GET','POST'])
def continue_watching_home():

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')

    try:
        if 'session_secret' in session:
            
            key = session["session_secret"]

            client = get_client(None,session["session_secret"], None)
            account = Account(client)

            acc = account.get()

            userInfo = get_acc_info(acc)
            
        elif bool(key):
            client = get_client(None,key, None)
            account = Account(client)

            acc = account.get()

            userInfo = get_acc_info(acc)

    except Exception:
        userInfo = None

    client = get_client(None,None,secret)
    databases = Databases(client)

    search = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('CONTINUE_WATCHING'),
                queries=[
                    Query.equal("userId",acc.get("$id")),
                    Query.order_desc('$updatedAt'),
                    Query.select(['continueId','animeId','episodeId','currentTime','duration','server','language']),
                    Query.limit(6)
                ]
            )
    animes = []
    for data in search['documents']:
        
        anime = data['animeId']

        aniimeData = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime'),
            document_id=anime,
            queries = [
                Query.select(["mainId","animeId","english","romaji","lastUpdated","type","subbed","dubbed"]),
            ] # optional
        )

        img = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('ANIME_IMGS'),
            document_id=aniimeData.get('mainId'),
            queries=[
                Query.select(['cover','banner'])
            ]
        )

        ep = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime_Episodes'),
            document_id=data['episodeId'],
            queries = [
                Query.select("number"),
            ] # optional
        )
        cv = new_url = img.get('cover').replace("medium", "large")

        
        ff=  {
                "title": aniimeData["english"] if aniimeData['english'] is not None else aniimeData["romaji"],
                "link":f"/watch/{aniimeData['mainId']}/{ep.get('number')}?server={data['server']}&lang={data['language']}",                
                "episode": ep.get('number'),
                "progress": f"{int(data['currentTime'] // 60)}:{int(data['currentTime'] % 60):02}",
                "duration": f"{int(data['duration'] // 60)}:{int(data['duration'] % 60):02}",
                "thumbnail": cv
            }
        animes.append(ff)
    return jsonify(animes)

@app.route('/api/continue-watching',methods=['GET','POST'])
def continue_watching():
    
    page = int(request.args.get('page', 1))
    per_page = 12
    start = (page - 1) * per_page
    end = start + per_page
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')
    userInfo = None
    try:
        if 'session_secret' in session:
            key = session["session_secret"]
            client = get_client(None,session["session_secret"], None)
            account = Account(client)
            acc = account.get()
            userInfo = get_acc_info(acc)

        elif bool(key):
            client = get_client(None,key, None)
            account = Account(client)
            acc = account.get()
            userInfo = get_acc_info(acc)

    except Exception:
        userInfo = None
    
    if userInfo is None:
        return jsonify({"error": "User not authenticated"}), 401

    client = get_client(None,None, secret)
    databases = Databases(client)

    search = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('CONTINUE_WATCHING'),
        queries=[
            Query.equal("userId", acc.get("$id")),
            Query.order_desc('$updatedAt'),
            Query.select(['continueId','animeId','episodeId','currentTime','duration','server','language']),
            Query.limit(per_page),
            Query.offset(start)
        ]
    )
    
    animes = []
    for data in search['documents']:
        anime = data['animeId']

        aniimeData = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime'),
            document_id=anime,
            queries=[
                Query.select(["mainId", "animeId", "english", "romaji", "lastUpdated", "type", "subbed", "dubbed"]),
            ]
        )

        img = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_IMGS'),
            document_id=aniimeData.get('mainId'),
            queries=[
                Query.select(['cover', 'banner'])
            ]
        )

        ep = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime_Episodes'),
            document_id=data['episodeId'],
            queries=[
                Query.select("number"),
            ]
        )

        ff = {
            "title": aniimeData["english"] if aniimeData['english'] is not None else aniimeData["romaji"],
            "link": f'/watch/{aniimeData["mainId"]}/{ep.get("number")}?server={data["server"]}&lang={data["language"]}',
            "episode": ep.get('number'),
            "progress": f"{int(data['currentTime'] // 60)}:{int(data['currentTime'] % 60):02}",
            "duration": f"{int(data['duration'] // 60)}:{int(data['duration'] % 60):02}",
            "thumbnail": img.get('cover')
        }
        animes.append(ff)

    # Paginate the results
    total_pages = math.ceil(search['total'] / per_page)
    
    return jsonify({
        "data": animes,
        "total_pages": total_pages,
        "current_page": page
    })

@app.route('/api/realtime/anime/<id>',methods=['GET','POST'])
@limiter.limit("5000 per minute")
def realtime_anime_info(id):
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')
    client = get_client(None,None,secret)
    databases = Databases(client)

    result = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime'),
        document_id=id,
        queries=[
            Query.select(["mainId","english","romaji"]),
        ]
    )

    if not result:
        return {"error": "Anime not found","success": False}, 404
    
    img = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('ANIME_IMGS'),
            document_id=result.get('mainId'),
            queries=[
                Query.select(['cover','banner'])
            ]
    )

    animeDetails = {
        "title":result.get("english") if result.get('english') is not None else result.get("romaji"),
        "cover":img.get('banner') if img.get('banner') is not None else img.get('cover'),
    }

    return animeDetails

@app.route('/api/notifications/<notification_type>', methods=['GET','POST'])
@limiter.limit("30 per minute")
def get_notifications(notification_type):
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")
    
    try:
        page = int(request.args.get('page', 1))
        if isApi:
            per_page = 10  # Number of notifications per page
        else:
            per_page = 6
        offset = (page - 1) * per_page

        if 'session_secret' in session:
            client = get_client(None,session["session_secret"], None)
            account = Account(client)
            acc = account.get()
        elif key:
            client = get_client(None,key, secret)
            account = Account(client)
            acc = account.get()
        else:
            return jsonify({'success': False, 'message': 'Authentication Failed'}), 401
        
        # Extract user info
        user_info = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "email": acc.get("email"),
        }
        
        # Initialize Databases client
        client = get_client(None,key, secret)
        databases = Databases(client)
        
        # Determine the `isCommunity` query based on notification_type
        is_community_query = {
            'community': Query.equal('isCommunity', True),
            'anime': Query.equal('isCommunity', False),
            'system': Query.is_null('isCommunity'),
        }.get(notification_type, Query.is_null('isCommunity'))  # Default to system if type is invalid
        
        # Query notifications
        notifications = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Notifications'),
            queries=[
                Query.limit(per_page + 1),  # Fetch one extra to check if there are more
                Query.offset(offset),
                Query.equal('userId', acc.get("$id")),
                Query.order_desc("time"),
                Query.select([
                    'notificationId', 'userId', 'relatedEpId', 'message',
                    'isRead', 'isCommunity', 'time','realtedPostId'
                ]),
                is_community_query,
            ],
        )

        noti = []
        for noa in notifications['documents'][:per_page]:  # Process only up to per_page items
            imgurl = "/static/placeholder.svg?height=200&width=100"
            url = '#'
            if noa.get('relatedEpId') and notification_type == 'anime':
                ep = databases.get_document(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime_Episodes'),
                    document_id=noa.get('relatedEpId'),
                    queries=[
                        Query.select(['number','animeId'])
                    ]
                )
                img = databases.list_documents(
                    database_id = os.getenv('DATABASE_ID'),
                    collection_id = os.getenv('ANIME_IMGS'),
                    queries=[
                        Query.equal('animeId',ep.get('animeId')),
                        Query.select(['cover'])
                    ]
                )

                anime = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=[
                        Query.equal("animeId", ep.get('animeId')),  # Ensure `anii` is properly defined
                        Query.select(["mainId"])
                    ]
                )

                url = f"/watch/{anime['documents'][0]['mainId']}/{ep.get('number')}?lang={re.search(r'\[(.*?)\]', noa.get('message')).group(1).lower() if re.search(r'\[(.*?)\]', noa.get('message')) else None}&nid={noa.get('notificationId')}&type=anime"
                
                imgurl = img['documents'][0]['cover']
            elif noa.get('relatedEpId') and notification_type == 'community':
                try:
                    ep = databases.get_document(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('Anime_Episodes'),
                        document_id=noa.get('relatedEpId'),
                        queries=[
                            Query.select(['number','animeId'])
                        ]
                    )
                    img = databases.list_documents(
                        database_id = os.getenv('DATABASE_ID'),
                        collection_id = os.getenv('ANIME_IMGS'),
                        queries=[
                            Query.equal('animeId',ep.get('animeId')),
                            Query.select(['cover'])
                        ]
                    )

                    anime = databases.list_documents(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('Anime'),
                        queries=[
                            Query.equal("animeId", ep.get('animeId')),  # Ensure `anii` is properly defined
                            Query.select(["mainId"])
                        ]
                    )

                    url = f"/watch/{anime['documents'][0]['mainId']}/{ep.get('number')}"
                except Exception as e:
                    if str(e) == "Document with the requested ID could not be found.":
                        url = "/#"
            elif noa.get('realtedPostId') and notification_type == 'community':
                try:
                    pcomment = databases.get_document(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('Posts'),
                        document_id=noa.get('realtedPostId'),
                        queries=[
                            Query.select(['title','$id'])
                        ]
                    )
                    url = f"/post/{pcomment.get('$id')}?nid={noa.get('notificationId')}"
                except Exception as e:
                    if str(e) == "Document with the requested ID could not be found.":
                        url = "/#"

                
            noti.append({
                "id":noa.get('notificationId'),
                "message":noa.get('message'),
                "time":format_relative_time(noa.get('time')),
                "link":url,
                "image":imgurl,
                "isCommunity":noa.get('isCommunity'),
                "isRead":noa.get('isRead'),
            })
        
        # Check if there are more notifications
        has_more = len(notifications['documents']) > per_page
        
        return jsonify({
            'notifications': noti,
            'has_more': has_more,
            'page': page,
        })
    
    except Exception as e:
        print(f"Error: {e}")
        return (f"Error: {e}")
    
@app.route('/api/notifications/count', methods=['GET','POST'])
@limiter.limit("30 per minute")
def get_notifications_count():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")
    
    try:
        page = int(request.args.get('page', 1))
        per_page = 6  # Number of notifications per page
        offset = (page - 1) * per_page

        if 'session_secret' in session:
            client = get_client(None,session["session_secret"], None)
            account = Account(client)
            acc = account.get()
        elif key:
            client = get_client(None,key, secret)
            account = Account(client)
            acc = account.get()
        else:
            return jsonify({'success': False, 'message': 'Authentication Failed'}), 401
        
        # Extract user info
        user_info = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "email": acc.get("email"),
        }
        
        # Initialize Databases client
        client = get_client(None,key, secret)
        databases = Databases(client)
        
        # Query notifications
        notifications = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Notifications'),
            queries=[
                Query.offset(offset),
                Query.equal('userId', acc.get("$id")),
                Query.equal('isRead', False),
                Query.select([
                    'notificationId'
                ]),
                Query.limit(10)
            ],
        )

        if notifications['total'] > 0 :
            if notifications['total'] > 10:
                total = '9+'
            else:
                total = notifications['total']
        else:
            total = 0

        return jsonify({
            'total': total,
            'success': True,
        })
    
    except Exception as e:
        print(f"Error: {e}")
        return (f"Error: {e}")
    
@app.route('/api/top/anime/',methods=['POST','GET'])
def get_anime_data():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')
    client = get_client(None,None, secret)
    databases = Databases(client)

    tab = request.args.get('tab', 'today')
    limit = request.args.get('limit')
    if tab == 'today':
        dy = 1
    elif tab == 'week':
        dy = 7
    else:
        dy = 30

    one_month_ago = datetime.now(pytz.UTC) - timedelta(days=dy)
    iso_timestamp = one_month_ago.isoformat()

    # Query for anime views
    key = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime_Views'),
        queries=[
            Query.select(['animeId']),
            Query.greater_than_equal('$createdAt', iso_timestamp),
            Query.limit(10000000)
        ]
    )

    anime_data = []
    # Create a list of all anime IDs
    keywords = [doc['animeId'] for doc in key['documents']]

    # Count occurrences of each anime ID
    keyword_counts = Counter(keywords)

    # Get the top 10 most common anime
    if limit:
        ll = int(limit)
    else:
        ll = 10
    top_10 = keyword_counts.most_common(ll)

    for top, count in top_10:
        # Fetch anime details
        result = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime'),
            document_id=top,
            queries=[
                Query.select([
                    "mainId", "english", "romaji", "native", "ageRating", 
                    "malScore", "averageScore", "duration", "studios", 
                    "genres", "season", "startDate", "status", 
                    "synonyms", "type", "year", "subbed", "dubbed", "description"
                ])
            ]
        )

        # Fetch anime cover image
        img = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_IMGS'),
            document_id=result.get('mainId'),
            queries=[
                Query.select(['cover'])
            ]
        )

        anime_data.append({
            "title": result.get('english') or result.get('romaji') or result.get('native'),
            "image": img.get('cover'),
            "url":f"/anime/{result.get('mainId')}",
            "stats":{
                    "subbed":result.get('subbed'),
                    "dubbed":result.get('dubbed')
            }
        })

    return jsonify(anime_data)

@app.route('/api/top/posts',methods=['POST','GET'])
def get_top_posts():
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
            
    client = get_client(None,None,os.getenv('SECRET'))
    databases = Databases(client)

    posts = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Posts'),
        queries=[
            Query.order_desc('added'),
            Query.select(['title','content','category','added','userId','postId']),
            Query.limit(6),
        ]
    )

    documents_top_posts = posts.get('documents', [])
    postz = []

    for post in documents_top_posts:
        comments = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('POST_COMMENTS'),
                queries=[
                    Query.equal('postId', post.get('postId')),
                    Query.select(['postId','userId']),
                ]
            )
        
        user = databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                document_id=post.get('userId'),
                queries=[Query.select(['username', 'userId',"pfp"])]
            )
        url = f'/post/{post.get("postId")}'
        postz.append({
                    "id": post.get("postId"),
                    "title": post.get("title"),
                    "content": post.get("content"),
                    "link":url,
                    "tag": post.get("category"),
                    "time": format_relative_time(post.get("added")),
                    'authorAvatar': user.get('pfp'),
                    'author':user.get('username'),
                    'comments':comments['total']
                })

    return jsonify({"posts": postz})

from time import time

@app.route('/countdowns',methods=['POST','GET'])
def countdowns():
    animes = []
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        try:
            client = get_client(None,session["session_secret"], None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(None,key, None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None  
    else:
        userInfo = None

    client = get_client(None,None, os.getenv('SECRET'))
    databases = Databases(client)

    topUpcoming = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime'),
        queries=[
            Query.equal("public", True),
            Query.is_not_null('airingAt'),
            Query.select(["mainId", "english", "romaji", "airingAt", "nextAiringEpisode"]),
            Query.order_asc("airingAt"),
            Query.limit(100)
        ]  # optional
    )

    count = topUpcoming.get('documents', [])
    animes = []
    current_time = int(time())  # Current time in seconds since epoch

    for anii in count:
        if anii.get('airingAt') and anii.get('airingAt') < (current_time - 24 * 3600):
            # Skip animes that aired more than 24 hours ago
            continue

        print(anii.get('mainId'), anii.get('english'))

        img = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_IMGS'),
            document_id=anii.get('mainId'),
            queries=[
                Query.select(['cover'])
            ]
        )

        animes.append({
            "id": anii.get("mainId"),
            "title": anii.get("english") if anii.get('english') is not None else anii.get("romaji"),
            "target_date": anii.get("airingAt") * 1000,
            "cover": img.get("cover"),
            "episode": anii.get("nextAiringEpisode"),
            "url":f"/anime/{anii.get("mainId")}",
        })

    return render_template('countdowns.html', animes=animes, userInfo=userInfo)

@app.route('/api/schedule', methods=['GET','POST'])
def get_schedule():
    date = request.args.get('date')  # Expected format: YYYY-MM-DD
    user_timezone = request.args.get('timezone', 'UTC')

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')

    # Initialize Appwrite client and databases service
    client = get_client(None,None, secret)
    databases = Databases(client)

    # Query data from Appwrite database
    try:
        response = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime'),
            queries=[
                Query.equal("public", True),
                Query.is_not_null("airingAt"),
                Query.select(["mainId", "english", "romaji", "airingAt", "nextAiringEpisode"]),
                Query.order_asc("airingAt"),
                Query.limit(60)
            ]
        )
        documents = response.get('documents', [])
    except Exception as e:
        return jsonify({"error": str(e)}), 500

    # Validate and prepare timezone
    try:
        user_tz = tz(user_timezone)
    except Exception as e:
        return jsonify({"error": f"Invalid timezone: {user_timezone}"}), 400

    # If date is provided, convert it to UTC timestamp range for that entire day in user's timezone
    if date:
        try:
            # Parse the date string into a datetime object in user's timezone
            local_start = datetime.strptime(date, '%Y-%m-%d').replace(
                hour=0, minute=0, second=0, microsecond=0,
                tzinfo=user_tz
            )
            local_end = local_start.replace(hour=23, minute=59, second=59)
            
            # Convert to UTC timestamps for filtering
            utc_start = local_start.astimezone(Fuck).timestamp()
            utc_end = local_end.astimezone(Fuck).timestamp()
        except ValueError:
            return jsonify({"error": "Invalid date format. Use YYYY-MM-DD"}), 400
    
    # Process data
    animes_by_date = {}
    for anime in documents:
        airing_timestamp = anime.get("airingAt")
        if not airing_timestamp:
            continue
        current_time = int(time())
        if anime.get('airingAt') and anime.get('airingAt') < (current_time - 24 * 3600):
            # Skip animes that aired more than 24 hours ago
            continue

        # Convert timestamp to user's timezone
        utc_time = datetime.utcfromtimestamp(airing_timestamp).replace(tzinfo=Fuck)
        local_time = utc_time.astimezone(user_tz)

        # Format date and time
        airing_date = local_time.strftime('%Y-%m-%d')
        airing_time = local_time.strftime('%H:%M')

        # Filter by date if provided
        if date:
            if not (utc_start <= airing_timestamp <= utc_end):
                continue

        # Prepare anime details
        anime_data = {
            "time": airing_time,
            "title": anime.get("english") or anime.get("romaji"),
            "episode": anime.get("nextAiringEpisode"),
        }

        # Group by adjusted date
        if airing_date not in animes_by_date:
            animes_by_date[airing_date] = []
        animes_by_date[airing_date].append(anime_data)

    return jsonify(animes_by_date)

def comment_filter(comment):
    """
    Determines if a comment should be blocked based on the presence of links, inappropriate content, or spam.
    """
    # Normalize the comment to lowercase
    comment = comment.lower().strip()

    # Patterns to detect inappropriate or malicious content
    patterns = [
        # Detect links (HTTP, HTTPS, "www", IPs, or obfuscated links)
        r"http[s]?:\/\/",       # Standard URLs (http:// or https://)
        r"www\.",               # URLs starting with "www."
        r"\b\d{1,3}(\.\d{1,3}){3}\b",  # IP addresses
        r"\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}\b",  # Email addresses
        r"t\.me|telegram|discord\.gg",  # Common spam platforms
        r"\.com|\.net|\.org|\.io|\.xyz",  # Domain extensions
        r"\b[a-z0-9]+(?:\s*\.\s*)[a-z]{2,}",  # Obfuscated domain links

        # Detect inappropriate content (explicit or harmful language)
        r"porn|p[o0]rn|p3orn|nude|sex|nsfw|snap leaks?",  # Explicit content
        r"rape|r[a@]p[e3]d|child",                      # Harmful/abusive content
        r"darkweb|drkweb|deepweb",                      # Dark web references
        r"blackmail|blkmail",                           # Blackmail terms
        r"teen[s]?|t[e3]ens?|loli",                     # Underage-related terms
        r"drug[s]?|meth|cocaine|weed|marijuana",        # Drug references
        r"\bkill|murder|suicide|self[-\s]?harm",        # Violence/self-harm
        r"\bscam|fraud|cheat|phishing",                 # Scam-related terms

        # Detect excessive suggestive emojis
        r"[🤤🥵😈🍑🍆💦🙈🔥]{4,}"  # Excessive emojis (4+ suggestive emojis in a row)
    ]

    # Check if any inappropriate pattern matches the comment
    for pattern in patterns:
        if re.search(pattern, comment):
            return True

    # Detect excessive non-alphanumeric characters (e.g., obfuscation like "p3rn!!!")
    non_alpha_ratio = sum(1 for char in comment if not char.isalnum() and not char.isspace()) / len(comment)
    if non_alpha_ratio > 0.4:  # Increased threshold to account for casual Gen-Z text styles
        return True

    # Detect spam-like patterns
    if re.search(r"(.)\1{4,}", comment):  # Excessive repetition of a single character
        return True

    # Word repetition (e.g., "buy buy buy" or overly repetitive words)
    words = comment.split()
    if len(words) > 4 and len(set(words)) / len(words) < 0.5:  # Only for longer comments
        return True

    # Whitelist for Gen-Z phrases and slang
    gen_z_phrases = [
        "fire", "🔥", "lit", "cool", "slay", "vibes", "goat", "bet", "fam", "sus", "lowkey", "no cap", 
        "drip", "bussin", "iconic", "periodt", "yeet", "fr", "deadass", "dope", "lol", "rofl", "omg", "😂", "💀"
    ]
    for phrase in gen_z_phrases:
        if phrase in comment:
            return False

    return False

def format_views(views):
    if views >= 1_000_000:
        return f"{views / 1_000_000:.1f}M Views"
    elif views >= 1_000:
        return f"{views / 1_000:.1f}k Views"
    elif views == 1:
        return f"1 View"
    else:
        return f"{views} Views"
    

def format_views_without_view(views):
    if views >= 1_000_000:
        return f"{views / 1_000_000:.1f}M"
    elif views >= 1_000:
        return f"{views / 1_000:.1f}k"
    elif views == 1:
        return f"1"
    else:
        return f"{views}"
    
def format_likes(views):
    if views >= 1_000_000:
        return f"{views / 1_000_000:.1f}M Likes"
    elif views >= 1_000:
        return f"{views / 1_000:.1f}k Likes"
    elif views == 1:
        return f"1 Like"
    else:
        return f"{views} Likes"
@app.route('/update/profile',methods=['POST'])
def update_profile():
    data = request.json
    print(data)

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')
    if not bool(key):
        key=session["session_secret"]

    if data.get('newPassword') and data.get('confirmNewPassword'):

        if not data.get('newPassword') == data.get('confirmNewPassword'):
            return jsonify({'success': False, 'message': 'Passwords Doesn\'t match'}), 404

        
        client = get_client(None,key,None)
        account = Account(client)

        result = account.update_password(
            password = data.get('confirmNewPassword'),
            old_password = data.get('oldPassword') # optional
        )

    return jsonify({'success': True, 'message': 'Done'}), 200

@app.route('/version')
def check_version():
        secret = os.getenv('SECRET')
        client = get_client(None,None,secret)
        databases = Databases(client)

        Notice = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Notices'),
            queries=[
                Query.order_desc('$createdAt'),
                Query.equal("Type","android"),
                Query.select(["version","Message","discord","telegram","discord","time","Title","reddit","build"]),
                Query.limit(1)
            ]
        )

        nData = Notice['documents'][0]

        print(nData)

        return nData
@app.route('/download')
def download():

    secret = os.getenv('SECRET')
    client = get_client(None,None, secret)
    databases = Databases(client)

    Notice = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Notices'),
        queries=[
            Query.order_desc('$createdAt'),
            Query.equal("Type", "android"),
            Query.select(["version","$updatedAt","build"]),
            Query.limit(1)
        ]
    )

    nData = Notice['documents'][0]

    android = {
       "version":nData['version'],
       "build":nData['build'],
       "latest":format_relative_time(nData['$updatedAt'])
    }

    return render_template("download.html",android=android)
@app.route('/download/apk')
def download_apk():
    secret = os.getenv('SECRET')
    client = get_client(None,None, secret)
    databases = Databases(client)

    Notice = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Notices'),
        queries=[
            Query.order_desc('$createdAt'),
            Query.equal("Type", "android"),
            Query.select(["downloadUrl","version","build"]),
            Query.limit(1)
        ]
    )

    nData = Notice['documents'][0]
    download_url = nData['downloadUrl']

    # Fetch APK from internal/local server
    headers = {"User-Agent": "ProxyServer"}
    response = requests.get(download_url, headers=headers, stream=True)

    if response.status_code != 200:
        return "Error fetching the file", 500

    return Response(
        response.iter_content(chunk_size=8192),
        content_type="application/vnd.android.package-archive",
        headers={
            "Content-Disposition": f"attachment; filename=\"kuudere-v{nData['version']}-build-{nData['build']}.apk\""
        }
    )


@app.route('/auth/callback')
def callback():
    print(request)
    
@app.route('/realtime')
def realtime():
    return render_template('rtest.html')

@app.route('/recently-updated', methods=['GET','POST'])
def recently_updated():
    secret = None
    key = None
    isApi = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')
    isKey = bool(secret)
    ctotal = None
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        try:
            

            client = get_client(None,session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(None,key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = get_acc_info(acc)

        except Exception as e:
            userInfo = None  
    else:
        userInfo = None     
    
    try:
        client = get_client(None,None,secret)
        databases = Databases(client)


        latest_eps = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime_Episodes'),
            queries = [
                Query.select("animeId"),
                Query.order_desc("aired"),
                Query.limit(200),
            ] # optional
        )

        processed_ids = set()  # Set to track processed anime IDs
        filtered_documents = []
        documents_eps = latest_eps.get('documents', [])
        filtered_documents_eps = []

        latest_ep_data = documents_eps

        # Access specific fields
        for anime in latest_ep_data:
            required_id = anime.get("animeId")
            anime_id = required_id

            # Skip if this anime ID has already been processed
            if anime_id in processed_ids:
                continue

            processed_ids.add(anime_id)

            anii = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('Anime'),
                queries=[
                    Query.greater_than_equal('year',2024),
                    Query.equal("animeId",required_id),
                    Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms", "type", "year", "description","subbed","dubbed"])
                ]
            )

            if anii['total'] == 0:
                continue

            anii=anii['documents'][0]

            img = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('ANIME_IMGS'),
                document_id=anii.get('mainId'),
                queries=[
                    Query.select(['cover'])
                ]
            )

            ass = anii.get('mainId')

            filtered_documents_eps.append({
                "id": anii.get("mainId"),
                "english": anii.get("english") if anii.get('english') is not None else anii.get("romaji"),
                "romaji": anii.get("romaji"),
                "native": anii.get("native"),
                "ageRating": anii.get("ageRating"),
                "malScore": anii.get("malScore"),
                "averageScore": anii.get("averageScore"),
                "duration": anii.get("duration"),
                "genres": anii.get("genres"),
                "cover": img.get("cover") ,
                "season": anii.get("season"),
                "startDate": datetime.fromisoformat(anii.get("startDate").replace("Z", "+00:00")).strftime("%b %d, %Y") if anii.get("startDate") else None,
                "status": anii.get("status"),
                "synonyms": anii.get("synonyms"),
                "type": anii.get("type"),
                "year": anii.get("year"),
                "epCount": anii.get("subbed"),
                "subbedCount": anii.get("subbed"),
                "dubbedCount": anii.get("dubbed"),
                "description": anii.get("description"),
                "url":f'/watch/{anii.get("mainId")}/{anii.get("subbed")}',
            })

            if len(filtered_documents_eps) >= 27:
                break

        data = {
            "latestEps": filtered_documents_eps,
            "userInfo": userInfo,
        }    
        
        response = make_response(json.dumps(data, indent=4, sort_keys=False))
        response.headers["Content-Type"] = "application/json"

        if isApi:
            return response
        else:
            return render_template('latestEps.html',result = filtered_documents_eps,userInfo=userInfo)
    except Exception as e:
         return jsonify({'success': False, 'message': str(e)}), 500 
    
def calculate_progress(current_aura):
    # Define rank thresholds
    rank_thresholds = [0, 60000, 120000, 180000, 240000]  # Aura thresholds for ranks
    max_aura = rank_thresholds[-1]  # Maximum Aura for the last rank

    # Calculate total progress percentage
    total_percentage = round((current_aura / max_aura) * 100, 2)

    # Determine current rank and next rank
    current_rank = None
    next_rank_threshold = None
    for i in range(len(rank_thresholds) - 1):
        if rank_thresholds[i] <= current_aura < rank_thresholds[i + 1]:
            current_rank = i  # Current rank index
            next_rank_threshold = rank_thresholds[i + 1]
            break

    # If below the first rank, current rank is the first
    if current_rank is None:
        current_rank = 0
        next_rank_threshold = rank_thresholds[1]

    # Progress to next rank
    current_rank_threshold = rank_thresholds[current_rank]
    rank_range = next_rank_threshold - current_rank_threshold
    progress_to_next_rank = round(((current_aura - current_rank_threshold) / rank_range) * 100, 2)

    return total_percentage

@app.route("/public/user/<id>",methods=['GET','POST'])
def public_profile(id):
    progress = 0

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')

    try:
            client = get_client(None,None,secret)
            users = Users(client)

            acc = users.get(
                user_id = id
            )

            userInfo = get_acc_info(acc)

    except Exception as e:
            userInfo = None      
            print(e)     
    
    try:
        client = get_client(None,None,secret)
        databases = Databases(client)

        rank = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('LEADER_BOARD'),
            queries=[
                Query.equal('userId',acc.get('$id')),
                Query.select(['points','$id']),
                ]
            )
        if rank['total'] > 0:
            points =rank['documents'][0].get('points')
            progress = calculate_progress(points)

        client = get_client(None,None,secret)
        databases = Databases(client)

        watchlist = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('Watchlist'),
                queries = [
                    Query.order_desc("$updatedAt"),
                    Query.equal("userId",id),
                    Query.select(["itemId","userId","animeId","folder","lastUpdated"]),
                    Query.limit(10)
                ] # optional
        )

        documents = watchlist.get('documents', [])

        watchlist_dataz = []
        
        for data in documents:
            aid = data.get('animeId')

            aniimeData = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('Anime'),
                document_id=aid,
                queries = [
                    Query.select(["mainId","english","romaji","lastUpdated","type","subbed","dubbed"]),
                ] # optional
            )

            img = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('ANIME_IMGS'),
                document_id=aniimeData.get('mainId'),
                queries=[
                    Query.select(['cover'])
                ]
            )

            output = {
                "id": aniimeData.get("mainId"),
                "title": aniimeData.get("english"),
                "type": aniimeData.get("type"),
                "subbed": aniimeData.get("subbed"),
                "dubbed": aniimeData.get("dubbed"),
                "image": img.get("cover"),
                "status": data.get("folder"),
                "url":f'/watch/{aniimeData.get("mainId")}',
            }
            watchlist_dataz.append(output)

            userInfo = {
                    "status":acc.get("emailVerification"),
                    "username" : acc.get("name"),
                    "pfp" : userInfo.get("pfp"),
                    "since" : datetime.fromisoformat(acc.get('$createdAt').replace("Z", "+00:00")).strftime("%Y-%m-%d"),
                    "progress":progress,
                    "points":format_views_without_view(points),
                    "watchlist":watchlist_dataz,
                }
    except Exception as e:
        print(e)
    return render_template('public_profile.html',userInfo=userInfo)
@app.route('/player/<type>/<id>')
@app.route('/player2/<type>/<id>')
@limiter.limit("120 per minute") 
def player(type, id):
    accessed_route = request.url_rule.rule.split('/')[1]
    try:
        if 'session_secret' in session:
            
            key = session["session_secret"]

            client = get_client(None,session["session_secret"], None)
            account = Account(client)

            acc = account.get()

            userInfo = get_acc_info(acc)
            
        elif bool(key):
            client = get_client(None,key, None)
            account = Account(client)

            acc = account.get()

            userInfo = get_acc_info(acc)

        else:
            userInfo = None
    except Exception:
        userInfo = None

    if type == "Hianime":
        ep = request.args.get('ep')
        server = request.args.get('server')
        category =request.args.get('category')
        vide = request.args.get('vide')
        anime = request.args.get('anime')
        episode = request.args.get('episode')
        current = None
        duration = None

        if category == 'raw':
            category = 'sub'
        
            # Con\struct the URL to get episode sources
        sources_url = f"{os.getenv('HIANIME_ENDPOINT')}/api/v2/hianime/episode/sources?animeEpisodeId={id}?ep={ep}&server={server}&category={category}"
            
            # Make the request to get sources
        sources_response = requests.get(sources_url)
        if sources_response.status_code == 500:
            category = "raw"
        
        sources_url = f"{os.getenv('HIANIME_ENDPOINT')}/api/v2/hianime/episode/sources?animeEpisodeId={id}?ep={ep}&server={server}&category={category}"
            
            # Make the request to get sources
        sources_response = requests.get(sources_url)

        if sources_response.status_code == 500:
            return jsonify({'success': True, 'message': 'Resources Not Found'}), 404

        sources_data = sources_response.json()
        data = sources_data.get("data")
        if not data:
                abort(404, description="Data not found in the response")

        video_url = data["sources"][0]["url"]
        subtitles = data["tracks"]

        client = get_client(None,None,os.getenv('SECRET'))
        databases = Databases(client)

        if userInfo:

            search = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('CONTINUE_WATCHING'),
                    queries=[
                        Query.equal("userId",acc.get("$id")),
                        Query.equal("animeId",anime),
                        Query.equal("episodeId",episode),
                        Query.select(['continueId','currentTime','duration']),
                    ]
                )
            
            if search['total'] > 0:
                data = search['documents'][0]
                current = data.get('currentTime')
                duration = data.get('duration')
            
            print(subtitles)

        if accessed_route == 'player':
            return render_template('player2.html', video_url=video_url, subtitles=subtitles,userInfo=userInfo,current=current, duration=duration)
        elif accessed_route == 'player2':
            return render_template('player.html', video_url=video_url, subtitles=subtitles,userInfo=userInfo,current=current, duration=duration)


    else:
        abort(400, description="Unsupported type")

def rank_points(client,acc,type,nd=None):

    databases = Databases(client)
    rid = ID.unique()

    if not nd:

        rank = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('LEADER_BOARD'),
            queries=[
                Query.equal('userId',acc.get('$id')),
                Query.select(['points','$id']),
                ]
            )
        if rank['total'] > 0:
            points = rank['documents'][0]
            lol=databases.update_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('LEADER_BOARD'),
            document_id=points.get('$id'),
            data={
                'points':points.get('points')+POINTS_LIKES,
                'userId':acc.get('$id'),
                }
            )
        else:
            lol=databases.create_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('LEADER_BOARD'),
            document_id=rid,
            data={
                'points':0+POINTS_LIKES,
                'userId':acc.get('$id'),
            }
        )
    else:
        rank = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('LEADER_BOARD'),
            queries=[
                Query.equal('userId',nd),
                Query.select(['points','$id']),
                ]
            )
        if rank['total'] > 0:
            points = rank['documents'][0]
            lol=databases.update_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('LEADER_BOARD'),
            document_id=points.get('$id'),
            data={
                'points':points.get('points')+POINTS_LIKES,
                'userId':nd,
                }
            )
        else:
            lol=databases.create_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('LEADER_BOARD'),
            document_id=rid,
            data={
                'points':0+POINTS_LIKES,
                'userId':nd,
            }
        )
@app.route("/add-anime")
def add_anime():
    return render_template('add.html')


@app.route("/report/anime/episode",methods=['POST'])
def report_episode():
    # Get the JSON data from the request body
    data = request.json
    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
        if not key or not secret:  # Ensures both key and secret are valid
            return jsonify({'success': False, 'message': "Unauthorized"}), 401
    isKey = bool(secret)
    
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
        
        key = session["session_secret"]

        client = get_client(None,session["session_secret"], None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)
        
    elif bool(key):
        client = get_client(None,key, None)
        account = Account(client)

        acc = account.get()

        userInfo = get_acc_info(acc)

    else:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    client = get_client(None,None,secret)
    databases = Databases(client)
    rid = ID.unique()

    try:
        databases.create_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('REPORTS'),
                document_id=rid,
                data={
                    "rid":rid,
                    "animeId":data.get('anime'),
                    "epId":f"{data.get('episode')}",
                    "userId":acc.get("$id"),
                    "type":data.get('category'),
                    "explain":data.get('feedback'),
                }
        )
    
        return jsonify({'success': True, 'message': 'Reported'}), 200
    except Exception as e:
        print(e)
        return jsonify({'success': False, 'message': 'Something Went Wrong'}), 500

@app.route('/sync_anilist/<int:anilist_id>')
def sync_anilist(anilist_id):
    # GraphQL query to fetch anime data from AniList
    query = '''
    query ($id: Int) {
        Media (id: $id, type: ANIME) {
            title {
                romaji
                english
                native
            }
            description
            genres
            episodes
            status
            averageScore
            coverImage {
                large
            }
            bannerImage
        }
    }
    '''
    
    variables = {
        'id': anilist_id
    }
    
    url = 'https://graphql.anilist.co'
    
    response = requests.post(url, json={'query': query, 'variables': variables},proxies=tor_proxy)
    data = response.json()
    
    if 'errors' in data:
        return jsonify({'error': 'Failed to fetch AniList data'}), 400
    
    anime_data = data['data']['Media']
    
    return jsonify({
        'title': anime_data['title']['english'] or anime_data['title']['romaji'],
        'description': anime_data['description'],
        'genres': anime_data['genres'],
        'episodes': anime_data['episodes'],
        'status': anime_data['status'],
        'averageScore': anime_data['averageScore'],
        'coverImage': anime_data['coverImage']['large'],
        'bannerImage': anime_data['bannerImage']
    })

@app.route('/proxy/subtitle/<path:url>')
def proxy_subtitle(url):
    response = requests.get(url)
    return Response(response.content, content_type=response.headers['content-type'])        

class AniListOAuth:
    """Class to handle AniList OAuth authentication."""

    @staticmethod
    @auth_bp.route("/login")
    def login():

        secret = None
        key = None

        isApi, key, secret, userInfo, acc = verify_api_request(request)

        isKey = bool(secret)
        if secret:
            isKey = True
            print("Key exists: ", secret)
        else:
            isKey = False
            secret = os.getenv('SECRET')  # Default value
            print("Key is missing or empty, setting default secret.")

        if 'session_secret' in session:
            try:
                

                client = get_client(None,session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            except Exception as e:
                userInfo = None     

        account = Account(client)
        session_data = account.create_jwt()
        session_data = session_data.get('jwt')

        if not session_data:
            id = session['session_id']
        """Redirect user to AniList OAuth login page."""
        auth_url = f"{os.getenv('ANILIST_AUTH_URL')}?client_id={os.getenv('CLIENT_ID')}&redirect_uri={os.getenv('REDIRECT_URI')}&response_type=code&state={session_data}"
        return redirect(auth_url)

    @staticmethod
    @auth_bp.route("/callback")
    def callback():
        """Handle OAuth callback and store token in session."""
        if "error" in request.args:
            return jsonify({"error": request.args["error"]})
        
        id = request.args.get('state')

        code = request.args.get("code")
        s = request.args.get("code")
        if not code:
            return "No authorization code received", 400

        data = {
            "grant_type": "authorization_code",
            "client_id": os.getenv('CLIENT_ID'),
            "client_secret": os.getenv('CLIENT_SECRET'),
            "redirect_uri": os.getenv('REDIRECT_URI'),
            "code": code
        }

        response = requests.post(os.getenv('ANILIST_TOKEN_URL'), json=data,proxies=tor_proxy)
        
        if response.status_code == 200:
            token_data = response.json()
            session["access_token"] = token_data["access_token"]
            session["refresh_token"] = token_data["refresh_token"]
            session["token_expiry"] = token_data["expires_in"]

            print(f'access_token:{token_data["access_token"]}')

            client = get_client(None,None, None,id)

            account = Account(client)

            acc = account.get()

            try:
                print(acc.get('$id'))  # Print session details

                client = get_client(None,None, os.getenv('SECRET'),None)
                databases = Databases(client)

                check = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('ANILIST_INFO'),
                    queries=[
                        Query.equal('user',acc.get('$id')),
                        Query.select(['$id'])
                    ]
                )

                if check['total'] > 0:

                    databases.update_document(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('ANILIST_INFO'),
                        document_id=acc.get('$id'),
                        data={
                        "user": acc.get('$id'),
                        "refresh_token":encrypt(token_data["refresh_token"]),
                        "access_token":encrypt(token_data["access_token"]),
                        "expire":token_data["expires_in"]
                        }
                    )

                else:

                    databases.create_document(
                        database_id=os.getenv('DATABASE_ID'),
                        collection_id=os.getenv('ANILIST_INFO'),
                        document_id=acc.get('$id'),
                        data={
                        "user": acc.get('$id'),
                        "refresh_token":token_data["refresh_token"],
                        "access_token":token_data["access_token"],
                        "expire":token_data["expires_in"]
                        }
                    )

                    try:
                        headers = {"Authorization": f"Bearer {token_data["access_token"]}"}
                        query = """
                        query {
                            Viewer {
                                id
                                name
                                avatar {
                                    medium
                                }
                            }
                        }
                        """
                        response = requests.post("https://graphql.anilist.co", json={"query": query}, headers=headers,proxies=tor_proxy)

                        if response.status_code == 200:
                            viewer_data = response.json().get("data", {}).get("Viewer", {})
                            
                            profile_picture = viewer_data.get("avatar", {}).get("medium")
                            print(profile_picture)

                            databases.update_document(
                                database_id=os.getenv('DATABASE_ID'),
                                collection_id=os.getenv('Users'),
                                document_id=acc.get('$id'),
                                data={"pfp": profile_picture}
                            )
                        else:
                            return "Failed to fetch profile", 400
                    except Exception as e:
                        print(f"Error: {e}")

            except AppwriteException as e:
                print("Error fetching session info:", e)
            return render_template('callback.html',token=token_data["access_token"])
        else:
            return f"Failed to get access token: {response.json()}", 400

    @staticmethod
    @auth_bp.route("/profile")
    def profile():
        """Fetch AniList user profile using the stored access token."""
        if "access_token" not in session:
            return redirect(url_for("auth.login"))

        headers = {"Authorization": f"Bearer {session['access_token']}"}
        query = """
        query {
          Viewer {
            id
            name
            avatar {
              medium
            }
          }
        }
        """
        response = requests.post("https://graphql.anilist.co", json={"query": query}, headers=headers,proxies=tor_proxy)

        if response.status_code == 200:
            return jsonify(response.json()["data"]["Viewer"])
        else:
            return "Failed to fetch profile", 400

# Register blueprint
app.register_blueprint(auth_bp)

# Route to get votes for an anime
@app.route('/votes/anime/<anime_id>', methods=['POST'])
def get_votes(anime_id):


    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    isKey = bool(secret)
    if secret:
            isKey = True
            print("Key exists: ", secret)
    else:
            isKey = False
            secret = os.getenv('SECRET')  # Default value
            print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
            try:
                

                client = get_client(None,session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            except Exception as e:
                userInfo = None     
    client = get_client(None, None, os.getenv('SECRET'), None)
    databases = Databases(client)

    if userInfo:
        user_rtings = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_VOTES'),
            queries=[
                Query.equal("anime", anime_id),  # Fixed query syntax
                Query.equal("user", userInfo.get('userId'))
            ]
        )
    else:
        user_rtings = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_VOTES'),
            queries=[
                Query.equal("anime", anime_id),  # Fixed query syntax
                Query.equal("ip", request.headers.get('X-Forwarded-For', request.remote_addr))
            ]
        )

    if user_rtings['total'] > 0:
        isUserVoted = True
        voteCount = user_rtings['documents'][0].get('vote')
    else:
        isUserVoted = False
        voteCount = 0


    try:
        rtings = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_VOTES'),
            queries=[
                Query.equal("anime", anime_id)  # Fixed query syntax
            ]
        )

        total = rtings['total']
        if total > 0:
            ratings = [dc.get('vote', 0) * 2 for dc in rtings['documents']]  # Scale 1-5 to 2-10
            avg_rating = sum(ratings) / len(ratings) if ratings else 0
        else:
            avg_rating = 0  # Ensures avg_rating is always defined

        return jsonify({
            "total": total,
            "rating": avg_rating,
            "isUserVoted": isUserVoted,  # This should be determined based on user session
            "usersVote": voteCount      # This should also be determined properly
        })
    
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({"error": "Internal server error"}), 500

@app.route('/vote/anime/<anime_id>', methods=['POST'])
def submit_vote(anime_id):
    # Verify API request
    isApi, key, secret, userInfo, acc = verify_api_request(request)
    
    if not secret:
        secret = os.getenv('SECRET')  # Fallback to default secret
        print("Key is missing or empty, setting default secret.")
    
    # Handle user session authentication
    if 'session_secret' in session:
        try:
            client = get_client(None, session["session_secret"], None)
            account = Account(client)
            acc = account.get()
            userInfo = get_acc_info(acc)
        except Exception as e:
            print(f"Error fetching user session: {e}")
            userInfo = None
    
    # Get rating from request body
    data = request.json or {}
    rating = data.get('rating', 0)
    
    # Initialize database client
    client = get_client(None, None, os.getenv('SECRET'), None)
    databases = Databases(client)

    # Extract a valid IP address
    def get_valid_ip():
        ip_address = request.headers.get('X-Forwarded-For', request.remote_addr)
        ip_list = ip_address.split(",") if ip_address else []
        
        for ip in ip_list:
            ip = ip.strip()  # Remove spaces
            if re.match(r"^\d{1,3}(\.\d{1,3}){3}$", ip) or re.match(r"^[a-fA-F0-9:]+$", ip):
                return ip  # Return the first valid IP
        return "0.0.0.0"  # Fallback if no valid IP exists
    
    client_ip = get_valid_ip()

    # Check if user already voted
    query_filters = [Query.equal("anime", anime_id)]
    if userInfo:
        query_filters.append(Query.equal("user", userInfo.get('userId')))
    else:
        query_filters.append(Query.equal("ip", client_ip))
    
    try:
        user_ratings = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_VOTES'),
            queries=query_filters
        )
        
        if user_ratings["total"] > 0:
            # Update existing vote
            vote_id = user_ratings["documents"][0]["$id"]
            databases.update_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('ANIME_VOTES'),
                document_id=vote_id,
                data={"vote": rating}
            )
            isUserVoted = True
            voteCount = rating
        else:
            # Create new vote
            vote_data = {
                "anime": anime_id,
                "vote": rating,
                "ip": client_ip
            }
            if userInfo:
                vote_data["user"] = userInfo.get('userId')
            
            new_vote = databases.create_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('ANIME_VOTES'),
                document_id=ID.unique(),
                data=vote_data
            )
            isUserVoted = True  # Set to True since the user/IP has now voted
            voteCount = rating
        
        # Get all votes for the anime
        all_ratings = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('ANIME_VOTES'),
            queries=[Query.equal("anime", anime_id)]
        )
        total = all_ratings["total"]
        ratings = [doc.get("vote", 0) * 2 for doc in all_ratings["documents"]]  # Scale 1-5 to 2-10
        avg_rating = sum(ratings) / len(ratings) if ratings else 0
        
        return jsonify({
            "total": total,
            "rating": avg_rating,
            "isUserVoted": isUserVoted,
            "usersVote": voteCount
        })
    
    except Exception as e:
        print(f"Error processing vote: {e}")
        return jsonify({"error": "Internal server error"}), 500
    

@app.route('/realtimet')
def realtimet():
    return render_template('realtime.html')

@app.route('/faq')
@cache.cached(timeout=60)
def faq():
    return render_template('f&q.html')  

@app.route('/timeline')
@cache.cached(timeout=60)
def timeline():
    return render_template('timeline.html')          

@app.route('/',methods=['GET','POST'])
@cache.cached(timeout=60)
def home():
    secret = None
    key = None
    isKey = False

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    if isApi:
            if not key or not secret:  # Ensures both key and secret are valid
                return jsonify({'success': False, 'message': "Unauthorized"}), 401
    
    if not bool(secret):
        secret = os.getenv('SECRET')
        isKey = True
    client = get_client(None,None, secret)
    databases = Databases(client)

    one_month_ago = datetime.now(pytz.UTC) - timedelta(days=120)
    iso_timestamp = one_month_ago.isoformat()

    key = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('SEARCH_DATA'),
        queries=[
            Query.select(['Keyword']),
            Query.greater_than_equal('$createdAt', iso_timestamp),
            Query.limit(2000)
        ]
    )

    words = []
    # Create a list of all keywords
    keywords = [doc['Keyword'] for doc in key['documents']]

    # Count occurrences of each keyword
    keyword_counts = Counter(keywords)

    # Get the 5 most common keywords and their counts
    top_5_searches = keyword_counts.most_common(5)

    # Print the results
    print("\nTop 5 Searches:")
    for keyword, count in top_5_searches:
        word = {
            "keyword":keyword
        }
        words.append(word)
    print(words)
    if not isKey:
        return jsonify(keywords)
    else:
        return render_template("home.html",keywords=words)
    
def get_anime_hover_data(anime_id,user_id):
        
        client = get_client(None, None, os.getenv('SECRET'), None)
        databases = Databases(client)
        watchlist_tt = {
            "total":0
        }

        anii = databases.list_documents(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('Anime'),
                queries=[
                    Query.equal("mainId",anime_id),
                    Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres",'studios', "season", "startDate", "status", "synonyms", "type", "year", "description","subbed","dubbed"])
                ]
            )
        
        if anii['total'] > 0:

            media = anii['documents'][0]

            watchlist_tt = databases.list_documents(
                        database_id = os.getenv('DATABASE_ID'),
                        collection_id = os.getenv('Watchlist'),
                        queries = [
                            Query.equal("animeId",anime_id),
                            Query.select(['folder'])
                        ]
                )


            try:
            
                watchlist = databases.list_documents(
                        database_id = os.getenv('DATABASE_ID'),
                        collection_id = os.getenv('Watchlist'),
                        queries = [
                            Query.equal("animeId",anime_id),
                            Query.equal("userId",user_id.get('userId')),
                            Query.select(['animeId','folder','lastUpdated'])
                        ]
                )
                print(watchlist)
            except Exception as e:
                print(e)
                watchlist = {
                        "total": 0
                    }

            if watchlist['total'] > 0:
                folder = watchlist['documents'][0].get('folder')
                added = format_relative_time(watchlist['documents'][0].get('lastUpdated'))
                isInWatchlist = True
            else:
                folder = None
                added = None
                isInWatchlist = False

            
            formatted_date = datetime.fromisoformat(media.get("startDate").replace("Z", "+00:00")).strftime("%b %d, %Y") if media.get("startDate") else None,
            
            # Clean HTML from description
            description = media.get('description')
            if description:
                # Basic HTML tag removal (you might want to use a proper HTML parser)
                description = html.unescape(description)
                description = description.replace('<br>', ' ')
                description = description.replace('<i>', '').replace('</i>', '')
                description = description.replace('<b>', '').replace('</b>', '')
            
            # Get main studio
            studio = media.get('studios')
            
            
            return {
                'id': media.get('mainId'),
                'title': {
                    'english':media.get('english') or media.get('romaji'),
                    'native': media.get('native'),
                },
                'description': description,
                'format': media.get('type'),
                'episodes': media.get('subbed'),
                'duration': media.get('duration'),
                'status': media.get('status'),
                'startDate': formatted_date,
                'genres':media.get('genres'),
                'score': media['malScore'],
                'popularity': 1000,
                'season': media.get('season'),
                'studio': studio,
                # These would come from your own database in a real implementation
                'subbedCount': media.get('subbed'),
                'dubbedCount': media.get('dubbed'),
                'folder':folder,
                'isInWatchlist':isInWatchlist,
                'added':added,
                "users":watchlist_tt['total'],
                "userInfo":user_id,
            }
        
        return None
@app.route('/api/hover/html', methods=['GET'])
def anime_hover_card():
    html_content = render_template('cardHoverData.html')
    return jsonify({'html': html_content})

@app.route('/api/hover/anime/<anime_id>', methods=['GET'])
def anime_hover_data(anime_id):
    # Add a small artificial delay to prevent excessive API calls during quick mouse movements
    shitl.sleep(0.1)

    secret = None
    key = None

    isApi, key, secret, userInfo, acc = verify_api_request(request)

    isKey = bool(secret)
    if secret:
            isKey = True
            print("Key exists: ", secret)
    else:
            isKey = False
            secret = os.getenv('SECRET')  # Default value
            print("Key is missing or empty, setting default secret.")

    if 'session_secret' in session:
            try:
                

                client = get_client(None,session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = get_acc_info(acc)

            except Exception as e:
                userInfo = None   
    
    # Get the data (either from cache or by fetching it)
    hover_data = get_anime_hover_data(anime_id,userInfo)
    
    if hover_data:
        return jsonify(hover_data)
    else:
        return jsonify({'error': 'Anime not found or API error occurred'}), 404
    
# Custom error handler for 404 errors
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(Exception)
def handle_exception(error):
    # Get the error details
    error_info = traceback.format_exc()
    
    # Log the error (you should set up proper logging)
    print(error_info)  # Replace with proper logging
    
    # Return the error page
    return render_template('500.html',
        error_code="500",
        error_message="Oops! Something went wrong on our servers."
    ), 500

# Custom error handler for 500 errors
@app.errorhandler(500)
def internal_error(error):
    return render_template('index.html'), 500      

@app.errorhandler(HTTPException)
def handle_http_exception(e):
    # Handle HTTP exceptions, including rate limit exceeded
    if e.code == 429:  # 429 Too Many Requests
        return jsonify({'success': False, "message": "Too many requests. Please try again later."}), 429
    if e.code == 500:  # 429 Too Many Requests
        return jsonify({'success': False, "message": "Internal Server Error"}), 500
    return jsonify({'success': False,"message": str(e)}), e.code
    
if __name__ == '__main__':
    threading.Thread(target=lambda: asyncio.run(websocket_listener()), daemon=True).start()
    socketio.run(app, debug=True, host='0.0.0.0')