from datetime import datetime, timezone
import hashlib
from flask import Flask, request, jsonify, session, render_template,make_response,redirect,send_from_directory,url_for,abort
from appwrite.services.databases import Databases
from flask_limiter.util import get_remote_address
from flask import Response
from flask_socketio import SocketIO, join_room, leave_room, rooms
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
import time
import math
import base64
import os
import re

os.environ['no_proxy'] = 'localhost,127.0.0.1'
POINTS_LIKES = 25

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

limiter = Limiter(
    get_real_ip,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

socketio = SocketIO(app,cors_allowed_origins="*",ping_interval=10,ping_timeout=20)
room_counts = defaultdict(int)
lock = threading.Lock()
CORS(app)
Compress(app)
ext = Sitemap(app)
cache = Cache(app, config={'CACHE_TYPE': 'SimpleCache'})
def get_client(session_id=None, secret=None):
    client = Client()
    client.set_endpoint(os.getenv('PROJECT_ENDPOINT'))
    client.set_project(os.getenv('PROJECT_ID') )
    
    if session_id:
        client.set_session(session_id)
    else:
        client.set_key(secret)
    
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
            

            client = get_client(session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email"),
                "joined":datetime.fromisoformat(acc.get('$createdAt').replace("Z", "+00:00")).strftime("%Y-%m-%d"),
                "verified":acc.get('status')
            }

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email"),
                "joined":datetime.fromisoformat(acc.get('$createdAt').replace("Z", "+00:00")).strftime("%Y-%m-%d"),
                "verified":acc.get('status')
            }
        except Exception as e:
            userInfo = None  
    else:
        userInfo = None   

    return userInfo

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Check if the user is authenticated by using Appwrite's session service
        try:
            # Get session data
            client = get_client(session["session_secret"],None)
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
    client = get_client(None, secret)
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
    
    
    excluded_routes = ['/api/', '/save/progress','/proxy/','/static/']
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
        client = get_client(None,secret)
        databases = Databases(client)
        user_check = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Users'),
            queries=[
                Query.equal("username",name)
            ]
        )

        if user_check['total'] > 0:
            return jsonify({"error": "Username already exists"}), 400
        
        account = Account(client)
        result = account.create(ID.unique(), email=email, password=password, name=name)

        session_data = account.create_email_password_session(email=email, password=password)

        client = get_client(session_data['secret'],None)
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
        session['session_id'] = session_data['$id']  # Store the session ID for logout
        session['session_secret'] = session_data['secret']  # Store the secret for authentication
        return jsonify({'success': True, 'message': 'User registered successfully'})
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

    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
    print(secret)
    
    try:
        client = get_client(None,secret)
        account = Account(client)
        session_data = account.create_email_password_session(email=email, password=password)
        
        # Store both session ID and secret
        session.clear()
        session['session_id'] = session_data['$id']  # Store the session ID for logout
        session['session_secret'] = session_data['secret']  # Store the secret for authentication
        
        return jsonify({
            'success': True, 
            'message': 'Logged in successfully',
            'session_id': session_data['secret']
        })
    except Exception as e:
        return jsonify({'success': False, 'message': 'Invalid email or password'}),401
    
@app.route('/logout', methods=['POST'])
def logout():

    isKey = False
    secret = os.getenv('SECRET')  # Default value
    print(session['session_id'])
    
    try:
        client = get_client(session['session_secret'],secret)
        account = Account(client)
        session_data = account.delete_session(
           session_id= session['session_id']
        )

        session.clear()
        
        return jsonify({
            'success': True, 
            'message': 'Logged Out successfully',
        })
    except Exception as e:
        return jsonify({'success': False, 'message': e}),500 
    
@app.route('/user', methods=['POST'])
def get_user():
    data = request.json
    email = data.get('email')
    password = data.get('password')
    secret = data.get('secret')
    key = data.get('key')
    print(secret)
    
    try:
        client = get_client(key,None)
        account = Account(client)
        result = account.get()
        dat = result['$id']

        databases = Databases(client)

        result = databases.get_document(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Users'),
            document_id = dat,
        )
        return jsonify({'success': True, 'userId': result})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500
    
def recreate_url(base_url, url_code):
    """Recreate the full shortened URL from the base URL and code."""
    return f"{base_url.rstrip('/')}/{url_code.lstrip('/')}"   

@app.route('/home', methods=['GET'])
def load_home():
    encoded = request.args.get('spc')
    secret = request.args.get('secret')
    key = request.args.get('key')
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
            

            client = get_client(session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }
        except Exception as e:
            userInfo = None  
    else:
        userInfo = None     
    
    try:
        client = get_client(None,secret)
        databases = Databases(client)

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
                Query.equal("year",2025),
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

        latest_eps = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime_Episodes'),
            queries = [
                Query.select("animeId"),
                Query.order_desc("aired"),
                Query.order_desc("$updatedAt"),
                Query.limit(20)
            ] # optional
        )

        documents = result.get('documents', [])
        processed_ids = set()  # Set to track processed anime IDs
        filtered_documents = []
        documents_eps = latest_eps.get('documents', [])
        filtered_documents_eps = []
        documents_top = topAiring.get('documents', [])
        filtered_documents_top = []
        documents_top_upcoming = topUpcoming.get('documents', [])
        filtered_documents_top_upcoming = []

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
                    Query.equal("animeId",required_id),
                    Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms", "type", "year", "description","subbed","dubbed"])
                ]
            )

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
                "startDate": anii.get("startDate"),
                "status": anii.get("status"),
                "synonyms": anii.get("synonyms"),
                "type": anii.get("type"),
                "year": anii.get("year"),
                "epCount": anii.get("subbed"),
                "subbedCount": anii.get("subbed"),
                "dubbedCount": anii.get("dubbed"),
                "description": anii.get("description"),
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
                "startDate": doc.get("startDate"),
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

            if not img.get("banner"):
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
                "cover":img.get("cover"),
                "banner": img.get("banner") or new_url,
                "season": air.get("season"),
                "startDate": air.get("startDate"),
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
                "cover":img.get("cover"),
                "banner": img.get("banner"),
                "season": upcoming.get("season"),
                "startDate": upcoming.get("startDate"),
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
        }    
        
        response = make_response(json.dumps(data, indent=4, sort_keys=False))
        response.headers["Content-Type"] = "application/json"

        if isKey:
            return response
        else:
            return render_template('index.html', last_updated=filtered_documents,latest_eps = filtered_documents_eps, topAiring = filtered_documents_top,topUpcoming=filtered_documents_top_upcoming,userInfo=userInfo,ctotal=ctotal,Surl=Surl)
    except Exception as e:
         return jsonify({'success': False, 'message': str(e)}), 500 
        
@app.route('/search')
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
    secret = request.args.get('secret')
    keyword = request.args.get('keyword')
    page = request.args.get('page', default=1, type=int)
    isPage = bool(page)
    results_per_page = 18

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
        try:
            

            client = get_client(session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }
        except Exception as e:
            userInfo = None  
    else:
        userInfo = None     

    try:
        # Validate secret 
        client = get_client(None, secret)
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
                Query.search("english", keyword),
                Query.search("romaji", keyword),
                Query.search("native", keyword),
                Query.contains("synonyms", keyword)
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

@app.route('/anime/<id>', methods=['GET'])
def anime_info(id):

    secret = request.args.get('secret')
    isKey = bool(secret)
    idz = id
    key = request.args.get('key')
    inWatchlist = False

    # Add error handling for missing parameters
    if not idz:
        return jsonify({"error": "Missing required(id) parameters", "success":False}), 400
    if not secret and key:
        return jsonify({"error": "Missing Session And Secret parameters", "success":False}), 400
    
    if secret:
        isKey = True
    else:
        isKey = False 
        print("bye")  
        secret = os.getenv('SECRET')
    try:
        if 'session_secret' in session:
            

            client = get_client(session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }
        elif bool(key):
            client = get_client(key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }
        else:
            userInfo = None

    except Exception as e:
        userInfo = None
     
    try:
        client = get_client(key, secret)
        databases = Databases(client)
        
        result = databases.get_document(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Anime'),
            document_id=idz,
            queries=[
                Query.select(["mainId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration","studios", "genres", "season", "startDate", "status", "synonyms", "type", "year","subbed","dubbed","description"])
            ]
        )

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
                    Query.equal("itemId", wid)
                ]
            )

            if wr['total'] > 0:
                inWatchlist = True

        title = doc.get('english') if doc.get('english') is not None else doc.get('romaji')
        description = doc.get("description")
        cover = img.get("banner") or "/static/placeholder.svg"

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
        return jsonify({"error": str(e),"success": False}), 500

@app.route('/watch/<anime_id>/<ep_number>', methods=['GET'])
def watch_page(anime_id, ep_number):
    ep = ep_number
    print(ep)
    secret = request.args.get('secret')
    nid = request.args.get('nid')
    key = request.args.get('key')
    idz =anime_id
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
                

                client = get_client(session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = {
                    "userId":acc.get("$id"),
                    "username" : acc.get("name"),
                    "email" : acc.get("email")
                }
            elif bool(key):
                client = get_client(key,None)
                account = Account(client)

                acc = account.get()
                
                userInfo = {
                    "userId":acc.get("$id"),
                    "username" : acc.get("name"),
                    "email" : acc.get("email")
                }
            else:
                userInfo = None
        except Exception as e:
            userInfo = None       

        # Initialize client and database
    client = get_client(None, secret)
    databases = Databases(client)

    # Fetch anime document from the database
    result = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime'),
        document_id=idz,
        queries=[
            Query.select(["mainId","animeId", "english", "romaji", "native", "ageRating", "malScore", "averageScore", "duration", "genres", "season", "startDate", "status", "synonyms","studios", "type", "year", "description","subbed","dubbed"]),
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
                

                if IsUserLiked['total'] > 0:
                    isLiked = True
                elif IsUserunLiked['total'] > 0:
                    isUnliked = True

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
    print("Documents retrieved:", likass)


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
                "startDate": result.get("startDate"),
                "status": result.get("status"),
                "synonyms": result.get("synonyms"),
                "studios": result.get("studios"),
                "type": result.get("type"),
                "year": result.get("year"),
                "epCount":result.get("subbed"),
                "subbedCount": result.get("subbed"),
                "dubbedCount": result.get("dubbed"),
                "description": result.get("description"),
                "ep":ep,
                "userLiked": isLiked,
                "userUnliked": isUnliked,
                "likes":likes['total'],
                "dislikes":dislikes['total']
            }
            
    response = {
        "anime_info": filtered_document,
        "userInfo":userInfo,
        "success": True
    }
    dec = f'Best site to watch { result.get("english") if result.get('english') is not None else result.get("romaji")} English Sub/Dub online Free and download { result.get("english") if result.get('english') is not None else result.get("romaji")} English Sub/Dub anime'
    cover = img.get("cover") if img.get('cover') is not None else img.get("banner")

    response = make_response(json.dumps(response, indent=4, sort_keys=False))
    response.headers["Content-Type"] = "application/json"

    if isKey:
        return response
    return render_template('watch.html', anime_id=anime_id, ep_number=ep_number,animeInfo = filtered_document,userInfo=userInfo,description=dec,cover=cover)

@app.route("/api/anime/respond/<id>", methods=['POST'])
def like_anime(id):
    # Get the JSON data from the request body
    data = request.get_json()

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

        client = get_client(session["session_secret"], None)
        account = Account(client)

        acc = account.get()

        userInfo = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "email": acc.get("email")
        }
        
    elif bool(key):
        client = get_client(key, None)
        account = Account(client)

        acc = account.get()

        userInfo = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "email": acc.get("email")
        }
    else:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401

    lid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(key, None)
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
                                "user": acc.get("$id"),
                                "related_anime": id,
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
                                "user": acc.get("$id"),
                                "related_anime": id,
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
                                "user": acc.get("$id"),
                                "related_anime": id,
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
                                "user": acc.get("$id"),
                                "related_anime": id,
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
    
@app.route('/add-to-watchlist/<folder>/<animeid>', methods=['GET'])
def add_to_watchlist(folder, animeid):
    try:
        key = request.args.get('key')
        user_id = request.args.get('userid')

        if not key:
            key = session.get("session_secret")

        valid_folders = ["Plan To Watch", "Watching", "Completed", "On Hold", "Dropped", "Remove"]
        if folder not in valid_folders:
            return jsonify({"error": "Invalid folder", "success": False}), 400

        client = get_client(key, None)
        account = Account(client)
        result = account.get()
        uid = result['$id']

        databases = Databases(client)
        wid = generate_unique_id(uid,animeid)

        print(wid)

        wr = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Watchlist'),
            queries=[
                Query.equal("itemId", wid)
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
                        "user": uid,
                        "anime": animeid,
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
                    "user": uid,
                    "anime": animeid,
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

    secret = os.getenv('SECRET')  # Default value

    try:
        # Validate secret
        client = get_client(None, secret)
        databases = Databases(client)

        # Base query list
        base_query_list = [Query.equal("public", True)]

        # Search strategies for the keyword
        def get_keyword_search_queries(keyword):
            return [
                Query.search("english", keyword),
                Query.search("romaji", keyword),
                Query.search("native", keyword),
                Query.contains("synonyms", keyword)
            ]

        # Limiting the query to 4 results
        base_query_list.append(Query.limit(4))
        base_query_list.append(Query.select(["mainId", "english", "romaji", "native", "duration", "type", "year"]))

        # Result variable
        result = None
        filtered_documents = []

        # Try different search strategies until results are found
        for keyword_query in get_keyword_search_queries(keyword):
            # Combine base queries with the current keyword strategy
            query_list = base_query_list + [keyword_query]

            try:
                # Perform the database query
                result = databases.list_documents(
                    database_id=os.getenv('DATABASE_ID'),
                    collection_id=os.getenv('Anime'),
                    queries=query_list
                )

                # Break if results are found
                if result['total'] > 0:
                    break

            except Exception as e:
                print(f"Error occurred during query: {e}")
                result = None

        if result['total'] <= 0:
            return None
        # Process documents if results were found
        if result and result.get('documents'):
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

        # If no documents found, return a message
        if not filtered_documents:
            filtered_documents = [{"message": "No results found.", "findOutMore": "/search"}]

    except Exception as e:
        print(f"Error occurred: {e}")
        filtered_documents = [{"message": "An error occurred while fetching results."}]

    # Return JSON response
    return jsonify(filtered_documents)

@app.route('/watch-api/<anime_id>/<int:ep_number>')
def fetch_episode_info(anime_id,ep_number):
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr).split(',')[0]
    idz = anime_id
    epASs = int(ep_number)
    secret = os.getenv('SECRET')  # Default value
    print("Key is missing or empty, setting default secret.")

        # Initialize client and database
    client = get_client(None, secret)
    databases = Databases(client)

        # Fetch anime document from the database
    result = databases.get_document(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime'),
        document_id=idz,
        queries=[
            Query.select(["animeId"]),
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
            "anime":anime_id,
        }
    )
    
    epiList = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('Anime_Episodes'),
        queries=[
            Query.equal("animeId",result.get("animeId")),
            Query.select(["titles", "number", "aired", "score", "recap", "filler","$id"]),
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

    # Extract episode data
    episodes = epiList.get("documents", [])
    episode_details = []
    ep_links = []

    for episode in episodes:
        episode_info = {
            "id": episode.get("$id"),
            "titles": episode.get("titles", []),
            "filler": episode.get("filler"),
            "number": episode.get("number"),
            "recap": episode.get("recap")
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
        if links.get("serverName") == "Hianime":
            link_info = {
                "$id": links.get("$id"),
                "serverId": links.get("serverId"),
                "serverName": links.get("serverName"),
                "episodeNumber": links.get("episodeNumber"),
                "dataType": links.get("dataType"),
                "dataLink": links.get("dataLink").replace("https://hianime.to/watch/", "/player/Hianime/") + f"&episode={epinfo['documents'][0]['$id']}&anime={anime_id}&vide=Hianime"
            }
        else:    
            link_info = {
                "$id": links.get("$id"),
                "serverId": links.get("serverId"),
                "serverName": links.get("serverName"),
                "episodeNumber": links.get("episodeNumber"),
                "dataType": links.get("dataType"),
                "dataLink": links.get("dataLink")
            }
        ep_links.append(link_info)

    ep_links.sort(key=lambda x: x['serverId'])

    coms = []

    comm = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments'),
            queries=[
                Query.equal("animeId", anime_id),
                Query.equal("epNumber", ep_number),  # Ensure episode.get("$id") returns the correct value
                Query.not_equal("removed", True),
                Query.select(["commentId","userId","added_date","comment"]),
            ]
        )
    comz = comm.get("documents", [])

    for comment in comz:
        replys = []
        reply = databases.list_documents(
            database_id=os.getenv('DATABASE_ID'),
            collection_id=os.getenv('Episode_Comments_Replys'),
            queries=[
                Query.equal("replyEpisodeCommentId", comment.get("commentId")),
                Query.not_equal("removed", True),
            ]
        )
        userifo =databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                document_id=comment.get('userId'),
                queries=[
                    Query.select('username')
                ]
            )
        rz = reply.get("documents", [])
        for rzls in rz:
            userifo0 =databases.get_document(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                document_id=rzls.get('userId'),
                queries=[
                    Query.select('username')
                ]
            )
            data = {
                'id': rzls.get("commentId"),
                "author":userifo0.get('username'),
                "time": format_relative_time(rzls.get("added_date")),
                "content": rzls.get("content")
            }
            replys.append(data)
        detail_info = {
            "id": comment.get("commentId"),
            "author": userifo.get('username'),
            "time": format_relative_time(comment.get("added_date")),
            "content": comment.get("comment"),
            "showReplyForm": False,
            "showReplies": False,
            "replyContent": "",
            "replies": replys,
        }
        coms.append(detail_info)

            
    response = {
        "all_episodes": episode_details,
        "episode_links": ep_links,
        "episode_comments":coms,
        "total_comments":comm['total'],
        "success": True
    }

    response = make_response(json.dumps(response, indent=4, sort_keys=False))
    response.headers["Content-Type"] = "application/json"

    return response

posts = [
    {
        "id": 1,
        "title": "Join Our Discord Community for Support and Anime Fun!",
        "content": "Hello everyone, We understand that many of you have been experiencing various issues with the website. While our moderators do their best to assist here when possible, it's simply not feasible to address every concern directly on the site. For more...",
        "author": "mugiwara_no_L4R",
        "category": "Updates",
        "likes": 368,
        "comments": 337,
        "time": "4 months ago",
        "pinned": True,
        "isMod": True
    },
    {
        "id": 2,
        "title": "Pinned posts now found here 8-10-24",
        "content": "In order to reduce the number of pinned posts, we will have links to the pinned community posts here. This will allow us to mostly only have one pinned post. This post may be changed or edited as needed. Hanime Download Guide...",
        "author": "agaric1",
        "category": "Updates",
        "likes": 149,
        "comments": 90,
        "time": "4 months ago",
        "pinned": True,
        "isMod": True
    }
    ,
        {
            'id': 3,
            'title': 'Pinned posts now found here 8-10-24',
            'content': 'In order to reduce the number of pinned posts, we will have links to the pinned community posts here. This will allow us to mostly only have one pinned post. This post may be changed or edited as needed. Hanime Download Guide...',
            'author': 'agaric1',
            'authorAvatar': '/placeholder.svg?height=32&width=32',
            'category': 'Suggestion',
            'likes': 149,
            'comments': 90,
            'time': '4 months ago',
            'pinned': True,
            'isMod': True
        }
]

@app.route('/community')
def community():
        posts = []
        secret = request.args.get('secret')
        key = request.args.get('key')
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
                

                client = get_client(session["session_secret"],None)
                account = Account(client)

                acc = account.get()
                
                userInfo = {
                    "userId":acc.get("$id"),
                    "username" : acc.get("name"),
                    "email" : acc.get("email")
                }

            except Exception as e:
                userInfo = None      
        elif bool(key):
            try:
                client = get_client(key,None)
                account = Account(client)

                acc = account.get()
                
                userInfo = {
                    "userId":acc.get("$id"),
                    "username" : acc.get("name"),
                    "email" : acc.get("email")
                }
            except Exception as e:
                userInfo = None  
        else:
            userInfo = None       

        client = get_client(None,secret)
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

            client = get_client(None,secret)
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
                    Query.select(['username','userId']),
                ]
            )

            posts.append({
                "id": post.get("postId"),
                "title": post.get("title"),
                "content": post.get("content"),
                "category": post.get("category"),
                "time": added,  # Use relative time
                "author": user.get('username'),
                'authorAvatar': '/placeholder.svg?height=32&width=32',
                'likes': 149,
                'comments': 90,
                'userUnliked':True,
                "pinned": False,
                "isMod": isMod,
            })   


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

@app.route('/api/posts', methods=['GET'])
def get_posts():
    category = request.args.get('category', 'All')
    page = int(request.args.get('page', 1))
    per_page = 20
    isLiked = False
    isUnliked = False


    valid_folders = ["General", "Suggestion", "Discussion", "Feedback","Question","All","Updates"]
    if category not in valid_folders:
        return jsonify({"error": "Invalid Category", "success": False}), 404

    secret = request.args.get('secret')
    key = request.args.get('key')
    posts = []
    isKey = bool(secret)

    # Process secret or key for authentication
    if not secret:
        secret = os.getenv('SECRET')  # Default value if secret is missing

    userInfo = None
    if 'session_secret' in session:
        try:
            client = get_client(session["session_secret"], None)
            account = Account(client)
            acc = account.get()
            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
        except Exception:
            userInfo = None
    elif isKey:
        try:
            client = get_client(key, None)
            account = Account(client)
            acc = account.get()
            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
        except Exception:
            userInfo = None

    # Fetch posts from database
    try:
        client = get_client(None, secret)
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
                queries=[Query.select(['username', 'userId'])]
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
                'authorAvatar': '/placeholder.svg?height=32&width=32',
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
            

            client = get_client(session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }
        elif bool(key):
            client = get_client(key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }
        else:
            return jsonify({'success': False, 'message': 'Authentication Fail'}),401
    except Exception as e:
        return jsonify({'success': False, 'message': 'Authentication Fail'}),401
    
    
    try:
        valid_folders = ["General", "Suggestion", "Discussion", "Feedback","Question"]
        if data.get('category') not in valid_folders:
            return jsonify({"error": "Invalid Category", "success": False}), 400
        client = get_client(key,secret)
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
                'postedUser':acc.get("$id"),
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
                    'message':f'You have been mentioned on post {data.get('title')}',
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                    'receiver':user['documents'][0]['userId'],
                    'related_post':did,
                }
            )

            print(user['documents'][0]['userId'])
        new_post['id'] = did  # This would normally be generated by the database
        new_post['author'] = acc.get("name"),
        new_post['authorAvatar'] = '/placeholder.svg?height=32&width=32'
        new_post['likes'] = 0
        new_post['comments'] = 0
        new_post['time'] = 'Just now'
        new_post['pinned'] = False
        new_post['isMod'] = False
        return jsonify(new_post), 201

    except Exception as e:
        return jsonify({'success': False, 'message': e}),500
    
@app.route("/api/post/respond/<id>", methods=['POST'])
def like_post(id):
    # Get the JSON data from the request body
    data = request.get_json()

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

        client = get_client(session["session_secret"], None)
        account = Account(client)

        acc = account.get()

        userInfo = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "email": acc.get("email")
        }
        
    elif bool(key):
        client = get_client(key, None)
        account = Account(client)

        acc = account.get()

        userInfo = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "email": acc.get("email")
        }
    else:
        return jsonify({'success': False, 'message': "Unauthorized"}), 401

    lid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(key, None)
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
                                "likedUser": acc.get("$id"),
                                "post": id,
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
                                "likedUser": acc.get("$id"),
                                "post": id,
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
                                "likedUser": acc.get("$id"),
                                "post": id,
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
                                "likedUser": acc.get("$id"),
                                "post": id,
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

@app.route('/post/<post_id>', methods=['GET'])
def view_post(post_id):
    try:
        # Get query parameters
        secret = request.args.get('secret')
        key = request.args.get('key')
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
            client = get_client(session["session_secret"], None)
            account = Account(client)
            acc = account.get()
            
            userInfo = {
                "userId": acc.get("$id", ""),
                "username": acc.get("name", ""),
                "email": acc.get("email", "")
            }
        elif bool(key):
            client = get_client(key, None)
            account = Account(client)
            acc = account.get()
            
            userInfo = {
                "userId": acc.get("$id", ""),
                "username": acc.get("name", ""),
                "email": acc.get("email", "")
            }

        # Get database client
        client = get_client(key, secret)
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
        client = get_client(None, secret)
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
            queries=[Query.select(['username', 'userId'])]
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
            usercm = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('Users'),
                queries=[
                    Query.equal('userId', cm.get('userId', '')),
                    Query.select(['username', 'userId'])
                ]
            )

            if usercm.get('documents'):
                comment_data = {
                    "id": cm.get('postCommentId', ''),
                    "author": usercm['documents'][0].get('username', ''),
                    "avatar": "/placeholder.svg?height=32&width=32",
                    "content": cm.get('content', ''),
                    "time": format_relative_time(cm.get('added_date'))
                }
                comments.append(comment_data)

        # Prepare post data
        post = {
            'id': result.get("postId", ""),
            'title': result.get("title", ""),
            'content': result.get("content", ""),
            'author': user.get('username', ""),
            'authorAvatar': '/placeholder.svg?height=32&width=32',
            'category': result.get("category", ""),
            'userLiked': bool(isLiked),
            'userUnliked': bool(isUnliked),
            'likes': likes.get('total', 0),
            'comments': comms.get('total', 0),
            'time': format_relative_time(result.get("added", ""))
        }

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

         client = get_client(session["session_secret"],None)
         account = Account(client)

         acc = account.get()
         
         userInfo = {
             "userId":acc.get("$id"),
             "username" : acc.get("name"),
             "email" : acc.get("email")
         }
         
    elif bool(key):
         client = get_client(key,None)
         account = Account(client)

         acc = account.get()
         
         userInfo = {
             "userId":acc.get("$id"),
             "username" : acc.get("name"),
             "email" : acc.get("email")
         }
    else:
       return jsonify({'success': False, 'message':"Unauthorized"}), 401
    
    cid = ID.unique()
    iso_timestamp = datetime.now(timezone.utc).isoformat()

    client = get_client(key,None)
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
            'commentedUser':acc.get("$id"),
            'post':post_id,
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
                    'message':f'{acc.get('name')} commented on {result.get('title')}',
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                    'receiver':user_id,
                    'related_post':post_id,
                    'realtedPostId':post_id,
                    'related_post_commentId':cid,
                    'relatedPostCommentId':cid,
                }
            )
    rank_points(client,acc,'comment')
    new_comment = {
        "id": cid,
        "author": acc.get("name"),  # In a real app, you'd get this from user authentication
        "avatar": "/placeholder.svg?height=32&width=32",
        "content": data['content'],
        "time": "Just now"
    }
    return jsonify(new_comment), 201    

@app.route('/anime/comment/',methods=['POST'])
@limiter.limit("2 per minute") 
def comment():
    data = request.json
    print(data)
    
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
         

         client = get_client(session["session_secret"],None)
         account = Account(client)

         acc = account.get()
         
         userInfo = {
             "userId":acc.get("$id"),
             "username" : acc.get("name"),
             "email" : acc.get("email")
         }
         
    elif bool(key):
         client = get_client(key,None)
         account = Account(client)

         acc = account.get()
         
         userInfo = {
             "userId":acc.get("$id"),
             "username" : acc.get("name"),
             "email" : acc.get("email")
         }
    else:
       return jsonify({'success': False, 'message':"Unauthorized"}), 401
    
    try:
        client = get_client(None,secret)
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
        

        client = get_client(session["session_secret"],None)
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
                "users": acc.get("$id"),
                "anime":data.get('anime'),
                "episode": epxx['documents'][0]['$id'],      
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
                    'message':f'{acc.get('name')} mentioned you on anime {anime['documents'][0]['english'] if anime['documents'][0]['english'] is not None else anime['documents'][0]['romaji']}',
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                    'receiver':user['documents'][0]['userId'],
                    'related_ep':cid,
                }
            )

            print(user['documents'][0]['userId'])

        data = {
            "userId": acc.get("$id"),
            "username": acc.get("name"),
            "commentId": cid,
            "comment" : data.get('content'),
        }

        return jsonify({'success': False, 'message': "Added","data":data}), 200

        
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/anime/comments/reply', methods=['POST'])
def post_reply():
    data = request.get_json()  # Get JSON data from the request
    comment_id = data.get('commentId')
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
         

         client = get_client(session["session_secret"],None)
         account = Account(client)

         acc = account.get()
         
         userInfo = {
             "userId":acc.get("$id"),
             "username" : acc.get("name"),
             "email" : acc.get("email")
         }
         
    elif bool(key):
         client = get_client(key,None)
         account = Account(client)

         acc = account.get()
         
         userInfo = {
             "userId":acc.get("$id"),
             "username" : acc.get("name"),
             "email" : acc.get("email")
         }
    else:
       return jsonify({'success': False, 'message':"Unauthorized"}), 401
    

    if not comment_id or not reply_content:
        return jsonify({"error": "commentId and content are required"}), 400
    
    if comment_filter(reply_content):
        remove = True
    else:
        remove = False

    try:
        client = get_client(None,secret)
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
                "replyed_episode_comment":comment_id,
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
                    'message':f'{acc.get('name')} replied to your comment on {anime.get('english') if anime.get('english') is not None else anime.get('romaji')}',
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                    'receiver':find_comment['documents'][0]['userId'],
                    'related_ep':find_comment['documents'][0]['episodeId'],
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
                    'message':f'{acc.get('name')} mentioned you on anime comment {find_comment['documents'][0]['comment']}',
                    'isRead':False,
                    'isCommunity':True,
                    'time':iso_timestamp,
                    'receiver':user['documents'][0]['userId'],
                    'related_ep_comment':find_comment['documents'][0]['commentId'],
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
# Simulated data (replace with database queries in a real application)

notifications_data = [
    {
        "id": 1,
        "title": "Is It Wrong to Try to Pick Up Girls in a Dungeon? V - Episode 11 [SUB] available NOW!",
        "time": "an hour ago",
        "image": "https://cdn.noitatnemucod.net/cover/danmachi-v.jpg",
        "type": "anime"
    },
    {
        "id": 2,
        "title": "Tasuketsu -Fate of the Majority- - Episode 23 [SUB] available NOW!",
        "time": "2 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/tasuketsu.jpg",
        "type": "anime"
    },
    {
        "id": 3,
        "title": "I'll Become a Villainess Who Goes Down in History - Episode 12 [SUB] available NOW!",
        "time": "2 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/akuyaku.jpg",
        "type": "anime"
    },
    {
        "id": 4,
        "title": "Tying the Knot with an Amagami Sister - Episode 12 [SUB] available NOW!",
        "time": "2 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/amagami.jpg",
        "type": "anime"
    },
    {
        "id": 5,
        "title": "Seirei Gensouki: Spirit Chronicles Season 2 - Episode 11 [SUB] available NOW!",
        "time": "3 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/seirei-gensouki-2nd-season.jpg",
        "type": "anime"
    },
    {
        "id": 7,
        "title": "Is It Wrong to Try to Pick Up Girls in a Dungeon? V - Episode 11 [SUB] available NOW!",
        "time": "an hour ago",
        "image": "https://cdn.noitatnemucod.net/cover/danmachi-v.jpg",
        "type": "anime"
    },
    {
        "id": 8,
        "title": "Tasuketsu -Fate of the Majority- - Episode 23 [SUB] available NOW!",
        "time": "2 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/tasuketsu.jpg",
        "type": "anime"
    },
    {
        "id": 9,
        "title": "I'll Become a Villainess Who Goes Down in History - Episode 12 [SUB] available NOW!",
        "time": "2 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/akuyaku.jpg",
        "type": "anime"
    },
    {
        "id": 10,
        "title": "Tying the Knot with an Amagami Sister - Episode 12 [SUB] available NOW!",
        "time": "2 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/amagami.jpg",
        "type": "anime"
    },
    {
        "id": 11,
        "title": "Seirei Gensouki: Spirit Chronicles Season 2 - Episode 11 [SUB] available NOW!",
        "time": "3 days ago",
        "image": "https://cdn.noitatnemucod.net/cover/seirei-gensouki-2nd-season.jpg",
        "type": "anime"
    }
]
   
@app.route('/profile')
@app.route('/user/<path:subpath>')
@login_required
def user(subpath=None):
    secret = request.args.get('secret')
    key = request.args.get('key')
    userInfo = get_user_info(key,secret)
    return render_template('profile.html',userInfo=userInfo)
@app.route('/api/profile')
def profile():
    secret = request.args.get('secret')
    key = request.args.get('key')

    userInfo = get_user_info(key,secret)
 
    return jsonify(userInfo)

@app.route('/api/watchlist')
def watchlist():
    time.sleep(1)  # Simulate delay
    page = int(request.args.get('page', 1))
    status = request.args.get('status', 'All')
    secret = request.args.get('secret')
    key = request.args.get('key')
    per_page = 12
    userInfo = get_user_info(key,secret)
    isKey = bool(secret)
    if secret:
        isKey = True
        print("Key exists: ", secret)
    else:
        isKey = False
        secret = os.getenv('SECRET')  # Default value
        print("Key is missing or empty, setting default secret.")


    client = get_client(None,secret)
    databases = Databases(client)

    watchlist = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Watchlist'),
            queries = [
                Query.order_desc("$updatedAt"),
                Query.equal("userId",userInfo.get('userId')),
                Query.select(["itemId","userId","animeId","folder","lastUpdated"]),
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
            "url":f'/watch/{aniimeData.get("mainId")}/1',
            "duration": "45m", "current": 0, "total": 3,
        }
        watchlist_dataz.append(output)



    filtered_data = watchlist_dataz if status == 'All' else [item for item in watchlist_dataz if item['status'] == status]
    
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = filtered_data[start:end]
    total_pages = math.ceil(len(filtered_data) / per_page)
    
    return jsonify({
        "data": paginated_data,
        "total_pages": total_pages,
        "current_page": page
    })

@app.route('/api/notifications')
def notifications():
    time.sleep(1)  # Simulate delay
    page = int(request.args.get('page', 1))
    per_page = 2
    start = (page - 1) * per_page
    end = start + per_page
    paginated_data = notifications_data[start:end]
    total_pages = math.ceil(len(notifications_data) / per_page)
    return jsonify({
        "data": paginated_data,
        "total_pages": total_pages,
        "current_page": page
    })
@app.route('/save/progress',methods=['POST'])
@limiter.limit("15 per minute")
def save_continue_watching():
    data = request.json

    try:
        if 'session_secret' in session:
            
            key = session["session_secret"]

            client = get_client(session["session_secret"], None)
            account = Account(client)

            acc = account.get()

            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
            
        elif bool(key):
            client = get_client(key, None)
            account = Account(client)

            acc = account.get()

            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
    except Exception:
        userInfo = None


    client = get_client(None,os.getenv('SECRET'))
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
                    Query.equal("episodeId",data.get('episode')),
                    Query.select(['continueId']),
                ]
            )
    
    if search['total'] > 0:

    
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
                "user":acc.get("$id"),
                "related_anime": data.get('anime'),
                "episode":data.get('episode'),
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
                "user":acc.get("$id"),
                "related_anime": data.get('anime'),
                "episode":data.get('episode'),
                "currentTime":data.get('currentTime'),
                "duration":data.get('duration'),
            }
        )

    return request.json

@app.route('/api/continue-watching-home')
def continue_watching_home():

    try:
        if 'session_secret' in session:
            
            key = session["session_secret"]

            client = get_client(session["session_secret"], None)
            account = Account(client)

            acc = account.get()

            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
            
        elif bool(key):
            client = get_client(key, None)
            account = Account(client)

            acc = account.get()

            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
    except Exception:
        userInfo = None

    client = get_client(None,os.getenv('SECRET'))
    databases = Databases(client)

    search = databases.list_documents(
                database_id=os.getenv('DATABASE_ID'),
                collection_id=os.getenv('CONTINUE_WATCHING'),
                queries=[
                    Query.equal("userId",acc.get("$id")),
                    Query.order_desc('$updatedAt'),
                    Query.select(['continueId','animeId','episodeId','currentTime','duration','server','language']),
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

        
        ff=  {
                "title": aniimeData["english"] if aniimeData['english'] is not None else aniimeData["romaji"],
                "link":f'/watch/{aniimeData["mainId"]}/{ep.get('number')}?server={data['server']}&lang={data['language']}',                
                "episode": ep.get('number'),
                "progress": f"{int(data['currentTime'] // 60)}:{int(data['currentTime'] % 60):02}",
                "duration": f"{int(data['duration'] // 60)}:{int(data['duration'] % 60):02}",
                "thumbnail": img.get('cover')
            }
        animes.append(ff)
    return jsonify(animes)

@app.route('/api/continue-watching')
def continue_watching():
    time.sleep(1)  # Simulate delay
    
    page = int(request.args.get('page', 1))
    per_page = 8
    start = (page - 1) * per_page
    end = start + per_page
    
    userInfo = None
    try:
        if 'session_secret' in session:
            key = session["session_secret"]
            client = get_client(session["session_secret"], None)
            account = Account(client)
            acc = account.get()
            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
        elif bool(key):
            client = get_client(key, None)
            account = Account(client)
            acc = account.get()
            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
    except Exception:
        userInfo = None
    
    if userInfo is None:
        return jsonify({"error": "User not authenticated"}), 401

    client = get_client(None, os.getenv('SECRET'))
    databases = Databases(client)

    search = databases.list_documents(
        database_id=os.getenv('DATABASE_ID'),
        collection_id=os.getenv('CONTINUE_WATCHING'),
        queries=[
            Query.equal("userId", acc.get("$id")),
            Query.order_desc('$updatedAt'),
            Query.select(['continueId','animeId','episodeId','currentTime','duration','server','language']),
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
    continue_watching_data = animes
    paginated_data = continue_watching_data[start:end]
    total_pages = math.ceil(len(continue_watching_data) / per_page)
    
    return jsonify({
        "data": paginated_data,
        "total_pages": total_pages,
        "current_page": page
    })

@app.route('/api/realtime/anime/<id>')
@limiter.limit("5000 per minute")
def realtime_anime_info(id):
    secret = os.getenv('SECRET')  
    client = get_client(None,secret)
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

@app.route('/api/notifications/<notification_type>', methods=['GET'])
@limiter.limit("30 per minute")
def get_notifications(notification_type):
    secret = request.args.get('secret')
    key = request.args.get('key')
    
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
            client = get_client(session["session_secret"], None)
            account = Account(client)
            acc = account.get()
        elif key:
            client = get_client(key, secret)
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
        client = get_client(key, secret)
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

                url = f'/watch/{anime['documents'][0]['mainId']}/{ep.get('number')}?lang={re.search(r'\[(.*?)\]', noa.get('message')).group(1).lower() if re.search(r'\[(.*?)\]', noa.get('message')) else None}&nid={noa.get('notificationId')}&type=anime'
                
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

                    url = f'/watch/{anime['documents'][0]['mainId']}/{ep.get('number')}'
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
                    url = f'/post/{pcomment.get('$id')}?nid={noa.get('notificationId')}'
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
    
@app.route('/api/notifications/count', methods=['GET'])
@limiter.limit("30 per minute")
def get_notifications_count():
    secret = request.args.get('secret')
    key = request.args.get('key')
    
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
            client = get_client(session["session_secret"], None)
            account = Account(client)
            acc = account.get()
        elif key:
            client = get_client(key, secret)
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
        client = get_client(key, secret)
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

@app.route('/api/top/posts', methods=['GET'])
def get_top_posts():
    client = get_client(None,os.getenv('SECRET'))
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
                queries=[Query.select(['username', 'userId'])]
            )
        url = f'/post/{post.get("postId")}'
        postz.append({
                    "id": post.get("postId"),
                    "title": post.get("title"),
                    "content": post.get("content"),
                    "link":url,
                    "tag": post.get("category"),
                    "time": format_relative_time(post.get("added")),
                    'authorAvatar': '/placeholder.svg?height=32&width=32',
                    'author':user.get('username'),
                    'comments':comments['total']
                })

    return jsonify({"posts": postz})

@app.route('/countdowns')
def countdowns():
    animes = []
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
        try:
            

            client = get_client(session["session_secret"],None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }

        except Exception as e:
            userInfo = None      
    elif bool(key):
        try:
            client = get_client(key,None)
            account = Account(client)

            acc = account.get()
            
            userInfo = {
                "userId":acc.get("$id"),
                "username" : acc.get("name"),
                "email" : acc.get("email")
            }
        except Exception as e:
            userInfo = None  
    else:
        userInfo = None

    client = get_client(None,os.getenv('SECRET'),)
    databases = Databases(client)


    topUpcoming = databases.list_documents(
            database_id = os.getenv('DATABASE_ID'),
            collection_id = os.getenv('Anime'),
            queries = [
                Query.equal("public",True),
                Query.is_not_null('airingAt'),
                Query.select(["mainId", "english","romaji","airingAt","nextAiringEpisode"]),
                Query.order_asc("airingAt"),
                Query.limit(100)
            ] # optional
        )

    count = topUpcoming.get('documents', [])
    animes = []
    

    for anii in count:
        print(anii.get('mainId'), anii.get('english'))

        img = databases.get_document(
                database_id = os.getenv('DATABASE_ID'),
                collection_id = os.getenv('ANIME_IMGS'),
                document_id=anii.get('mainId'),
                queries=[
                    Query.select(['cover'])
                ]
            )


        animes.append({
                    "id": anii.get("mainId"),
                    "title": anii.get("english") if anii.get('english') is not None else anii.get("romaji"),
                    "target_date":anii.get("airingAt")* 1000,
                    "cover": img.get("cover") ,
                    "episode":anii.get("nextAiringEpisode"),
                })

    return render_template('countdowns.html', animes=animes,userInfo=userInfo)

@app.route('/api/schedule', methods=['GET'])
def get_schedule():
    date = request.args.get('date')  # Expected format: YYYY-MM-DD
    user_timezone = request.args.get('timezone', 'UTC')

    # Initialize Appwrite client and databases service
    client = get_client(None, os.getenv('SECRET'))
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

    if data.get('newPassword') and data.get('confirmNewPassword'):

        if not data.get('newPassword') == data.get('confirmNewPassword'):
            return jsonify({'success': False, 'message': 'Passwords Doesn\'t match'}), 404

        
        client = get_client(session['session_secret'],None)
        account = Account(client)

        result = account.update_password(
            password = data.get('confirmNewPassword'),
            old_password = data.get('oldPassword') # optional
        )

    return jsonify({'success': True, 'message': 'Done'}), 200

@app.route('/auth/callback')
def callback():
    print(request)
    
@app.route('/realtime')
def realtime():
    return render_template('rtest.html')

@app.route('/player/<type>/<id>')
@limiter.limit("5 per minute") 
def player(type, id):
    try:
        if 'session_secret' in session:
            
            key = session["session_secret"]

            client = get_client(session["session_secret"], None)
            account = Account(client)

            acc = account.get()

            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
            
        elif bool(key):
            client = get_client(key, None)
            account = Account(client)

            acc = account.get()

            userInfo = {
                "userId": acc.get("$id"),
                "username": acc.get("name"),
                "email": acc.get("email")
            }
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

        client = get_client(None,os.getenv('SECRET'))
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


        return render_template('hi.html', video_url=video_url, subtitles=subtitles,userInfo=userInfo,current=current, duration=duration)

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
                'user':acc.get('$id'),
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
                'user':acc.get('$id'),
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
                'user':acc.get('$id'),
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
                'user':acc.get('$id'),
            }
        )

@app.route('/proxy/subtitle/<path:url>')
def proxy_subtitle(url):
    response = requests.get(url)
    return Response(response.content, content_type=response.headers['content-type'])        

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

@app.route('/')
@cache.cached(timeout=60)
def home():
    return render_template("home.html")

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
    socketio.run(app, debug=True,host='0.0.0.0')