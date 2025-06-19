from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import json
import os
from datetime import datetime
import uuid
import secrets
import logging
from functools import wraps
import requests
import base64

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = Flask(__name__, template_folder='templates')
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed file extensions for uploads
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'webp', 'heic', 'heif'} # For profile pictures, added HEIC/HEIF

# Chat Media Configurations
app.config['CHAT_MEDIA_UPLOAD_FOLDER'] = 'static/chat_media'
ALLOWED_CHAT_MEDIA_EXTENSIONS = {
    # Images
    'png', 'jpg', 'jpeg', 'gif', 'webp', 'heic', 'heif', # Added HEIC/HEIF for chat media
    # Audio
    'mp3', 'wav', 'ogg', 'm4a',
    # Video
    'mp4', 'webm', 'mov', 'avi',
    # Documents
    'pdf', 'doc', 'docx', 'txt', 'xls', 'xlsx', 'ppt', 'pptx',
    # Archives
    'zip', 'rar'
}


# ImgBB API Key
IMGBB_API_KEY = 'IMGBB_API_KEY'

socketio = SocketIO(app, cors_allowed_origins="*", async_mode='gevent')

# Ensure upload directories exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True) # For profile pictures
os.makedirs(app.config['CHAT_MEDIA_UPLOAD_FOLDER'], exist_ok=True) # For chat media

# JSON file paths
USERS_FILE = 'users.json'
MESSAGES_FILE = 'messages.json'

def allowed_file(filename):
    """Check if profile picture file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def allowed_chat_file(filename):
    """Check if chat media file extension is allowed"""
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_CHAT_MEDIA_EXTENSIONS

def load_json(filename):
    """Load data from JSON file with error handling"""
    if os.path.exists(filename):
        try:
            with open(filename, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if not content:
                    return {}
                return json.loads(content)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading {filename}: {e}")
            return {}
    return {}

def save_json(filename, data):
    """Save data to JSON file with error handling"""
    try:
        # Create backup before saving
        if os.path.exists(filename):
            backup_filename = f"{filename}.backup"
            if os.path.exists(backup_filename):
                os.remove(backup_filename)
            os.rename(filename, backup_filename)
        
        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    except IOError as e:
        logger.error(f"Error saving {filename}: {e}")
        # Restore backup if save failed
        backup_filename = f"{filename}.backup"
        if os.path.exists(backup_filename):
            os.rename(backup_filename, filename)
        raise

def get_current_time():
    """Get current timestamp"""
    return datetime.now().isoformat()

def login_required(f):
    """Decorator to require login for routes"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            return redirect(url_for('index'))
        return f(*args, **kwargs)
    return decorated_function

def validate_username(username):
    """Validate username format"""
    if not username or len(username) < 3 or len(username) > 30:
        return False
    return username.replace('_', '').replace('-', '').isalnum()

def update_user_status(username, status='online'):
    """Update user online status"""
    try:
        users = load_json(USERS_FILE)
        if username in users:
            users[username]['status'] = status
            users[username]['last_seen'] = get_current_time()
            save_json(USERS_FILE, users)
    except Exception as e:
        logger.error(f"Error updating user status: {e}")

# Routes
@app.route('/')
def index():
    if 'username' in session:
        return redirect(url_for('chat'))
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        
        # Validate input
        if not validate_username(username):
            flash('Username must be 3-30 characters long and contain only letters, numbers, hyphens, and underscores.')
            return render_template('register.html')
        
        if len(password) < 6:
            flash('Password must be at least 6 characters long.')
            return render_template('register.html')
        
        try:
            users = load_json(USERS_FILE)
            
            if username in users:
                flash('Username already exists!')
                return render_template('register.html')
            
            users[username] = {
                'password': generate_password_hash(password),
                'name': username,
                'profile_photo': '',
                'status': 'offline',
                'last_seen': get_current_time(),
                'created_at': get_current_time()
            }
            
            save_json(USERS_FILE, users)
            flash('Registration successful! Please login.')
            return redirect(url_for('index'))
        except Exception as e:
            logger.error(f"Registration error: {e}")
            flash('Registration failed. Please try again.')
            return render_template('register.html')
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username', '').strip()
    password = request.form.get('password', '')
    
    if not username or not password:
        flash('Please enter both username and password.')
        return redirect(url_for('index'))
    
    try:
        users = load_json(USERS_FILE)
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            session.permanent = True
            update_user_status(username, 'online')
            return redirect(url_for('chat'))
        else:
            flash('Invalid username or password!')
            return redirect(url_for('index'))
    except Exception as e:
        logger.error(f"Login error: {e}")
        flash('Login failed. Please try again.')
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    if 'username' in session:
        update_user_status(session['username'], 'offline')
        session.clear()
    return redirect(url_for('index'))

@app.route('/chat')
@login_required
def chat():
    try:
        users = load_json(USERS_FILE)
        current_user = session['username']
        # Pass page_style for chat page to use different base layout
        return render_template('chat.html', current_user=current_user, users=users, page_style='chat_whatsapp_look')
    except Exception as e:
        logger.error(f"Chat route error: {e}")
        flash('Error loading chat. Please try again.')
        return redirect(url_for('index'))

@app.route('/profile')
@login_required
def profile():
    try:
        users = load_json(USERS_FILE)
        user_data = users.get(session['username'], {})
        return render_template('profile.html', user=user_data, username=session['username'])
    except Exception as e:
        logger.error(f"Profile route error: {e}")
        flash('Error loading profile. Please try again.')
        return redirect(url_for('chat'))

@app.route('/update_profile', methods=['POST'])
@login_required
def update_profile():
    username = session['username']
    name = request.form.get('name', '').strip()
    
    if not name or len(name) > 100:
        flash('Name must be between 1 and 100 characters.')
        return redirect(url_for('profile'))
    
    try:
        users = load_json(USERS_FILE)
        users[username]['name'] = name
        
        # Handle profile photo upload
        if 'profile_photo' in request.files:
            file = request.files['profile_photo']
            if file and file.filename: # Check if a file is selected
                if allowed_file(file.filename):
                    try:
                        # Read image file and encode to base64
                        image_read = file.read()
                        image_b64 = base64.b64encode(image_read).decode('utf-8')

                        # Upload to ImgBB
                        imgbb_url = "https://api.imgbb.com/1/upload"
                        payload = {
                            "key": IMGBB_API_KEY,
                            "image": image_b64,
                            "name": secure_filename(file.filename) # Optional: send filename
                        }
                        response = requests.post(imgbb_url, data=payload, timeout=60)
                        response.raise_for_status() # Raise an exception for HTTP errors
                        
                        result = response.json()
                        if result.get("data") and result["data"].get("url"):
                            users[username]['profile_photo'] = result["data"]["url"]
                            # Optionally, delete old ImgBB image if its ID was stored and API supports it
                        else:
                            logger.error(f"ImgBB upload failed: {result.get('error', {}).get('message', 'Unknown error')}")
                            flash('Profile photo upload failed. ImgBB error.')
                            # Not returning here, will save other profile changes if any
                    except requests.exceptions.RequestException as e:
                        logger.error(f"ImgBB request error: {e}")
                        flash('Profile photo upload failed due to network error.')
                    except Exception as e:
                        logger.error(f"Error processing image for ImgBB: {e}")
                        flash('Profile photo upload failed.')
                else:
                    flash('Invalid file type. Please upload PNG, JPG, JPEG, GIF, or WebP files only.')
                    return redirect(url_for('profile'))
            # If no new file is selected, profile_photo remains unchanged unless explicitly cleared by other logic (not present here)

        save_json(USERS_FILE, users)
        flash('Profile updated successfully!')
        return redirect(url_for('profile'))
    except Exception as e:
        logger.error(f"Profile update error: {e}")
        flash('Error updating profile. Please try again.')
        return redirect(url_for('profile'))

@app.route('/api/users')
@login_required
def get_users():
    try:
        all_users_data = load_json(USERS_FILE)
        all_messages_data = load_json(MESSAGES_FILE)
        current_user_username = session['username']
        
        user_list_with_details = []
        for username, user_data_obj in all_users_data.items():
            if username == current_user_username:
                continue

            chat_key = f"{min(current_user_username, username)}_{max(current_user_username, username)}"
            chat_specific_messages = all_messages_data.get(chat_key, [])
            
            last_message_content = "No messages yet"
            # Use user creation time as a very distant past if no messages or no timestamp in last message
            last_message_time = user_data_obj.get('created_at', "1970-01-01T00:00:00.000000") 
            unread_count = 0
            
            if chat_specific_messages:
                last_msg = chat_specific_messages[-1]
                last_message_time = last_msg.get('timestamp', last_message_time) # Keep fallback
                
                msg_type = last_msg.get('type', 'text')
                msg_text_content = last_msg.get('message', '')
                msg_original_filename = last_msg.get('original_filename', '')

                if msg_type == 'text':
                    last_message_content = (msg_text_content[:25] + '...') if len(msg_text_content) > 25 else msg_text_content
                elif msg_type == 'image':
                    last_message_content = "📷 Photo"
                elif msg_type == 'audio':
                    last_message_content = f"🎵 {msg_original_filename if msg_original_filename else 'Audio'}"
                elif msg_type == 'video':
                    last_message_content = f"🎬 {msg_original_filename if msg_original_filename else 'Video'}"
                elif msg_type == 'file':
                    last_message_content = f"📄 {msg_original_filename if msg_original_filename else 'File'}"
                
                if last_msg.get('sender') == current_user_username:
                    last_message_content = f"You: {last_message_content}"
                
                for msg in chat_specific_messages:
                    if msg.get('receiver') == current_user_username and not msg.get('read', False):
                        unread_count += 1
                        
            user_list_with_details.append({
                'username': username,
                'name': user_data_obj.get('name', username),
                'status': user_data_obj.get('status', 'offline'),
                'last_seen': user_data_obj.get('last_seen', ''),
                'profile_photo': user_data_obj.get('profile_photo', ''),
                'last_message_content': last_message_content,
                'last_message_time': last_message_time,
                'unread_count': unread_count
            })
        
        user_list_with_details.sort(key=lambda u: u['last_message_time'], reverse=True)
        return jsonify(user_list_with_details)
    except Exception as e:
        logger.error(f"Get users API error: {e}")
        return jsonify({'error': 'Failed to load users'}), 500

@app.route('/api/search_users')
@login_required
def search_users():
    try:
        query = request.args.get('q', '').lower().strip()
        all_users_data = load_json(USERS_FILE)
        all_messages_data = load_json(MESSAGES_FILE)
        current_user_username = session['username']

        if not query: # If query is empty, return all users with details, sorted
            user_list_with_details = []
            for username, user_data_obj in all_users_data.items():
                if username == current_user_username:
                    continue
                # (Copied logic from get_users for consistency)
                chat_key = f"{min(current_user_username, username)}_{max(current_user_username, username)}"
                chat_specific_messages = all_messages_data.get(chat_key, [])
                last_message_content = "No messages yet"
                last_message_time = user_data_obj.get('created_at', "1970-01-01T00:00:00.000000")
                unread_count = 0
                if chat_specific_messages:
                    last_msg = chat_specific_messages[-1]
                    last_message_time = last_msg.get('timestamp', last_message_time)
                    msg_type = last_msg.get('type', 'text')
                    msg_text_content = last_msg.get('message', '')
                    msg_original_filename = last_msg.get('original_filename', '')
                    if msg_type == 'text':
                        last_message_content = (msg_text_content[:25] + '...') if len(msg_text_content) > 25 else msg_text_content
                    elif msg_type == 'image': last_message_content = "📷 Photo"
                    elif msg_type == 'audio': last_message_content = f"🎵 {msg_original_filename if msg_original_filename else 'Audio'}"
                    elif msg_type == 'video': last_message_content = f"🎬 {msg_original_filename if msg_original_filename else 'Video'}"
                    elif msg_type == 'file': last_message_content = f"📄 {msg_original_filename if msg_original_filename else 'File'}"
                    if last_msg.get('sender') == current_user_username: last_message_content = f"You: {last_message_content}"
                    for msg in chat_specific_messages:
                        if msg.get('receiver') == current_user_username and not msg.get('read', False): unread_count += 1
                user_list_with_details.append({
                    'username': username, 'name': user_data_obj.get('name', username),
                    'status': user_data_obj.get('status', 'offline'), 'last_seen': user_data_obj.get('last_seen', ''),
                    'profile_photo': user_data_obj.get('profile_photo', ''), 'last_message_content': last_message_content,
                    'last_message_time': last_message_time, 'unread_count': unread_count
                })
            user_list_with_details.sort(key=lambda u: u['last_message_time'], reverse=True)
            return jsonify(user_list_with_details)

        # If there is a query, filter users
        filtered_users_with_details = []
        for username, user_data_obj in all_users_data.items():
            if username != current_user_username and \
               (query in username.lower() or query in user_data_obj.get('name', '').lower()):
                # (Copied logic from get_users for consistency)
                chat_key = f"{min(current_user_username, username)}_{max(current_user_username, username)}"
                chat_specific_messages = all_messages_data.get(chat_key, [])
                last_message_content = "No messages yet"
                last_message_time = user_data_obj.get('created_at', "1970-01-01T00:00:00.000000")
                unread_count = 0
                if chat_specific_messages:
                    last_msg = chat_specific_messages[-1]
                    last_message_time = last_msg.get('timestamp', last_message_time)
                    msg_type = last_msg.get('type', 'text')
                    msg_text_content = last_msg.get('message', '')
                    msg_original_filename = last_msg.get('original_filename', '')
                    if msg_type == 'text':
                        last_message_content = (msg_text_content[:25] + '...') if len(msg_text_content) > 25 else msg_text_content
                    elif msg_type == 'image': last_message_content = "📷 Photo"
                    elif msg_type == 'audio': last_message_content = f"🎵 {msg_original_filename if msg_original_filename else 'Audio'}"
                    elif msg_type == 'video': last_message_content = f"🎬 {msg_original_filename if msg_original_filename else 'Video'}"
                    elif msg_type == 'file': last_message_content = f"📄 {msg_original_filename if msg_original_filename else 'File'}"
                    if last_msg.get('sender') == current_user_username: last_message_content = f"You: {last_message_content}"
                    for msg in chat_specific_messages:
                        if msg.get('receiver') == current_user_username and not msg.get('read', False): unread_count += 1
                filtered_users_with_details.append({
                    'username': username, 'name': user_data_obj.get('name', username),
                    'status': user_data_obj.get('status', 'offline'), 'last_seen': user_data_obj.get('last_seen', ''),
                    'profile_photo': user_data_obj.get('profile_photo', ''), 'last_message_content': last_message_content,
                    'last_message_time': last_message_time, 'unread_count': unread_count
                })
        
        filtered_users_with_details.sort(key=lambda u: u['last_message_time'], reverse=True)
        return jsonify(filtered_users_with_details)
    except Exception as e:
        logger.error(f"Search users API error: {e}")
        return jsonify({'error': 'Search failed'}), 500

@app.route('/api/messages/<chat_with>')
@login_required
def get_messages(chat_with):
    try:
        # Validate chat_with parameter
        users = load_json(USERS_FILE)
        if chat_with not in users:
            return jsonify({'error': 'User not found'}), 404
        
        messages = load_json(MESSAGES_FILE)
        current_user = session['username']
        
        chat_key = f"{min(current_user, chat_with)}_{max(current_user, chat_with)}"
        chat_messages = messages.get(chat_key, [])
        
        return jsonify(chat_messages)
    except Exception as e:
        logger.error(f"Get messages API error: {e}")
        return jsonify({'error': 'Failed to load messages'}), 500

# Socket.IO events
@socketio.on('connect')
def handle_connect():
    if 'username' in session:
        username = session['username']
        join_room(username)
        update_user_status(username, 'online')
        emit('user_status_update', {'username': username, 'status': 'online'}, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'username' in session:
        username = session['username']
        leave_room(username)
        update_user_status(username, 'offline')
        emit('user_status_update', {'username': username, 'status': 'offline'}, broadcast=True)

@socketio.on('send_message')
def handle_send_message(data):
    if 'username' not in session:
        emit('error', {'message': 'Not authenticated'})
        return
    
    try:
        sender = session['username']
        receiver = data.get('receiver', '').strip()
        message = data.get('message', '').strip() # For text messages, this is the content; for media, this is the file_url
        message_type = data.get('type', 'text') # 'text', 'image', 'audio', 'video', 'file'
        original_filename = data.get('original_filename') # For 'file' type primarily, but can be sent for all media
        client_upload_id = data.get('clientUploadId') # Client-side ID for upload placeholder
        replied_to_id = data.get('replied_to_id') # ID of the message being replied to
        
        # Validate input
        if not receiver:
            emit('error', {'message': 'Recipient not specified'})
            return
        
        if not message: # Message content (text or URL) must exist
             emit('error', {'message': 'Empty message or file URL missing'})
             return

        if message_type == 'text' and len(message) > 5000:  # Limit text message length
            emit('error', {'message': 'Text message too long'})
            return
        
        # Verify receiver exists
        users = load_json(USERS_FILE)
        if receiver not in users:
            emit('error', {'message': 'Recipient not found'})
            return

        sender_name = users.get(sender, {}).get('name', sender) # Get sender's display name
        
        message_data = {
            'id': str(uuid.uuid4()),
            'sender': sender,
            'sender_name': sender_name, # Add sender's display name
            'receiver': receiver,
            'message': message, # URL for media, text for text
            'type': message_type,
            'original_filename': original_filename, # Store original filename
            'timestamp': get_current_time(),
            'read': False,
            'clientUploadId': client_upload_id, # Include clientUploadId if present
            'replied_to_id': None, # Initialize
            'replied_to_message_details': None # Initialize
        }

        # Handle reply
        if replied_to_id:
            messages_all_chats = load_json(MESSAGES_FILE)
            chat_key_for_original_msg = f"{min(sender, receiver)}_{max(sender, receiver)}" # Assuming reply is within same chat
            original_message_found = None
            if chat_key_for_original_msg in messages_all_chats:
                for msg_item in messages_all_chats[chat_key_for_original_msg]:
                    if msg_item['id'] == replied_to_id:
                        original_message_found = msg_item
                        break
            
            if original_message_found:
                original_sender_username = original_message_found.get('sender')
                original_sender_name = users.get(original_sender_username, {}).get('name', original_sender_username)
                
                message_data['replied_to_id'] = replied_to_id
                message_data['replied_to_message_details'] = {
                    'sender': original_sender_username,
                    'sender_name': original_sender_name,
                    'content': original_message_found.get('message'),
                    'type': original_message_found.get('type'),
                    'original_filename': original_message_found.get('original_filename')
                }
            else:
                logger.warning(f"Replied message ID {replied_to_id} not found.")
                # Decide if you want to send the message without reply context or error out
                # For now, it will send without reply context if original not found.

        # Save message
        messages = load_json(MESSAGES_FILE)
        chat_key = f"{min(sender, receiver)}_{max(sender, receiver)}"
        
        if chat_key not in messages:
            messages[chat_key] = []
        
        messages[chat_key].append(message_data)
        save_json(MESSAGES_FILE, messages)
        
        # Send to receiver and confirm to sender
        emit('new_message', message_data, room=receiver)
        emit('message_sent', message_data, room=sender)
        
    except Exception as e:
        logger.error(f"Send message error: {e}")
        emit('error', {'message': 'Failed to send message'})

@socketio.on('message_read')
def handle_message_read(data):
    if 'username' not in session:
        return
    
    try:
        message_id = data.get('message_id')
        chat_with = data.get('chat_with')
        current_user = session['username']
        
        if not message_id or not chat_with:
            return
        
        messages = load_json(MESSAGES_FILE)
        chat_key = f"{min(current_user, chat_with)}_{max(current_user, chat_with)}"
        
        if chat_key in messages:
            for msg in messages[chat_key]:
                if msg['id'] == message_id and msg['receiver'] == current_user:
                    msg['read'] = True
                    break
            
            save_json(MESSAGES_FILE, messages)
            emit('message_read_status', {'message_id': message_id, 'read': True}, room=chat_with)
            
    except Exception as e:
        logger.error(f"Message read error: {e}")

@socketio.on('delete_message')
def handle_delete_message(data):
    if 'username' not in session:
        return
    
    try:
        message_id = data.get('message_id')
        chat_with = data.get('chat_with')
        current_user = session['username']
        
        if not message_id or not chat_with:
            return
        
        messages = load_json(MESSAGES_FILE)
        chat_key = f"{min(current_user, chat_with)}_{max(current_user, chat_with)}"
        
        if chat_key in messages:
            # Only allow deletion of own messages
            original_length = len(messages[chat_key])
            messages[chat_key] = [
                msg for msg in messages[chat_key] 
                if not (msg['id'] == message_id and msg['sender'] == current_user)
            ]
            
            if len(messages[chat_key]) < original_length:
                save_json(MESSAGES_FILE, messages)
                emit('message_deleted', {'message_id': message_id}, room=current_user)
                emit('message_deleted', {'message_id': message_id}, room=chat_with)
                
    except Exception as e:
        logger.error(f"Delete message error: {e}")

@socketio.on('clear_chat')
def handle_clear_chat(data):
    if 'username' not in session:
        return
    
    try:
        chat_with = data.get('chat_with')
        current_user = session['username']
        
        if not chat_with:
            return
        
        messages = load_json(MESSAGES_FILE)
        chat_key = f"{min(current_user, chat_with)}_{max(current_user, chat_with)}"
        
        if chat_key in messages:
            messages[chat_key] = []
            save_json(MESSAGES_FILE, messages)
            emit('chat_cleared', {'chat_with': chat_with}, room=current_user)
            
    except Exception as e:
        logger.error(f"Clear chat error: {e}")

# WebRTC Signaling Socket.IO Events
@socketio.on('voice_call_offer')
def handle_voice_call_offer(data):
    target_user = data.get('target')
    offer = data.get('offer')
    caller_name = data.get('callerName', session.get('username')) # Use session username if callerName not provided
    
    if not target_user or not offer:
        logger.warning(f"Invalid voice_call_offer received: {data}")
        return
        
    logger.info(f"Relaying voice call offer from {session.get('username')} to {target_user}")
    # Emit to the specific user's room (which should be their username)
    emit('voice_call_offer', {'from': session.get('username'), 'offer': offer, 'callerName': caller_name}, room=target_user)

@socketio.on('voice_call_answer')
def handle_voice_call_answer(data):
    target_user = data.get('target') # This is the original caller
    answer = data.get('answer')

    if not target_user or not answer:
        logger.warning(f"Invalid voice_call_answer received: {data}")
        return

    logger.info(f"Relaying voice call answer from {session.get('username')} to {target_user}")
    emit('voice_call_answer', {'from': session.get('username'), 'answer': answer}, room=target_user)

@socketio.on('ice_candidate')
def handle_ice_candidate(data):
    target_user = data.get('target')
    candidate = data.get('candidate')
    sender_user = data.get('sender', session.get('username')) # Use sender if provided, else current user

    if not target_user or not candidate:
        logger.warning(f"Invalid ice_candidate received: {data}")
        return
        
    logger.info(f"Relaying ICE candidate from {sender_user} to {target_user}")
    # The 'from' field here should be the original sender of the candidate
    emit('ice_candidate', {'from': sender_user, 'candidate': candidate}, room=target_user)

@socketio.on('call_rejected')
def handle_call_rejected(data):
    target_user = data.get('target') # The user who initiated the call
    rejected_by = data.get('rejected_by', session.get('username'))
    reason = data.get('reason', '')

    if not target_user:
        logger.warning(f"Invalid call_rejected received: {data}")
        return

    # Fetch display name of the user who rejected
    users = load_json(USERS_FILE)
    rejected_by_name = users.get(rejected_by, {}).get('name', rejected_by)

    logger.info(f"Relaying call rejection from {rejected_by} to {target_user}")
    emit('call_rejected', {'rejected_by': rejected_by, 'rejected_by_name': rejected_by_name, 'reason': reason}, room=target_user)

@socketio.on('call_ended')
def handle_call_ended(data):
    target_user = data.get('target') # The other user in the call
    ended_by = data.get('ended_by', session.get('username'))

    if not target_user:
        # This might happen if one user hangs up and the other is already disconnected
        logger.info(f"Call ended by {ended_by}, no specific target to notify or target already gone.")
        return

    users = load_json(USERS_FILE)
    ended_by_name = users.get(ended_by, {}).get('name', ended_by)
    
    logger.info(f"Relaying call ended by {ended_by} to {target_user}")
    emit('call_ended', {'ended_by': ended_by, 'ended_by_name': ended_by_name}, room=target_user)

# Typing Indicator Events
@socketio.on('typing_start')
def handle_typing_start(data):
    if 'username' not in session:
        return # Not authenticated
    
    sender_username = data.get('sender')
    receiver_username = data.get('receiver')

    if not sender_username or not receiver_username:
        logger.warning(f"Invalid typing_start data: {data}")
        return

    # Ensure the sender from the data matches the session user for security/consistency
    if sender_username != session['username']:
        logger.warning(f"Typing_start sender mismatch. Session: {session['username']}, Data: {sender_username}")
        return

    logger.info(f"User {sender_username} started typing to {receiver_username}")
    emit('user_typing', {'sender': sender_username}, room=receiver_username)

@socketio.on('typing_stop')
def handle_typing_stop(data):
    if 'username' not in session:
        return # Not authenticated

    sender_username = data.get('sender')
    receiver_username = data.get('receiver')

    if not sender_username or not receiver_username:
        logger.warning(f"Invalid typing_stop data: {data}")
        return
    
    if sender_username != session['username']:
        logger.warning(f"Typing_stop sender mismatch. Session: {session['username']}, Data: {sender_username}")
        return

    logger.info(f"User {sender_username} stopped typing to {receiver_username}")
    emit('user_stopped_typing', {'sender': sender_username}, room=receiver_username)


@socketio.on('typing')
def handle_typing(data):
    if 'username' not in session:
        return
    
    recipient = data.get('recipient')
    if recipient:
        logger.info(f"User {session['username']} is typing to {recipient}")
        emit('user_typing', {'username': session['username']}, room=recipient)

@socketio.on('stop_typing')
def handle_stop_typing(data):
    if 'username' not in session:
        return
        
    recipient = data.get('recipient')
    if recipient:
        logger.info(f"User {session['username']} stopped typing to {recipient}")
        emit('user_stopped_typing', {'username': session['username']}, room=recipient)

@app.errorhandler(413)
def too_large(e):
    # Check if the request wants a JSON response (typical for API calls)
    if request.accept_mimetypes.accept_json and \
       not request.accept_mimetypes.accept_html:
        return jsonify({'success': False, 'error': 'File too large. Maximum size is 16MB.'}), 413
    # Otherwise, assume it's a regular form submission
    flash('File too large. Maximum size is 16MB.')
    # Redirect to profile or a more general error page if preferred
    # For now, keeping profile redirect as it was the original behavior for some cases
    if 'profile' in request.referrer: # A simple check, might need refinement
        return redirect(url_for('profile'))
    return redirect(request.referrer or url_for('index'))


@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal server error: {error}")
    return render_template('error.html', error="Internal server error"), 500

@app.route('/upload_chat_media', methods=['POST'])
@login_required
def upload_chat_media():
    if 'file' not in request.files:
        return jsonify({'success': False, 'error': 'No file part'}), 400
    
    file = request.files['file']
    if file.filename == '':
        return jsonify({'success': False, 'error': 'No selected file'}), 400
    
    if file and allowed_chat_file(file.filename):
        # Create a more unique filename to prevent collisions and secure it
        unique_id = str(uuid.uuid4())
        original_ext = file.filename.rsplit('.', 1)[1].lower() if '.' in file.filename else ''
        filename = secure_filename(f"{unique_id}.{original_ext}")
        
        file_path = os.path.join(app.config['CHAT_MEDIA_UPLOAD_FOLDER'], filename)
        try:
            file.save(file_path)
            file_url = url_for('static', filename=f'chat_media/{filename}')
            
            # Determine file type for the message
            ext = filename.rsplit('.', 1)[1].lower()
            file_type = 'file' # default
            if ext in {'png', 'jpg', 'jpeg', 'gif', 'webp'}:
                file_type = 'image'
            elif ext in {'mp3', 'wav', 'ogg', 'm4a'}:
                file_type = 'audio'
            elif ext in {'mp4', 'webm', 'mov'}: # Note: .avi might not be web-playable directly
                file_type = 'video'
            
            return jsonify({
                'success': True, 
                'file_url': file_url, 
                'file_type': file_type,
                'original_filename': file.filename # Send back original filename
            }), 200
        except Exception as e:
            logger.error(f"Error saving chat media: {e}")
            return jsonify({'success': False, 'error': 'Failed to save file'}), 500
    else:
        # Construct a more informative error message about allowed types
        allowed_types_str = ", ".join(sorted(list(ALLOWED_CHAT_MEDIA_EXTENSIONS)))
        error_msg = f"File type not allowed. Allowed types: {allowed_types_str}."
        if file.filename and '.' in file.filename:
             actual_ext = file.filename.rsplit('.',1)[-1].lower()
             error_msg = f"File type '{actual_ext}' not allowed. Allowed types: {allowed_types_str}."
        elif file.filename:
             error_msg = f"File '{file.filename}' has an unrecognized or disallowed type. Allowed types: {allowed_types_str}."


        return jsonify({'success': False, 'error': error_msg}), 400

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5010, allow_unsafe_werkzeug=True, use_reloader=False)
