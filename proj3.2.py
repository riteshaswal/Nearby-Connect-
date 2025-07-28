






from flask import Flask, request, jsonify, send_file, session, redirect, render_template
from flask_cors import CORS
from pymongo import MongoClient
from bson.objectid import ObjectId
from datetime import datetime
from werkzeug.security import generate_password_hash, check_password_hash
import os
from werkzeug.utils import secure_filename
from flask_socketio import SocketIO, emit
import json
from flask import request, jsonify, session
from geopy.distance import geodesic
from flask import send_from_directory
from flask import make_response, session, redirect, url_for



from flask_socketio import join_room, leave_room



# Create Flask app first
app = Flask(__name__)
app.secret_key = "your_secret_key"
CORS(app, supports_credentials=True)
socketio = SocketIO(app, cors_allowed_origins="*")
app.config['UPLOAD_FOLDER'] = 'static/uploads'  # or wherever you want to store images

# Initialize SocketIO after app creation


# Create folder if it doesn't exist
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# MongoDB setup
client = MongoClient("mongodb://localhost:27017/")
db = client["connectDB"]
collection = db["security"]
notifications_collection = db["notification"]
messages =db["messages"]


class JSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, ObjectId):
            return str(o)
        return super().default(o)

app.json_encoder = JSONEncoder


@app.route('/')
def serve_html():
    return send_file('proj3.html')

@app.route('/proj3.3.html')
def serve_dashboard():
    if 'username' in session:
        return send_file('proj3.3.html')
    return redirect('/login')
@app.route('/proj3.9.html')
def serve_location_page():
    if 'username' in session:
        return send_file('proj3.9.html')
    return redirect('/login')


@app.route('/create-account', methods=['POST'])
def create_account():
    data = request.json
    username = data.get("username")
    email = data.get("email")
    password = data.get("password")

    if not username or not email or not password:
        return jsonify({"error": "Missing fields"}), 400

    hashed_password = generate_password_hash(password)

    # Insert user with default profile picture
    result = collection.insert_one({
        "username": username,
        "email": email,
        "password": hashed_password,
        "profile_pic": "/static/uploads/dummyperson copy.png"  # Default profile picture
    })

    return jsonify({"message": "Account created", "id": str(result.inserted_id)}), 201
@app.route('/login', methods=['GET'])
def login_page():
    return send_file('/Users/riteshaswal/proj3.html')
@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = collection.find_one({"username": data['username']})

    if user and check_password_hash(user['password'], data['password']):
        session['username'] = user['username']
        session['email'] = user['email']
        session['user_id'] = str(user['_id'])

        return jsonify({"message": "Login successful!"}), 200
    else:
        return jsonify({"error": "Invalid username or password"}), 401
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.route('/user-info', methods=['GET'])
def user_info():
    # Assuming you're using session to track logged-in users, fetch the username from the session
    username = session.get('username')  # Or however you store the logged-in user info
    
    if username:
        # Find the user's document from MongoDB
        user = collection.find_one({"username": username})
        
        if user:
            # Return the necessary user details including the bio, profession, and hobbies
            return jsonify({
                "username": user.get("username"),
                "email": user.get("email"),
                "profile_pic": user.get("profile_pic", "/static/uploads/dummyperson copy.png"),
                "bio": user.get("bio", ""),
                "profession": user.get("profession", ""),
                "hobbies": user.get("hobbies", ""),
                "connections_count": len(user.get("connections", [])),
                "requests_count": len(user.get("connections request", [])),
                "connections": user.get("connections", []),
                "connection_requests": user.get("connections request", [])
})
        else:
            return jsonify({"error": "User not found"}), 404
    else:
        return jsonify({"error": "User not logged in"}), 403

@app.route('/upload-profile-pic', methods=['POST'])
def upload_profile_pic():
    if 'profile_pic' not in request.files:
        return jsonify(success=False, error='No file uploaded')

    file = request.files['profile_pic']
    if file and allowed_file(file.filename):
        username = session.get('username')
        if not username:
            return jsonify(success=False, error='Not logged in')

        filename = secure_filename(f"{username}_profile.jpg")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)

        # Save path to DB
        image_url = f"/static/uploads/{filename}"
        collection.update_one(
    {"username": username},
    {"$set": {"profile_pic": image_url}}
)

        return jsonify(success=True, image_url=image_url)
    else:
        return jsonify(success=False, error='Invalid file type')
@app.route('/save-profile', methods=['POST'])
def save_profile():
    # Get the current logged-in user's username (or any identifier)
    username = session.get('username')
    
    if username:
        # Get the updated profile data from the request
        data = request.get_json()
        bio = data.get("bio", "")
        profession = data.get("profession", "")
        hobbies = data.get("hobbies", "")
        
        # Find the user in the database and update the relevant fields
        result = collection.update_one(
    {"username": username},  # Find the user by their username
    {"$set": {
        "bio": bio,
        "profession": profession,
        "hobbies": hobbies
    }}
)
        
        if result.modified_count > 0:
            return jsonify({"success": True, "message": "Profile updated successfully"})
        else:
            return jsonify({"success": False, "error": "No changes made or user not found"}), 400
    else:
        return jsonify({"error": "User not logged in"}), 403
    
        user_dict = dict(user)
        username = user["username"]
        user_dict["is_request_sent"] = username in sent_requests
        user_dict["is_connected"] = username in connected_users
        final_results.append(user_dict)

    return jsonify(final_results)
@app.route('/proj3.6.html')
def serve_notifications_page():
    if 'username' in session:
        return send_file('proj3.6.html')
    return redirect('/login')
@app.route('/proj3.7.html')
def serve_chatlog():
    if 'username' in session:
        return send_file('proj3.7.html')
    return redirect('/login')
@app.route('/proj3.4.html')
def serve_search_page():
    if 'username' in session:
        return send_file('proj3.4.html')
    return redirect('/login')
@app.route('/proj3.5.html')
def serve_profile_page():
    if 'username' in session:
        return send_file('proj3.5.html')
    return redirect('/login')
@app.route('/add-connection', methods=['POST'])
def add_connection():
    data = request.get_json()
    current_user = session.get('username')
    target_user = data.get('username')

    if not current_user or not target_user:
        return jsonify(success=False, message="Invalid users")

  

    # Add to connections
    collection.update_one(
        {"username": target_user},
        {"$addToSet": {"connections request": current_user}}
    )
    collection.update_one(
        {"username": current_user},
        {"$addToSet": {"connections_sent": target_user}}  # not "connections sent"
    )

    # Create notification
    notifications_collection.insert_one({
        "to": target_user,
        "from": current_user,
        "message": f"{current_user} sent you a connection request",
        "type": "connections request",  # Added type
        "timestamp": datetime.now().isoformat(),
        "read": False
    })

    # Emit notification to the target user (via Socket.IO)
    socketio.emit('new_notification', {
        "from": current_user,
        "to": target_user,
        "message": f"{current_user} sent you a connection request",
        "type": "connections request",
        "timestamp": datetime.now().isoformat()
    }, room=target_user)
    socketio.emit('new_request', {
        "from": current_user,
        "to": target_user
    }, room=target_user)
    return jsonify(success=True)
from datetime import datetime

@app.route('/get-notifications')
def get_notifications():
    username = session.get("username")
    if not username:
        return jsonify([])

    # Convert all timestamps to datetime for sorting manually
    results = list(notifications_collection.find({"to": username}))
    
    # Normalize and sort by timestamp descending
    def parse_ts(n):
        ts = n.get("timestamp")
        if isinstance(ts, datetime):
            return ts
        try:
            return datetime.fromisoformat(str(ts))
        except:
            return datetime.min  # fallback for broken data

    results.sort(key=parse_ts, reverse=True)

    final_notifications = []
    for n in results:
        sender = n.get("from")
        sender_doc = collection.find_one({"username": sender}, {"profile_pic": 1})
        profile_pic = sender_doc.get("profile_pic", "/static/uploads/dummyperson copy.png") if sender_doc else "/static/default.jpg"

        ts_obj = parse_ts(n)
        timestamp = ts_obj.isoformat(timespec='seconds') if ts_obj else ""

        final_notifications.append({
            "from": sender,
            "message": n.get("message"),
            "timestamp": timestamp,
            "type": n.get("type"),
            "profile_pic": profile_pic
        })
     

    return jsonify(final_notifications)
@app.route('/remove-connection', methods=['POST'])
def remove_connection():
    data = request.get_json()
    current_user = session.get('username')
    target_user = data.get("username")

    if not current_user or not target_user:
        return jsonify({"success": False, "message": "Missing user info"}), 400

    # Normalize usernames (stripping extra spaces and making lowercase)
    

    # Debugging: Print out the users
    print(f"[REMOVE-CONNECTION] Current User: {current_user}, Target User: {target_user}")

    # Remove from connections (removing current_user from target_user's connection request and vice versa)
    collection.update_one(
        {"username": current_user},
        {"$pull": {"connections_sent": target_user}}
    )
    collection.update_one(
        {"username": target_user},
        {"$pull": {"connections request": current_user}}
    )

    # Debugging: Check if users were updated successfully
    print(f"Updated connections for {current_user} and {target_user}")

    # Delete relevant notification (looking for messages about connection requests)
    delete_result = notifications_collection.delete_many({
    "to": target_user,
    "from": current_user,
    "message": {"$regex": "connection request", "$options": "i"}
})

    # Debugging: Print out the number of notifications deleted
    print(f"🗑️ Deleted {delete_result.deleted_count} notification(s)")

    # If no notifications were deleted, print out the messages in the collection for debugging
    if delete_result.deleted_count == 0:
        print("No notifications deleted. Checking existing notifications:")
        notifications_to_check = notifications_collection.find({
            "to": target_user,
            "from": current_user
        })
        for notification in notifications_to_check:
            print(f"Existing Notification: {notification['message']}")
    socketio.emit(
    'remove_notification',
    {
        "from": current_user,
        "to": target_user,
        "type": "connection request"
    },
    room=target_user
)
    socketio.emit('remove_request', {
        "from": current_user,
        "to": target_user
    }, room=target_user)

    return jsonify({"success": True, "message": "Connection request removed"})

@app.route('/user-profile', methods=['GET'])
def view_user_profile():
    username = request.args.get('username')

    if not username:
        return jsonify({"error": "No username provided"}), 400

    user = collection.find_one({"username": username})
    if not user:
        return jsonify({"error": "User not found"}), 404

    return jsonify({
        "_id": str(user.get("_id")),
        "username": user.get("username"),
        "profile_pic": user.get("profile_pic", "/static/uploads/dummyperson copy.png"),
        "bio": user.get("bio", ""),
        "profession": user.get("profession", ""),
        "hobbies": user.get("hobbies", ""),
        "connections_request": user.get("connections request", []),
        "connections_sent": user.get("connections_sent", []),
        "connections": user.get("connections", [])
    })
@socketio.on('connect')
def handle_connect():
    username = session.get('username')
    if username:
        join_room(username)
        print(f"User {username} has connected and joined their room.")

@socketio.on('disconnect')
def handle_disconnect():
    current_user = session.get('username')
    if current_user:
        leave_room(current_user)
        print(f"User {current_user} has disconnected and left their room.")

@app.route('/send-notification', methods=['POST'])
def send_notification():
    # Logic to send the notification (could be adding to MongoDB, etc.)
    notification = {
        'from': 'System',
        'message': 'You have a new notification!',
        'timestamp': datetime.now().isoformat()
    }
    # Emitting to all connected clients
    socketio.emit('new_notification', notification, broadcast=True)
    return jsonify({'message': 'Notification sent'}), 200
@app.route('/get-current-username')
def get_current_username():
    if 'username' in session:
        return jsonify({'username': session['username']})
    return jsonify({'error': 'Not logged in'}), 401
@app.route('/delete-notification', methods=['POST'])
def delete_notification():
    data = request.json
    current_user = session.get('username')
    from_user = data.get('from')
    notif_type = data.get('type')

    result = notifications_collection.delete_one({
        "to": current_user,
        "from": from_user,
        "type": notif_type
    })

    # You could also emit `remove_notification` to other client if needed

    return jsonify(success=result.deleted_count > 0)
@app.route('/accept-connection', methods=['POST'])
def accept_connection():
    data = request.json
    current_user = session.get("username")
    from_user = data.get("from")

    if not current_user or not from_user:
        return jsonify(success=False, error="Invalid data")

    # Step 1: Add each other as connections
    # Step 1: Add each other as connections and clean up all mutual request traces
    collection.update_one(
        {"username": current_user},
        {
            "$addToSet": {"connections": from_user},
            "$pull": {
                "connections request": from_user,
                "connections_sent": from_user  # remove mutual sent if exists
                }
        }
    )
    collection.update_one(
        {"username": from_user},
        {
            "$addToSet": {"connections": current_user},
            "$pull": {
                "connections_sent": current_user,
                "connections request": current_user  # remove mutual request if exists
                }
            }
    )

    # Step 2: Delete the old connection request notification
    notifications_collection.delete_many({
    "$or": [
        {"to": current_user, "from": from_user, "type": "connections request"},
        {"to": from_user, "from": current_user, "type": "connections request"}
    ]
})

    # Step 3: Emit event to remove old notification in UI
    socketio.emit('remove_notification', {
        "from": from_user,
        "to": current_user,
        "type": "connections request"
        }, room=current_user)
    socketio.emit('remove_notification', {
        "from": current_user,
        "to": from_user,
        "type": "connections request"
        }, room=from_user)

    # Step 4: Create new notification
    notification_data = {
        "from": current_user,
        "to": from_user,
        "message": f"{current_user} accepted your connection request",
        "type": "connection_accepted",
        "timestamp": datetime.now().isoformat(),
        "read": False
    }

    # Step 5: Save new notification and emit it
    inserted = notifications_collection.insert_one(notification_data)
    notification_data['_id'] = str(inserted.inserted_id) 
    

    socketio.emit('new_notification', notification_data, room=from_user)
    # Emit to from_user to remove the UI request
    socketio.emit('remove_request_ui', {
        "from": current_user  # Who accepted the request
    }, room=from_user)

    return jsonify(success=True)
@app.route('/remove-connection-request', methods=['POST'])
def remove_connection_request():
    data = request.json
    current_user = session.get("username")
    from_user = data.get("from")

    if not current_user or not from_user:
        return jsonify(success=False, error="Invalid data")

    # Just remove the request
    collection.update_one({"username": current_user}, {
    "$pull": {"connections request": from_user}  # Note the space
    })
    collection.update_one({"username": from_user}, {
    "$pull": {"connections_sent": current_user}
    })

    # Optional: remove notification
    notifications_collection.delete_one({
        "to": current_user,
        "from": from_user,
        "type": "connections request"
    })
    socketio.emit('remove_notification', {
        "from": from_user,
        "to": current_user,
        "type": "connections request"
    }, room=current_user)
    # Emit to from_user to remove the UI request
    socketio.emit('remove_request_ui', {
        "from": current_user  # Who accepted the request
    }, room=from_user)


    return jsonify(success=True)
@app.route('/unread-notifications')
def unread_notifications():
    username = session.get('username')
    print("Current session username:", username)  # Debug line
    if not username:
        return jsonify({'unread': False})

    unread = db.notifications_collection.find_one({
        "to": username,
        "read": False
    })

    print("Unread notification found:", unread is not None)  # Debug line
    return jsonify({'unread': bool(unread)})
@app.route('/mark-notifications-read', methods=['POST'])
def mark_notifications_read():
    username = session.get('username')
    if not username:
        return jsonify({'success': False})

    db.notifications_collection.update_many(
        {"to": username, "read": False},
        {"$set": {"read": True}}
    )

    return jsonify({'success': True})
def check_if_in_chat(current_user, other_user):
    user_doc = collection.find_one({'username': current_user}, {'connections': 1})
    if not user_doc or 'connections' not in user_doc:
        return False
    return other_user in user_doc['connections']


@app.route('/search-users_in_connectionlist')
def search_users_in_connectionlist():
    # Get the search query and the current logged-in user
    query = request.args.get('query', '').strip().lower()
    current_user = session.get('username')

    # If no user is logged in, return empty results
    if not current_user:
        return jsonify([])

    # Get current user's connections from the database
    user_doc = collection.find_one({'username': current_user}, {'connections': 1})
    if not user_doc or 'connections' not in user_doc:
        return jsonify([])

    # Get the list of connection usernames
    connection_usernames = user_doc['connections']

    # Search for users in the current user's connections that match the query
    results = collection.find({
        'username': {'$in': connection_usernames},
        '$or': [
            {'username': {'$regex': query, '$options': 'i'}},  # Search by username
            {'full_name': {'$regex': query, '$options': 'i'}}  # Optional: search by full name if present
        ]
    })

    # Build the result array to return to the frontend
    final = []
    for user in results:
        final.append({
            'username': user['username'],
            'profile_pic': user.get('profile_pic'),
            'already_in_chat': check_if_in_chat(current_user, user['username'])  # Check if they are already in chat
        })

    return jsonify(final)
@app.route('/add-to-chat', methods=['POST'])
def add_to_chat():
    data = request.get_json()
    username_to_add = data.get('username')
    current_user = session.get('username')

    if not current_user or not username_to_add:
        return jsonify({'message': 'Missing data'}), 400

    # 🔧 Update the 'chat' array in the user's document inside `security` collection
    db.security.update_one(
        {'username': current_user},
        {'$addToSet': {'chat': username_to_add}}  # creates 'chat' if not exists
    )

    return jsonify({'message': f'{username_to_add} added to chat.'})
@app.route('/get-chat-users')
def get_chat_users():
    current_user = session.get('username')
    if not current_user:
        return jsonify([])

    # Get the current user's chat list
    user_doc = db.security.find_one({'username': current_user})
    chat_usernames = user_doc.get('chat', [])

    # Fetch full profile info of the users in chat list
    users = list(db.security.find(
        {'username': {'$in': chat_usernames}},
        {'_id': 0, 'username': 1, 'profile_pic': 1}  # Include profile pic here
    ))

    return jsonify(users)
@app.route('/proj3.8.html')
def serve_chat_page():
    if 'username' in session:  # Check if the user is logged in (you can check other session parameters as needed)
        chat_with = request.args.get('chat_with')  # Get the 'chat_with' parameter from the URL
        if not chat_with:
            return "Error: 'chat_with' parameter is required", 400
        return send_file('proj3.8.html')  # Serve the static HTML file for the chat page
    return redirect('/login') 
@app.route('/current-user')
def current_user():
    if 'username' in session:
        user = db["security"].find_one({"username": session['username']})
        if user:
            return jsonify({"_id": str(user['_id']), "username": user['username']})
    return jsonify({"error": "Not logged in"}), 401


@socketio.on('send_message')
def handle_send_message(msg):
    # Validate message
    if 'sender_id' not in msg or 'receiver_id' not in msg or 'message' not in msg:
        print("Invalid message structure")
        return

    # Add timestamp if missing
    if 'timestamp' not in msg:
        msg['timestamp'] = datetime.utcnow().isoformat()

    # Save message to DB
    messages.insert_one({
        'from': msg['sender_id'],
        'to': msg['receiver_id'],
        'message': msg['message'],
        'timestamp': msg['timestamp'],
        'seen': False
    })

    # 🔁 Add sender's username to receiver's chat list
    sender_user = db.security.find_one({'_id': ObjectId(msg['sender_id'])})
    receiver_user = db.security.find_one({'_id': ObjectId(msg['receiver_id'])})

    if sender_user and receiver_user:
        db.security.update_one(
            {'_id': receiver_user['_id']},
            {'$addToSet': {'chat': sender_user['username']}}  # Ensures no duplicates
        )

    # Emit message to receiver
        emit('receive_message', {
            'from': sender_user['username'],
            'profile_pic': sender_user.get('profile_pic', '/static/uploads/dummyperson copy.png'),
            'message': msg['message'],
            'timestamp': msg['timestamp']
        }, room=msg['receiver_id'])
    print("Emitting to:", str(msg['receiver_id']))

    print(f"Message from {msg['sender_id']} to {msg['receiver_id']} saved and contact updated.")

@app.route('/load-messages', methods=['GET'])
def load_messages():
    user1 = request.args.get('user1')
    user2 = request.args.get('user2')
    skip = int(request.args.get('skip', 0))
    limit = int(request.args.get('limit', 20))

    print(f"Loading messages between user1: {user1} and user2: {user2}, skip: {skip}, limit: {limit}")

    try:
        user1_obj = ObjectId(user1)
        user2_obj = ObjectId(user2)
    except Exception as e:
        print(f"Error converting user IDs to ObjectId: {e}")
        return jsonify({'error': 'Invalid user ID format'}), 400

    chat_cursor = messages.find({
        '$or': [
            {'from': user1, 'to': user2},
            {'from': user2, 'to': user1}
        ]
    }).sort('timestamp', -1).skip(skip).limit(limit)

    chat = list(chat_cursor)
    chat.reverse()  # Oldest on top for lazy loading

    for msg in chat:
        msg['_id'] = str(msg['_id'])
        msg['from'] = str(msg['from'])
        msg['to'] = str(msg['to'])
        if 'timestamp' in msg and hasattr(msg['timestamp'], 'isoformat'):
            msg['timestamp'] = msg['timestamp'].isoformat()

    return jsonify({'messages': chat})
@socketio.on('join')
def handle_join(data):
    user_id = data.get('user_id')
    if not user_id:
        print("⚠️ 'user_id' missing in join payload")
        return
    join_room(user_id)
    print(f"User {user_id} has joined the room")

@app.route('/toggle_location', methods=['POST'])
def toggle_location():
    if 'username' not in session:
        return jsonify({"error": "Not logged in"}), 401

    data = request.get_json()
    username = session['username']
    status = data.get('status')

    if status == 'on':
        lat = data.get('lat')
        lon = data.get('lon')
        db.security.update_one(
            {'username': username},
            {'$set': {'lat': lat, 'lon': lon}},
            upsert=True
        )
        return jsonify({"message": "Location updated"}), 200

    elif status == 'off':
        db.security.update_one(
            {'username': username},
            {'$unset': {'lat': "", 'lon': ""}}
        )
        return jsonify({"message": "Location removed"}), 200

    return jsonify({"error": "Invalid request"}), 400


@app.route('/search_by_radius')
def search_by_radius():
    current_username = session.get('username')
    if not current_username:
        return jsonify([])

    radius_km = float(request.args.get('radius', 2))
    current_user = collection.find_one({'username': current_username})
    
    if not current_user or 'lat' not in current_user or 'lon' not in current_user:
        return jsonify([])

    lat1, lon1 = current_user['lat'], current_user['lon']
    users = collection.find({
        'username': {'$ne': current_username},
        'lat': {'$exists': True},
        'lon': {'$exists': True}
    })

    results = []
    for u in users:
        lat2, lon2 = u['lat'], u['lon']
        distance_km = geodesic((lat1, lon1), (lat2, lon2)).km
        if distance_km <= radius_km:
            user_doc = collection.find_one({'username': u['username']}) or {}
            is_connected = collection.find_one({
                '$or': [
                    {'from': current_username, 'to': u['username'], 'status': 'accepted'},
                    {'from': u['username'], 'to': current_username, 'status': 'accepted'}
                ]
            }) is not None

            is_request_sent = collection.find_one({
                'from': current_username,
                'to': u['username'],
                'status': 'pending'
            }) is not None

            results.append({
                'username': u['username'],
                'bio': user_doc.get('bio', ''),
                'profile_pic': user_doc.get('profile_pic', ''),
                'is_connected': is_connected,
                'is_request_sent': is_request_sent,
                'distance': distance_km
            })

    return jsonify(results)
from flask import session, redirect, url_for


@app.route('/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({"redirect": url_for('login_page')})
def nocache(view):
    def no_cache(*args, **kwargs):
        resp = make_response(view(*args, **kwargs))
        resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        resp.headers['Pragma'] = 'no-cache'
        resp.headers['Expires'] = '0'
        return resp
    no_cache.__name__ = view.__name__
    return no_cache

@app.route('/protected')
@nocache
def protected():
    if 'username' not in session:
        return redirect(url_for('login_page'))
    # your protected content here
    return "Welcome, you are logged in!"
@app.route('/search-users')
def search_users():
    query = request.args.get('query', '').strip()
    current_user = session.get("username")

    if not query:
        return jsonify([])

    results = collection.find({
        "$and": [
            {"username": {"$regex": f"^{query}", "$options": "i"}},
            {"username": {"$ne": current_user}}
        ]
    }, {"_id": 0, "username": 1, "bio": 1, "profile_pic": 1})

    # Get current user doc
    current_user_doc = collection.find_one({"username": current_user}) or {}
    sent_requests = current_user_doc.get("connections_sent", [])
    connected_users = current_user_doc.get("connections", [])  # Users already connected

    final_results = []
    for user in results:
        user_dict = dict(user)
        username = user["username"]
        user_dict["is_request_sent"] = username in sent_requests
        user_dict["is_connected"] = username in connected_users
        final_results.append(user_dict)

    return jsonify(final_results)
@app.route('/api/unseen_counts/<user_id>')
def unseen_counts(user_id):
    # Group by sender
    pipeline = [
        {"$match": {"to": user_id, "seen": False}},
        {"$group": {"_id": "$from", "count": {"$sum": 1}}}
    ]
    unseen = list(messages.aggregate(pipeline))
    return jsonify(unseen)
@app.route('/api/mark_seen', methods=['POST'])
def mark_seen():
    data = request.json
    sender = data.get('chat_with')
    receiver = data.get('me')
    messages.update_many(
        {'from': sender, 'to': receiver, 'seen': False},
        {'$set': {'seen': True}}
    )
    return jsonify({'status': 'done'})


if __name__ == '__main__':
    socketio.run(app, port=5001, debug=True)