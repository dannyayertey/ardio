from flask import Flask, request, jsonify, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from flask_cors import CORS
from flask import send_from_directory
import serial
import threading
from time import sleep, time
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer
import os
from passlib.hash import sha256_crypt

app = Flask(__name__)
CORS(app)

# Configure app secret key for session management
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'dev_key_for_testing_only')

# Initialize LoginManager
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = 'Please log in to access this page.'

# Create token serializer for password reset
ts = URLSafeTimedSerializer(app.config["SECRET_KEY"])

# Serial connection
ser = None

def init_serial_connection(): 
    global ser 
    try: 
        ser = serial.Serial('COM3', 9600, timeout=1)  # Adjust COM port as needed for your system 
        print("Serial connection established") 
    except serial.SerialException as e: 
        print(f"Error opening serial port: {e}") 
        ser = None

def send_arduino_command(command):
    global ser
    if not ser:
        init_serial_connection()  # Try to reconnect
        
    if ser and ser.is_open:
        try:
            ser.write(f"{command}\n".encode())  # \n is important as command terminator
            # Wait for acknowledgment (optional)
            start_time = time()
            while (time() - start_time) < 2:  # 2 second timeout
                if ser.in_waiting:
                    response = ser.readline().decode().strip()
                    if response:  # Arduino should send confirmation
                        return True
            return False  # Timeout
        except serial.SerialException as e:
            print(f"Error sending command: {e}")
            ser = None  # Mark as disconnected
            return False
    return False

# Configure SQLite database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///energy_saver.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Database Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    is_active = db.Column(db.Boolean, default=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)
    
    def set_password(self, password):
        self.password_hash = sha256_crypt.hash(password)
        
    def check_password(self, password):
        return sha256_crypt.verify(password, self.password_hash)

class SensorData(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    motion_detected = db.Column(db.Boolean, nullable=False)
    light_level = db.Column(db.Float, nullable=False)
    device_status = db.Column(db.String(20), nullable=False)  # 'on' or 'off'
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('sensor_data', lazy=True))

class UserPreferences(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    motion_timeout = db.Column(db.Integer, default=300)  # seconds
    light_threshold = db.Column(db.Float, default=50.0)  # percentage
    auto_mode = db.Column(db.Boolean, default=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    user = db.relationship('User', backref=db.backref('preferences', lazy=True, uselist=False))

# User loader for Flask-Login
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Create database tables
with app.app_context():
    db.create_all()
    # Initialize user preferences if not exists
    if not UserPreferences.query.first():
        default_prefs = UserPreferences()
        db.session.add(default_prefs)
        db.session.commit()
    
    # Create admin user if not exists
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', email='admin@example.com', is_admin=True)
        admin.set_password('admin123')
        db.session.add(admin)
        db.session.commit()

# Authentication Routes
@app.route('/api/auth/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    email = data.get('email')
    password = data.get('password')
    
    if not username or not email or not password:
        return jsonify({'error': 'Missing required fields'}), 400
    
    # Check if username or email already exists
    if User.query.filter_by(username=username).first():
        return jsonify({'error': 'Username already exists'}), 400
    
    if User.query.filter_by(email=email).first():
        return jsonify({'error': 'Email already exists'}), 400
    
    # Create new user
    user = User(username=username, email=email)
    user.set_password(password)
    
    # Create user preferences
    prefs = UserPreferences(user=user)
    
    db.session.add(user)
    db.session.add(prefs)
    db.session.commit()
    
    return jsonify({'message': 'User registered successfully'}), 201

@app.route('/api/auth/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    remember = data.get('remember', False)
    
    if not username or not password:
        return jsonify({'error': 'Missing username or password'}), 400
    
    user = User.query.filter_by(username=username).first()
    
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid username or password'}), 401
    
    # Update last login time
    user.last_login = datetime.utcnow()
    db.session.commit()
    
    # Log in the user
    login_user(user, remember=remember)
    
    return jsonify({
        'message': 'Login successful',
        'user': {
            'id': user.id,
            'username': user.username,
            'email': user.email,
            'is_admin': user.is_admin
        }
    })

@app.route('/api/auth/logout', methods=['POST'])
@login_required
def logout():
    logout_user()
    return jsonify({'message': 'Logout successful'})

@app.route('/api/auth/user', methods=['GET'])
@login_required
def get_user():
    return jsonify({
        'id': current_user.id,
        'username': current_user.username,
        'email': current_user.email,
        'is_admin': current_user.is_admin
    })

@app.route('/api/auth/reset-password', methods=['POST'])
def reset_password_request():
    data = request.json
    email = data.get('email')
    
    if not email:
        return jsonify({'error': 'Email is required'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        # Don't reveal that the user doesn't exist
        return jsonify({'message': 'Password reset instructions sent if email exists'})
    
    # Generate token
    token = ts.dumps(user.email, salt='password-reset-salt')
    
    # In a real application, you would send an email with the reset link
    # For this prototype, we'll just return the token
    reset_url = f"/reset-password/{token}"
    
    return jsonify({
        'message': 'Password reset instructions sent',
        'reset_url': reset_url  # In production, remove this and send via email
    })

@app.route('/api/auth/reset-password/<token>', methods=['POST'])
def reset_password(token):
    data = request.json
    new_password = data.get('password')
    
    if not new_password:
        return jsonify({'error': 'New password is required'}), 400
    
    try:
        email = ts.loads(token, salt='password-reset-salt', max_age=86400)  # 24 hours
    except:
        return jsonify({'error': 'Invalid or expired token'}), 400
    
    user = User.query.filter_by(email=email).first()
    
    if not user:
        return jsonify({'error': 'User not found'}), 404
    
    user.set_password(new_password)
    db.session.commit()
    
    return jsonify({'message': 'Password reset successful'})

# Data Routes
@app.route('/api/sensor-data', methods=['GET'])
@login_required
def get_sensor_data():
    # If admin, can see all data, otherwise only user's data
    if current_user.is_admin:
        data = SensorData.query.order_by(SensorData.timestamp.desc()).limit(10).all()
    else:
        data = SensorData.query.filter_by(user_id=current_user.id).order_by(SensorData.timestamp.desc()).limit(10).all()
    
    return jsonify([{
        'timestamp': entry.timestamp,
        'motion_detected': entry.motion_detected,
        'light_level': entry.light_level,
        'device_status': entry.device_status
    } for entry in data])

@app.route('/api/sensor-data', methods=['POST'])
@login_required
def add_sensor_data():
    data = request.json
    new_entry = SensorData(
        motion_detected=data.get('motion_detected', False),
        light_level=data.get('light_level', 0.0),
        device_status=data.get('device_status', 'UNKNOWN'),
        user_id=current_user.id
    )
    db.session.add(new_entry)
    db.session.commit()
    return jsonify({'message': 'Sensor data added successfully'})

@app.route('/api/preferences', methods=['GET'])
@login_required
def get_preferences():
    # Get preferences for the current user, or create if not exists
    prefs = UserPreferences.query.filter_by(user_id=current_user.id).first()
    if not prefs:
        prefs = UserPreferences(user_id=current_user.id)
        db.session.add(prefs)
        db.session.commit()
    
    return jsonify({
        'motion_timeout': prefs.motion_timeout,
        'light_threshold': prefs.light_threshold,
        'auto_mode': prefs.auto_mode
    })

@app.route('/api/preferences', methods=['POST'])
@login_required
def update_preferences():
    data = request.json
    prefs = UserPreferences.query.filter_by(user_id=current_user.id).first()
    
    if not prefs:
        prefs = UserPreferences(user_id=current_user.id)
        db.session.add(prefs)
    
    prefs.motion_timeout = data.get('motion_timeout', prefs.motion_timeout)
    prefs.light_threshold = data.get('light_threshold', prefs.light_threshold)
    prefs.auto_mode = data.get('auto_mode', prefs.auto_mode)
    db.session.commit()
    return jsonify({'message': 'Preferences updated successfully'})

@app.route('/')
def serve_welcome():
    return send_from_directory('static', 'welcome.html')

@app.route('/welcome')
def serve_welcome_page():
    return send_from_directory('static', 'welcome.html')

@app.route('/login')
def serve_login_page():
    return send_from_directory('static', 'login.html')

@app.route('/register')
def serve_register_page():
    return send_from_directory('static', 'register.html')

@app.route('/dashboard')
@login_required
def serve_dashboard():
    return send_from_directory('static', 'index.html')

@app.route('/lights')
@login_required
def serve_lights_page():
    return send_from_directory('static', 'lights.html')

@app.route('/devices')
@login_required
def serve_devices_page():
    return send_from_directory('static', 'devices.html')

@app.route('/stats')
@login_required
def serve_stats_page():
    return send_from_directory('static', 'stats.html')

@app.route('/static/<path:filename>')
def serve_static(filename):
    return send_from_directory('static', filename)

@app.route('/api/current-status', methods=['GET'])
@login_required
def get_current_status():
    # Get the latest sensor data for the current user
    if current_user.is_admin:
        latest_data = SensorData.query.order_by(SensorData.timestamp.desc()).first()
    else:
        latest_data = SensorData.query.filter_by(user_id=current_user.id).order_by(SensorData.timestamp.desc()).first()
    
    prefs = UserPreferences.query.filter_by(user_id=current_user.id).first()
    if not prefs and current_user.is_admin:
        prefs = UserPreferences.query.first()
    elif not prefs:
        prefs = UserPreferences(user_id=current_user.id)
        db.session.add(prefs)
        db.session.commit()
    
    if latest_data:
        # Parse device status string to determine states of all devices
        device_status = latest_data.device_status.upper() if latest_data.device_status else ''
        
        return jsonify({
            'motion': 'Detected' if latest_data.motion_detected else 'None',
            'light_level': f"{latest_data.light_level:.1f}%",
            'light_state': 'ON' if 'LIGHT:ON' in device_status else 'OFF',
            'fan_state': 'ON' if 'FAN:ON' in device_status else 'OFF',
            'main_light_state': 'ON' if 'MAIN-LIGHT:ON' in device_status else 'OFF',
            'desk_light_state': 'ON' if 'DESK-LIGHT:ON' in device_status else 'OFF',
            'ambient_light_state': 'ON' if 'AMBIENT-LIGHT:ON' in device_status else 'OFF',
            'thermostat_state': 'ON' if 'THERMOSTAT:ON' in device_status else 'OFF',
            'purifier_state': 'ON' if 'PURIFIER:ON' in device_status else 'OFF',
            'humidifier_state': 'ON' if 'HUMIDIFIER:ON' in device_status else 'OFF',
            'plug_state': 'ON' if 'PLUG:ON' in device_status else 'OFF',
            'auto_mode': prefs.auto_mode,
            'user': current_user.username
        })
    else:
        return jsonify({
            'motion': 'None',
            'light_level': '0.0%',
            'light_state': 'OFF',
            'fan_state': 'OFF',
            'main_light_state': 'OFF',
            'desk_light_state': 'OFF',
            'ambient_light_state': 'OFF',
            'thermostat_state': 'OFF',
            'purifier_state': 'OFF',
            'humidifier_state': 'OFF',
            'plug_state': 'OFF',
            'auto_mode': prefs.auto_mode
        })

@app.route('/api/device-control', methods=['POST'])
@login_required
def device_control():
    data = request.json
    device = data.get('device')  # Device identifier: 'light', 'fan', 'thermostat', etc.
    action = data.get('action')  # Action to perform: 'on', 'off', 'speed', 'level', etc.
    value = data.get('value')    # Optional value for actions that require it (e.g., speed level)
    
    if not device or not action:
        return jsonify({'error': 'Missing device or action parameter'}), 400
    
    # Format command for Arduino
    if action in ['on', 'off']:
        command = f"{device.upper()}:{action.upper()}"
    elif value is not None:
        command = f"{device.upper()}:{action.upper()}:{value}"
    else:
        command = f"{device.upper()}:{action.upper()}"
    
    # Send command to Arduino
    success = send_arduino_command(command)
    
    # Prepare response data
    response_data = {
        'success': success,
        'device': device,
        'action': action
    }
    
    # Include value in response if provided
    if value is not None:
        response_data['value'] = value
    
    # Log the action in database
    latest_data = SensorData.query.filter_by(user_id=current_user.id).order_by(SensorData.timestamp.desc()).first()
    if not latest_data and current_user.is_admin:
        latest_data = SensorData.query.order_by(SensorData.timestamp.desc()).first()
        
    if latest_data:
        new_status = latest_data.device_status
        
        # Update device status based on command
        device_upper = device.upper()
        
        # Handle different types of commands
        if action.upper() == 'ON':
            new_status = command
        elif action.upper() == 'OFF':
            new_status = f"{device_upper}:OFF"
        elif value is not None:
            # For commands with values (brightness, speed, temperature, etc.)
            new_status = command
            
        new_entry = SensorData(
            motion_detected=latest_data.motion_detected,
            light_level=latest_data.light_level,
            device_status=new_status,
            user_id=current_user.id
        )
        db.session.add(new_entry)
        db.session.commit()
    else:
        # If no previous data exists, create a new entry with default values
        new_entry = SensorData(
            motion_detected=False,
            light_level=0.0,
            device_status=f"{device.upper()}:{action.upper()}",
            user_id=current_user.id
        )
        db.session.add(new_entry)
        db.session.commit()
    
    if success:
        response_data['message'] = f'Command {command} sent to device'
        response_data['user'] = current_user.username
        return jsonify(response_data)
    else:
        return jsonify({'error': 'Failed to send command to device'}), 500

def serial_reader():
    """Background thread to read from serial port"""
    while True:
        if ser and ser.is_open:
            try:
                line = ser.readline().decode().strip()
                if line:
                    print(f"Arduino: {line}")
                    # Process incoming data (sensor readings, etc.)
            except serial.SerialException:
                pass
        sleep(0.1)

# Initialize serial connection and start reader thread when app starts
@app.before_request
def before_request():
    global ser
    if not hasattr(app, '_got_first_request'):
        app._got_first_request = True
        print("Initializing serial connection...")
        init_serial_connection()
        threading.Thread(target=serial_reader, daemon=True).start()
        print("Serial reader thread started")
    else:
        # For debugging purposes
        if request.endpoint and not request.endpoint.startswith('static'):
            print(f"Request to {request.endpoint} - Serial connection status: {'Connected' if ser and ser.is_open else 'Not connected'}")
@app.route('/api/scene-control', methods=['POST'])
@login_required
def scene_control():
    data = request.json
    scene = data.get('scene')  # 'reading', 'movie', 'evening', 'all-off'
    
    if not scene:
        return jsonify({'error': 'Missing scene parameter'}), 400
    
    # Define scene configurations
    scene_configs = {
        'reading': {
            'main-light': 'on',
            'desk-light': 'on',
            'ambient-light': 'off'
        },
        'movie': {
            'main-light': 'off',
            'desk-light': 'off',
            'ambient-light': 'on'
        },
        'evening': {
            'main-light': 'on',
            'desk-light': 'off',
            'ambient-light': 'on'
        },
        'all-off': {
            'main-light': 'off',
            'desk-light': 'off',
            'ambient-light': 'off'
        }
    }
    
    if scene not in scene_configs:
        return jsonify({'error': 'Invalid scene parameter'}), 400
    
    # Apply scene configuration
    success = True
    device_status = ''
    
    for device, action in scene_configs[scene].items():
        # Format command for Arduino
        command = f"{device.upper()}:{action.upper()}"
        
        # Send command to Arduino
        cmd_success = send_arduino_command(command)
        if not cmd_success:
            success = False
        
        # Update device status
        if action == 'on':
            device_status += f"{device.upper()}:ON "
    
    # Log the scene activation in database
    latest_data = SensorData.query.filter_by(user_id=current_user.id).order_by(SensorData.timestamp.desc()).first()
    if not latest_data and current_user.is_admin:
        latest_data = SensorData.query.order_by(SensorData.timestamp.desc()).first()
    
    if latest_data:
        new_entry = SensorData(
            motion_detected=latest_data.motion_detected,
            light_level=latest_data.light_level,
            device_status=f"SCENE:{scene.upper()} {device_status}",
            user_id=current_user.id
        )
        db.session.add(new_entry)
        db.session.commit()
    else:
        # If no previous data exists, create a new entry with default values
        new_entry = SensorData(
            motion_detected=False,
            light_level=0.0,
            device_status=f"SCENE:{scene.upper()} {device_status}",
            user_id=current_user.id
        )
        db.session.add(new_entry)
        db.session.commit()
    
    if success:
        return jsonify({
            'message': f'Scene {scene} activated successfully',
            'user': current_user.username
        })
    else:
        return jsonify({
            'warning': f'Scene {scene} activated with some errors',
            'user': current_user.username
        }), 207

@app.route('/api/schedule', methods=['POST', 'DELETE'])
@login_required
def manage_schedule():
    data = request.json
    
    if request.method == 'POST':
        device = data.get('device')
        action = data.get('action')
        time = data.get('time')
        
        if not device or not action or not time:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # In a real application, you would store this in a database
        # For this prototype, we'll just acknowledge the request
        return jsonify({
            'message': f'Schedule added for {device} to {action} at {time}',
            'user': current_user.username
        })
    
    elif request.method == 'DELETE':
        device = data.get('device')
        action = data.get('action')
        time = data.get('time')
        
        if not device or not action or not time:
            return jsonify({'error': 'Missing required parameters'}), 400
        
        # In a real application, you would remove this from a database
        # For this prototype, we'll just acknowledge the request
        return jsonify({
            'message': f'Schedule removed for {device} to {action} at {time}',
            'user': current_user.username
        })

@app.route('/api/energy-stats', methods=['GET'])
@login_required
def get_energy_stats():
    # Get query parameters
    period = request.args.get('period', 'day')  # day, week, month, year
    device = request.args.get('device', 'all')  # all, lights, thermostat, fan, etc.
    
    # Get current timestamp
    now = datetime.now()
    
    # Calculate start time based on period
    if period == 'day':
        start_time = now - timedelta(days=1)
        interval = 'hour'
        labels = [f"{i}:00" for i in range(24)]
    elif period == 'week':
        start_time = now - timedelta(days=7)
        interval = 'day'
        labels = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']
    elif period == 'month':
        start_time = now - timedelta(days=30)
        interval = 'day'
        labels = [f"Day {i+1}" for i in range(30)]
    elif period == 'year':
        start_time = now - timedelta(days=365)
        interval = 'month'
        labels = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec']
    else:
        start_time = now - timedelta(days=1)
        interval = 'hour'
        labels = [f"{i}:00" for i in range(24)]
    
    # Query sensor data from database
    if current_user.is_admin:
        # Admin can see all data
        sensor_data = SensorData.query.filter(
            SensorData.timestamp >= start_time
        ).order_by(SensorData.timestamp).all()
    else:
        # Regular users can only see their own data
        sensor_data = SensorData.query.filter(
            SensorData.timestamp >= start_time,
            SensorData.user_id == current_user.id
        ).order_by(SensorData.timestamp).all()
    
    # Process data to calculate energy usage
    # In a real application, this would be calculated from actual sensor readings
    # For demo purposes, we'll generate simulated data based on the actual timestamps
    
    # Generate random energy data with some realistic patterns
    import random
    
    # Base energy consumption for different devices (in watts)
    device_base = {
        'lights': 60,
        'thermostat': 1000,
        'fan': 45,
        'purifier': 40,
        'plug': 80
    }
    
    # Time-based multipliers to simulate daily patterns
    def time_multiplier(hour):
        # Higher usage in morning and evening
        if 6 <= hour <= 9:  # Morning peak
            return 1.5
        elif 17 <= hour <= 22:  # Evening peak
            return 1.8
        elif 23 <= hour or hour <= 5:  # Night low
            return 0.6
        else:  # Daytime moderate
            return 1.0
    
    # Generate energy data
    energy_data = []
    total_energy = 0
    peak_usage = 0
    device_usage = {
        'lights': 0,
        'thermostat': 0,
        'fan': 0,
        'purifier': 0,
        'plug': 0
    }
    
    # If we have actual sensor data, use timestamps from it
    if sensor_data:
        for reading in sensor_data:
            hour = reading.timestamp.hour
            multiplier = time_multiplier(hour)
            
            # Calculate energy for each device
            device_energy = {}
            for dev, base in device_base.items():
                # Add some randomness
                variation = random.uniform(0.8, 1.2)
                # Calculate energy in watt-hours
                energy = base * multiplier * variation
                device_energy[dev] = energy
                device_usage[dev] += energy / 1000  # Convert to kWh
            
            # Total energy at this timestamp
            timestamp_total = sum(device_energy.values())
            total_energy += timestamp_total / 1000  # Convert to kWh
            peak_usage = max(peak_usage, timestamp_total)
            
            energy_data.append({
                'timestamp': reading.timestamp.isoformat(),
                'total': timestamp_total,
                'devices': device_energy
            })
    else:
        # Generate simulated data if no sensor data available
        data_points = len(labels)
        for i in range(data_points):
            # Simulate hour of day for daily pattern
            if period == 'day':
                hour = i
            else:
                hour = random.randint(0, 23)
                
            multiplier = time_multiplier(hour)
            
            # Calculate energy for each device
            device_energy = {}
            for dev, base in device_base.items():
                # Add some randomness
                variation = random.uniform(0.8, 1.2)
                # Calculate energy in watt-hours
                energy = base * multiplier * variation
                device_energy[dev] = energy
                device_usage[dev] += energy / 1000  # Convert to kWh
            
            # Total energy at this timestamp
            timestamp_total = sum(device_energy.values())
            total_energy += timestamp_total / 1000  # Convert to kWh
            peak_usage = max(peak_usage, timestamp_total)
            
            # Create a simulated timestamp
            if period == 'day':
                timestamp = (now.replace(hour=hour, minute=0, second=0, microsecond=0)).isoformat()
            elif period == 'week':
                timestamp = (now - timedelta(days=6-i)).isoformat()
            elif period == 'month':
                timestamp = (now - timedelta(days=29-i)).isoformat()
            else:  # year
                timestamp = (now.replace(month=i+1 if i+1 <= 12 else 12, day=1)).isoformat()
            
            energy_data.append({
                'timestamp': timestamp,
                'total': timestamp_total,
                'devices': device_energy
            })
    
    # Calculate energy saved (simulated)
    # Assume energy saved is 10-20% of total energy
    energy_saved = total_energy * random.uniform(0.1, 0.2)
    
    # Calculate cost (assume $0.15 per kWh)
    cost_per_kwh = 0.15
    estimated_cost = total_energy * cost_per_kwh
    
    # Filter by device if specified
    if device != 'all':
        filtered_data = []
        for entry in energy_data:
            if device in entry['devices']:
                filtered_entry = {
                    'timestamp': entry['timestamp'],
                    'total': entry['devices'][device],
                    'devices': {device: entry['devices'][device]}
                }
                filtered_data.append(filtered_entry)
        energy_data = filtered_data
    
    # Prepare response
    response = {
        'period': period,
        'labels': labels,
        'energy_data': energy_data,
        'summary': {
            'total_energy': round(total_energy, 2),  # kWh
            'peak_usage': round(peak_usage, 2),  # W
            'energy_saved': round(energy_saved, 2),  # kWh
            'estimated_cost': round(estimated_cost, 2),  # $
            'device_usage': {k: round(v, 2) for k, v in device_usage.items()},  # kWh per device
            'unit': 'kWh'
        },
        'username': current_user.username
    }
    
    return jsonify(response)

if __name__ == '__main__':
    app.run(debug=True)