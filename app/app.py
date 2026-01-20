import os
import configparser
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from keycloak import KeycloakOpenID
from azure.storage.blob import BlobClient
from jose import jwt, JWTError
import requests
from urllib.parse import quote

app = Flask(__name__)
app.secret_key = os.urandom(24)
CORS(app, supports_credentials=True)

# Load configuration
config = configparser.RawConfigParser()
config.read('/app/config.ini')

# Keycloak configuration
KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', config.get('keycloak', 'server_url', fallback='http://localhost:8080'))
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', config.get('keycloak', 'realm', fallback='asghalpro'))
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', config.get('keycloak', 'client_id', fallback='file-uploader'))
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', config.get('keycloak', 'client_secret', fallback='file-uploader-secret'))

# Azure Blob configuration (SAS Token)
AZURE_BLOB_URL = os.getenv('AZURE_BLOB_URL', config.get('azure_blob', 'blob_url', fallback=''))
AZURE_SAS_TOKEN = os.getenv('AZURE_SAS_TOKEN', config.get('azure_blob', 'sas_token', fallback=''))

# App configuration
MAX_FILE_SIZE_MB = int(config.get('app', 'max_file_size_mb', fallback='500'))
ALLOWED_EXTENSIONS = config.get('app', 'allowed_extensions', fallback='.pdf,.jpg,.png,.mp4').split(',')

# Initialize Keycloak client
keycloak_openid = None

def init_keycloak():
    global keycloak_openid
    try:
        keycloak_openid = KeycloakOpenID(
            server_url=KEYCLOAK_SERVER_URL,
            client_id=KEYCLOAK_CLIENT_ID,
            realm_name=KEYCLOAK_REALM,
            client_secret_key=KEYCLOAK_CLIENT_SECRET,
            verify=False
        )
        print(f"Keycloak initialized: {KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}")
        return True
    except Exception as e:
        print(f"Error initializing Keycloak: {e}")
        return False

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        
        # Check for token in Authorization header
        if 'Authorization' in request.headers:
            auth_header = request.headers['Authorization']
            try:
                token = auth_header.split(" ")[1]
            except IndexError:
                return jsonify({'error': 'Token is malformed'}), 401
        
        # Check for token in session
        if not token and 'access_token' in session:
            token = session['access_token']
        
        if not token:
            return jsonify({'error': 'Token is missing. Please login first.'}), 401
        
        try:
            # Verify the token with Keycloak
            token_info = keycloak_openid.introspect(token)
            
            if not token_info.get('active', False):
                return jsonify({'error': 'Token is invalid or expired'}), 401
            
            # Add user info to request
            request.user = token_info
            
        except Exception as e:
            print(f"Token verification error: {e}")
            return jsonify({'error': 'Token verification failed'}), 401
        
        return f(*args, **kwargs)
    return decorated

def upload_to_blob(file, filename):
    """Upload file to Azure Blob Storage using SAS Token"""
    try:
        if not AZURE_BLOB_URL or not AZURE_SAS_TOKEN:
            return {
                'success': False,
                'message': 'Azure Blob Storage not configured'
            }
        
        # Sanitize filename
        safe_filename = quote(filename, safe='.-_')
        
        # Build the blob URL with SAS token
        blob_url_with_sas = f"{AZURE_BLOB_URL}/{safe_filename}?{AZURE_SAS_TOKEN}"
        
        # Create blob client
        blob_client = BlobClient.from_blob_url(blob_url_with_sas)
        
        # Read file content
        file_content = file.read()
        
        # Upload the blob
        blob_client.upload_blob(file_content, overwrite=True)
        
        # Return the URL without the SAS token for display
        public_url = f"{AZURE_BLOB_URL}/{safe_filename}"
        
        return {
            'success': True,
            'message': f'File "{filename}" uploaded successfully',
            'url': public_url
        }
    except Exception as e:
        print(f"Upload error: {e}")
        return {
            'success': False,
            'message': f'Upload failed: {str(e)}'
        }

@app.route('/')
def index():
    """Main page with drag & drop interface"""
    logged_in = 'access_token' in session
    username = session.get('username', '')
    return render_template('index.html', logged_in=logged_in, username=username)

@app.route('/login', methods=['POST'])
def login():
    """Login endpoint - authenticates with Keycloak and returns JWT"""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password are required'}), 400
    
    try:
        # Get token from Keycloak
        token = keycloak_openid.token(username, password)
        
        # Store in session
        session['access_token'] = token['access_token']
        session['refresh_token'] = token.get('refresh_token', '')
        session['username'] = username
        
        return jsonify({
            'success': True,
            'message': 'Login successful',
            'access_token': token['access_token'],
            'expires_in': token.get('expires_in', 300)
        })
    except Exception as e:
        print(f"Login error: {e}")
        return jsonify({'error': 'Invalid credentials'}), 401

@app.route('/logout', methods=['POST'])
def logout():
    """Logout endpoint - clears session"""
    try:
        if 'refresh_token' in session:
            keycloak_openid.logout(session['refresh_token'])
    except:
        pass
    
    session.clear()
    return jsonify({'success': True, 'message': 'Logged out successfully'})

@app.route('/upload', methods=['POST'])
@token_required
def upload_file():
    """Upload file endpoint - requires valid JWT"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check file extension
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return jsonify({'error': f'File type {file_ext} not allowed'}), 400
    
    # Check file size
    file.seek(0, 2)
    file_size = file.tell()
    file.seek(0)
    
    if file_size > MAX_FILE_SIZE_MB * 1024 * 1024:
        return jsonify({'error': f'File too large. Max size is {MAX_FILE_SIZE_MB}MB'}), 400
    
    # Upload to blob storage
    result = upload_to_blob(file, file.filename)
    
    if result['success']:
        return jsonify({
            'success': True,
            'message': result['message'],
            'filename': file.filename,
            'size': file_size,
            'url': result.get('url', ''),
            'uploaded_by': request.user.get('username', 'unknown')
        })
    else:
        return jsonify({'error': result['message']}), 500

@app.route('/check-auth')
def check_auth():
    """Check if user is authenticated"""
    if 'access_token' in session:
        try:
            token_info = keycloak_openid.introspect(session['access_token'])
            if token_info.get('active', False):
                return jsonify({
                    'authenticated': True,
                    'username': session.get('username', '')
                })
        except:
            pass
    
    return jsonify({'authenticated': False})

@app.route('/health')
def health():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'keycloak_url': KEYCLOAK_SERVER_URL,
        'blob_configured': bool(AZURE_BLOB_URL and AZURE_SAS_TOKEN)
    })

# Initialize Keycloak on module load (works with gunicorn)
init_keycloak()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
