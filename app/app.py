import os
import configparser
import logging
import uuid
from functools import wraps
from flask import Flask, request, jsonify, render_template, session, redirect, url_for
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from keycloak import KeycloakOpenID
from azure.storage.blob import BlobClient
import requests
from urllib.parse import quote, urlencode
import magic

# Configure logging for gunicorn
logging.basicConfig(level=logging.INFO)
gunicorn_logger = logging.getLogger('gunicorn.error')

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
app.logger.handlers = gunicorn_logger.handlers
app.logger.setLevel(gunicorn_logger.level)
CORS(app, supports_credentials=True)

# Rate limiting configuration
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# Custom rate limit exceeded handler - must be registered with Flask error handler
@app.errorhandler(429)
def ratelimit_handler(e):
    return jsonify({
        'error': 'Too many requests',
        'message': str(e.description)
    }), 429

# Security headers middleware
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
    # CSP - adjust as needed for your CDNs
    response.headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'"
    return response

# Load configuration
config = configparser.RawConfigParser()
config.read('/app/config.ini')

# Keycloak configuration
KEYCLOAK_SERVER_URL = os.getenv('KEYCLOAK_SERVER_URL', config.get('keycloak', 'server_url', fallback='http://localhost:8080'))
KEYCLOAK_REALM = os.getenv('KEYCLOAK_REALM', config.get('keycloak', 'realm', fallback='asghalpro'))
KEYCLOAK_CLIENT_ID = os.getenv('KEYCLOAK_CLIENT_ID', config.get('keycloak', 'client_id', fallback='file-uploader'))
KEYCLOAK_CLIENT_SECRET = os.getenv('KEYCLOAK_CLIENT_SECRET', config.get('keycloak', 'client_secret', fallback='file-uploader-secret'))

# Redirect URI for OAuth2 Authorization Code Flow
APP_URL = os.getenv('APP_URL', 'http://localhost:5000')
REDIRECT_URI = f"{APP_URL}/callback"

# Azure Blob configuration (SAS Token)
AZURE_BLOB_URL = os.getenv('AZURE_BLOB_URL', config.get('azure_blob', 'blob_url', fallback=''))
AZURE_SAS_TOKEN = os.getenv('AZURE_SAS_TOKEN', config.get('azure_blob', 'sas_token', fallback=''))

# App configuration
MAX_FILE_SIZE_MB = int(config.get('app', 'max_file_size_mb', fallback='500'))
ALLOWED_EXTENSIONS = config.get('app', 'allowed_extensions', fallback='.pdf,.jpg,.png,.mp4').split(',')

# TLS verification - set to True in production
KEYCLOAK_VERIFY_SSL = os.getenv('KEYCLOAK_VERIFY_SSL', 'true').lower() == 'true'

# Magic bytes for file type validation
ALLOWED_MIME_TYPES = {
    '.pdf': ['application/pdf'],
    '.jpg': ['image/jpeg'],
    '.jpeg': ['image/jpeg'],
    '.png': ['image/png'],
    '.gif': ['image/gif'],
    '.mp4': ['video/mp4'],
    '.avi': ['video/x-msvideo', 'video/avi'],
    '.mov': ['video/quicktime'],
    '.mkv': ['video/x-matroska'],
    '.doc': ['application/msword'],
    '.docx': ['application/vnd.openxmlformats-officedocument.wordprocessingml.document'],
    '.xls': ['application/vnd.ms-excel'],
    '.xlsx': ['application/vnd.openxmlformats-officedocument.spreadsheetml.sheet'],
    '.txt': ['text/plain'],
    '.zip': ['application/zip', 'application/x-zip-compressed'],
    '.rar': ['application/x-rar-compressed', 'application/vnd.rar'],
    '.7z': ['application/x-7z-compressed'],
}

# Initialize Keycloak client
keycloak_openid = None

def init_keycloak():
    global keycloak_openid
    try:
        app.logger.info(f"Initializing Keycloak: server={KEYCLOAK_SERVER_URL}, realm={KEYCLOAK_REALM}, client={KEYCLOAK_CLIENT_ID}, verify_ssl={KEYCLOAK_VERIFY_SSL}")
        keycloak_openid = KeycloakOpenID(
            server_url=KEYCLOAK_SERVER_URL,
            client_id=KEYCLOAK_CLIENT_ID,
            realm_name=KEYCLOAK_REALM,
            client_secret_key=KEYCLOAK_CLIENT_SECRET,
            verify=KEYCLOAK_VERIFY_SSL
        )
        app.logger.info(f"Keycloak initialized successfully: {KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}")
        return True
    except Exception as e:
        app.logger.error(f"Error initializing Keycloak: {e}")
        return False

def validate_file_content(file, extension):
    """Validate file content using magic bytes"""
    try:
        # Read first 2048 bytes for magic detection
        header = file.read(2048)
        file.seek(0)  # Reset file pointer
        
        # Detect MIME type
        mime = magic.Magic(mime=True)
        detected_mime = mime.from_buffer(header)
        
        # Check if detected MIME matches allowed types for extension
        allowed_mimes = ALLOWED_MIME_TYPES.get(extension.lower(), [])
        
        if not allowed_mimes:
            # Extension not in whitelist, allow if extension check passed
            return True, detected_mime
            
        if detected_mime in allowed_mimes:
            return True, detected_mime
        
        return False, detected_mime
    except Exception as e:
        print(f"File validation error: {e}")
        # Fail open for now, but log the error
        return True, 'unknown'

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

def role_required(role_name):
    """Decorator to require a specific Keycloak role"""
    def decorator(f):
        @wraps(f)
        def decorated(*args, **kwargs):
            # Get user roles from token info
            user_info = getattr(request, 'user', {})
            
            # Roles can be in realm_access.roles or resource_access.{client}.roles
            realm_roles = user_info.get('realm_access', {}).get('roles', [])
            client_roles = user_info.get('resource_access', {}).get(KEYCLOAK_CLIENT_ID, {}).get('roles', [])
            
            all_roles = realm_roles + client_roles
            
            if role_name not in all_roles:
                app.logger.warning(f"User {user_info.get('username', 'unknown')} lacks role '{role_name}'. Has roles: {all_roles}")
                return jsonify({'error': f'Access denied. Role \'{role_name}\' is required.'}), 403
            
            return f(*args, **kwargs)
        return decorated
    return decorator

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

@app.route('/login')
def login():
    """Redirect to Keycloak login page (Authorization Code Flow)"""
    # Generate state and nonce for security
    state = str(uuid.uuid4())
    nonce = str(uuid.uuid4())
    session['oauth_state'] = state
    session['oauth_nonce'] = nonce
    
    # Build Keycloak authorization URL
    auth_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/auth"
    params = {
        'client_id': KEYCLOAK_CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'response_type': 'code',
        'scope': 'openid profile email',
        'state': state,
        'nonce': nonce
    }
    
    authorization_url = f"{auth_url}?{urlencode(params)}"
    app.logger.info(f"Redirecting to Keycloak: {authorization_url}")
    
    return redirect(authorization_url)

@app.route('/callback')
def callback():
    """OAuth2 callback - exchange authorization code for tokens"""
    # Verify state
    state = request.args.get('state')
    if state != session.get('oauth_state'):
        app.logger.error("Invalid OAuth state")
        return redirect(url_for('index'))
    
    # Check for errors
    error = request.args.get('error')
    if error:
        app.logger.error(f"OAuth error: {error} - {request.args.get('error_description')}")
        return redirect(url_for('index'))
    
    # Get authorization code
    code = request.args.get('code')
    if not code:
        app.logger.error("No authorization code received")
        return redirect(url_for('index'))
    
    try:
        # Exchange code for tokens
        token_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/token"
        token_data = {
            'grant_type': 'authorization_code',
            'client_id': KEYCLOAK_CLIENT_ID,
            'client_secret': KEYCLOAK_CLIENT_SECRET,
            'code': code,
            'redirect_uri': REDIRECT_URI
        }
        
        response = requests.post(token_url, data=token_data, verify=KEYCLOAK_VERIFY_SSL)
        
        if response.status_code != 200:
            app.logger.error(f"Token exchange failed: {response.text}")
            return redirect(url_for('index'))
        
        tokens = response.json()
        
        # Store tokens in session
        session['access_token'] = tokens['access_token']
        session['refresh_token'] = tokens.get('refresh_token', '')
        session['id_token'] = tokens.get('id_token', '')
        
        # Get user info
        userinfo_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/userinfo"
        headers = {'Authorization': f"Bearer {tokens['access_token']}"}
        userinfo_response = requests.get(userinfo_url, headers=headers, verify=KEYCLOAK_VERIFY_SSL)
        
        if userinfo_response.status_code == 200:
            userinfo = userinfo_response.json()
            session['username'] = userinfo.get('preferred_username', userinfo.get('sub'))
            session['email'] = userinfo.get('email', '')
            session['name'] = userinfo.get('name', '')
        
        app.logger.info(f"Login successful for user: {session.get('username')}")
        
        # Clear OAuth state
        session.pop('oauth_state', None)
        session.pop('oauth_nonce', None)
        
        return redirect(url_for('index'))
        
    except Exception as e:
        app.logger.error(f"Callback error: {str(e)}")
        return redirect(url_for('index'))

@app.route('/logout')
def logout():
    """Logout - clear session and redirect to Keycloak logout"""
    id_token = session.get('id_token', '')
    
    # Clear local session
    session.clear()
    
    # Redirect to Keycloak logout
    if id_token:
        logout_url = f"{KEYCLOAK_SERVER_URL}/realms/{KEYCLOAK_REALM}/protocol/openid-connect/logout"
        params = {
            'id_token_hint': id_token,
            'post_logout_redirect_uri': APP_URL
        }
        return redirect(f"{logout_url}?{urlencode(params)}")
    
    return redirect(url_for('index'))

@app.route('/upload', methods=['POST'])
@token_required
@role_required('videosasghal')
@limiter.limit("30 per minute")  # Rate limit uploads
def upload_file():
    """Upload file endpoint - requires valid JWT and 'videosasghal' role"""
    if 'file' not in request.files:
        return jsonify({'error': 'No file provided'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    # Check file extension
    file_ext = os.path.splitext(file.filename)[1].lower()
    if file_ext not in ALLOWED_EXTENSIONS:
        return jsonify({'error': f'File type {file_ext} not allowed'}), 400
    
    # Validate file content (magic bytes)
    is_valid, detected_mime = validate_file_content(file, file_ext)
    if not is_valid:
        return jsonify({'error': f'File content does not match extension. Detected: {detected_mime}'}), 400
    
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
