# AsGhalPro File Uploader

Secure file upload application with Keycloak OAuth2 authentication and Azure Blob Storage.

## 🔐 Authentication

This application uses **OAuth2 Authorization Code Flow** with Keycloak:

- Users are redirected to Keycloak login page (no password form in the app)
- After successful authentication, users are redirected back with an authorization code
- The app exchanges the code for JWT tokens (access_token, id_token, refresh_token)
- Role-based access control: requires `videosasghal` client role to upload files

### Role-Based Access Control

| Role | Access Level |
|------|--------------|
| `videosasghal` | ✅ Can upload files |
| No role | ❌ Access denied page shown |

Users without the `videosasghal` role will see an access denied message after login.

## 🛡️ Security Features

| Feature | Description |
|---------|-------------|
| 🛡️ Rate Limiting | 5 attempts/min on login, 30/min on uploads |
| 📋 Security Headers | X-Frame-Options, CSP, X-XSS-Protection, etc. |
| 🔍 Magic Bytes Validation | Detects files with spoofed extensions |
| 🔒 SSL Verification | Configurable for Keycloak connections |
| 👤 Non-root Container | Runs as unprivileged user |
| 🔑 Secure Sessions | Flask SECRET_KEY configuration |

## �🛠️ Technology Stack

### Backend
| Technology | Version | Description |
|------------|---------|-------------|
| Python | 3.11 | Programming language |
| Flask | 3.0.0 | Web framework |
| Gunicorn | 21.2.0 | WSGI HTTP Server |
| python-keycloak | 3.7.0 | Keycloak client library |
| azure-storage-blob | 12.19.0 | Azure Blob Storage SDK |
| flask-limiter | 3.5.0 | Rate limiting |
| python-magic | 0.4.27 | File type detection |
| cryptography | ≥42.0.0 | Cryptographic operations |

### Frontend
| Technology | Description |
|------------|-------------|
| HTML5 | Structure |
| CSS3 | Styling (Glassmorphism design) |
| Vanilla JavaScript | Drag & Drop API, Fetch API |

### Infrastructure
| Service | Description |
|---------|-------------|
| Docker | Containerization |
| Docker Compose | Container orchestration |
| Keycloak 23.0 | Identity and Access Management |
| PostgreSQL 15 | Keycloak database |
| Azure Blob Storage | File storage (SAS Token auth) |

## 🌐 Network & Ports

| Service | Port | Protocol | Description |
|---------|------|----------|-------------|
| File Uploader | 5000 | HTTP | Main application |
| Keycloak | 8080 | HTTP | Identity Provider |
| PostgreSQL | 5432 | TCP | Database (internal only) |

### Internal Communication
```
┌─────────────────────────────────────────────────────────────────┐
│                        Docker Network                           │
│                                                                 │
│  ┌─────────────┐      ┌─────────────┐      ┌─────────────┐     │
│  │ file-uploader│      │  keycloak   │      │  postgres   │     │
│  │   :5000     │◄────►│    :8080    │◄────►│    :5432    │     │
│  └─────────────┘      └─────────────┘      └─────────────┘     │
│         │                    │                                  │
└─────────┼────────────────────┼──────────────────────────────────┘
          │                    │
          ▼                    ▼
    localhost:5000       localhost:8080
```

## 🏗️ Architecture

```
┌─────────────────┐     ┌──────────────┐     ┌─────────────────┐
│   Frontend      │────▶│  Flask App   │────▶│  Azure Blob     │
│  (Drag & Drop)  │     │  (Python)    │     │  Storage        │
└─────────────────┘     └──────┬───────┘     └─────────────────┘
                               │
                               │ JWT Validation
                               ▼
                        ┌──────────────┐
                        │   Keycloak   │
                        │   (Auth)     │
                        └──────────────┘
```

## 🚀 Quick Start

### 1. Start Keycloak (local development only)

```bash
docker-compose -f docker-compose.keycloak.yml up -d
```

Wait ~60 seconds for Keycloak to be ready.

### 2. Start the application

```bash
docker-compose up -d --build
```

### Access URLs

| Service | URL | Credentials |
|---------|-----|-------------|
| File Uploader | http://localhost:5000 | See test users below |
| Keycloak Admin | http://localhost:8080/admin | admin / admin123 |

## 👥 Test Users

The `asghalpro` realm comes preconfigured with test users:

| Username | Password | Email | Role | Access |
|----------|----------|-------|------|--------|
| carlos.mendez | Carlos123! | carlos.mendez@asghalpro.com | `videosasghal` | ✅ Full access |
| laura.garcia | Laura456! | laura.garcia@asghalpro.com | `videosasghal` | ✅ Full access |
| usuario.sinrol | SinRol123! | sin.rol@asghalpro.com | None | ❌ Denied |

### Managing User Roles

To add/remove the `videosasghal` role from a user:

1. Access Keycloak Admin Console: http://localhost:8080/admin (admin/admin123)
2. Go to **Users** → Select user → **Role Mapping** tab
3. Filter by **file-uploader** client
4. Assign or remove the `videosasghal` role

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# Keycloak - Internal URL (container-to-container communication)
KEYCLOAK_SERVER_URL=http://host.docker.internal:8080

# Keycloak - External URL (browser redirects)
KEYCLOAK_EXTERNAL_URL=http://localhost:8080

# Application URL (for OAuth2 callback)
APP_URL=http://localhost:5000

# Keycloak Realm & Client
KEYCLOAK_REALM=asghalpro
KEYCLOAK_CLIENT_ID=file-uploader
KEYCLOAK_CLIENT_SECRET=file-uploader-secret

# Azure Blob Storage (SAS Token)
AZURE_BLOB_URL=https://your-account.blob.core.windows.net/container
AZURE_SAS_TOKEN=sv=2025-07-05&spr=https&...

# Security Settings
KEYCLOAK_VERIFY_SSL=true          # Set to 'false' only for local dev
SECRET_KEY=your-secret-key-here   # Generate with: python -c "import secrets; print(secrets.token_hex(32))"
```

### URL Configuration Explained

| Variable | Purpose | Example |
|----------|---------|---------|
| `KEYCLOAK_SERVER_URL` | Backend API calls to Keycloak | `http://host.docker.internal:8080` |
| `KEYCLOAK_EXTERNAL_URL` | Browser redirects to Keycloak login | `http://localhost:8080` |
| `APP_URL` | OAuth2 callback URL | `http://localhost:5000` |

> **Note:** In Docker, containers cannot access `localhost` on the host machine. Use `host.docker.internal` for internal communication.

### Configuration Files

| File | Description |
|------|-------------|
| `.env` | Environment variables (secrets) |
| `config.ini` | Application configuration |
| `keycloak/realm-export.json` | Keycloak realm configuration |

## 📁 Project Structure

```
/opt/videosblob/
├── docker-compose.yml           # App (production)
├── docker-compose.keycloak.yml  # Keycloak (development only)
├── config.ini                   # Application configuration
├── .env                         # Environment variables
├── README.md
├── app/
│   ├── Dockerfile              # Python 3.11-slim based
│   ├── app.py                  # Flask application
│   ├── requirements.txt        # Python dependencies
│   └── templates/
│       └── index.html          # Frontend SPA
└── keycloak/
    └── realm-export.json       # Realm + users config
```

## 🔒 OAuth2 Authorization Code Flow

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  Browser │     │  Flask App   │     │   Keycloak   │
└────┬─────┘     └──────┬───────┘     └──────┬───────┘
     │                  │                    │
     │ 1. Click Login   │                    │
     │─────────────────►│                    │
     │                  │                    │
     │ 2. Redirect to Keycloak               │
     │◄─────────────────│                    │
     │                  │                    │
     │ 3. User authenticates                 │
     │──────────────────────────────────────►│
     │                  │                    │
     │ 4. Redirect with auth code            │
     │◄──────────────────────────────────────│
     │                  │                    │
     │ 5. Callback /callback?code=xxx        │
     │─────────────────►│                    │
     │                  │ 6. Exchange code   │
     │                  │───────────────────►│
     │                  │ 7. JWT Tokens      │
     │                  │◄───────────────────│
     │                  │                    │
     │                  │ 8. Verify role     │
     │                  │    (videosasghal)  │
     │                  │                    │
     │ 9. Redirect home │                    │
     │◄─────────────────│                    │
     │                  │                    │
     │ 10. Upload + Session Cookie           │
     │─────────────────►│                    │
     │                  │ 11. Validate JWT   │
     │                  │ 12. Check role     │
     │                  │                    │
     │                  │ 13. Upload to Azure│
     │                  │──────────────────────────►
     │ 14. Success      │                    │
     │◄─────────────────│                    │
```

### Key Differences from Password Flow

| Aspect | Password Flow | Authorization Code Flow |
|--------|---------------|------------------------|
| Login form | In the app | In Keycloak |
| Credentials | Sent to app | Never seen by app |
| Security | Lower | Higher (recommended) |
| SSO | Not possible | ✅ Supported |
| MFA | App must implement | ✅ Keycloak handles |

## 🐳 Docker Commands

```bash
# Start Keycloak (development)
docker-compose -f docker-compose.keycloak.yml up -d
docker-compose -f docker-compose.keycloak.yml down

# Start application (production)
docker-compose up -d --build
docker-compose down

# View logs
docker-compose logs -f file-uploader
docker logs keycloak

# Check status
docker ps
```

## 🚀 Production Deployment

For production, deploy only `docker-compose.yml` and configure environment variables:

```bash
# Required environment variables for production
KEYCLOAK_SERVER_URL=https://your-keycloak-production.com
KEYCLOAK_VERIFY_SSL=true
SECRET_KEY=$(python -c "import secrets; print(secrets.token_hex(32))")
```

### Security Checklist for Production

- [ ] Set `KEYCLOAK_VERIFY_SSL=true` with valid SSL certificates
- [ ] Generate a strong `SECRET_KEY` and keep it secret
- [ ] Use HTTPS for the application (reverse proxy recommended)
- [ ] Configure proper SAS token permissions for Azure Blob
- [ ] Review rate limiting settings for your use case
- [ ] Set up log aggregation and monitoring

## 📋 API Endpoints

| Method | Endpoint | Auth | Rate Limit | Description |
|--------|----------|------|------------|-------------|
| GET | `/` | No | 50/hour | Main page (Jinja2 rendered) |
| GET | `/login` | No | **5/min** | Redirect to Keycloak login |
| GET | `/callback` | No | 50/hour | OAuth2 callback handler |
| GET | `/logout` | No | 50/hour | End session & redirect to Keycloak logout |
| POST | `/upload` | JWT+Role | **30/min** | Upload file (requires `videosasghal` role) |
| GET | `/health` | No | 50/hour | Health check |

## 🔧 Troubleshooting

### Common Issues

| Issue | Cause | Solution |
|-------|-------|----------|
| "Token is invalid or expired" | Session mismatch | Use 1 worker in Gunicorn |
| Redirect to `host.docker.internal` | Missing external URL | Set `KEYCLOAK_EXTERNAL_URL` |
| 403 Access Denied | Missing role | Assign `videosasghal` role in Keycloak |
| Login loop | Multiple workers | Reduce to 1 worker (`--workers 1`) |

### Checking Logs

```bash
# Application logs
docker logs file-uploader -f

# Keycloak logs
docker logs keycloak -f

# Filter for auth events
docker logs file-uploader 2>&1 | grep -E "Login|Token|role"
```

## 📝 License

Internal use only - AsGhalPro
