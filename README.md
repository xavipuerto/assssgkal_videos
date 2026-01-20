# AsGhalPro File Uploader

Secure file upload application with Keycloak authentication and Azure Blob Storage.

## � Security Features

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

The `asghalpro` realm comes preconfigured with two users:

| Username | Password | Email |
|----------|----------|-------|
| carlos.mendez | Carlos123! | carlos.mendez@asghalpro.com |
| laura.garcia | Laura456! | laura.garcia@asghalpro.com |

## ⚙️ Configuration

### Environment Variables (.env)

```bash
# Keycloak - Change for production
KEYCLOAK_SERVER_URL=http://host.docker.internal:8080
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

## 🔒 Authentication Flow

```
┌──────────┐     ┌──────────────┐     ┌──────────────┐
│  Browser │     │  Flask App   │     │   Keycloak   │
└────┬─────┘     └──────┬───────┘     └──────┬───────┘
     │                  │                    │
     │ 1. Login Form    │                    │
     │─────────────────►│                    │
     │                  │ 2. Authenticate    │
     │                  │───────────────────►│
     │                  │                    │
     │                  │ 3. JWT Token       │
     │                  │◄───────────────────│
     │ 4. Store Token   │                    │
     │◄─────────────────│                    │
     │                  │                    │
     │ 5. Upload + JWT  │                    │
     │─────────────────►│                    │
     │                  │ 6. Validate JWT    │
     │                  │───────────────────►│
     │                  │ 7. Token Valid     │
     │                  │◄───────────────────│
     │                  │                    │
     │                  │ 8. Upload to Azure │
     │                  │──────────────────────────►
     │ 9. Success       │                    │
     │◄─────────────────│                    │
```

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
| GET | `/` | No | 50/hour | Main page (SPA) |
| POST | `/login` | No | **5/min** | Authenticate user |
| POST | `/logout` | No | 50/hour | End session |
| POST | `/upload` | JWT | **30/min** | Upload file |
| GET | `/check-auth` | Session | 50/hour | Check authentication status |
| GET | `/health` | No | 50/hour | Health check |

## 📝 License

Internal use only - AsGhalPro
