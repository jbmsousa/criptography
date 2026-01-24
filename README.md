# Secure Messaging System

End-to-end encrypted messaging system with Perfect Forward Secrecy, built with Quarkus, Apache Wicket, and WebCrypto API.

## Security Features

- **ECDH Key Exchange** (P-256) - Perfect Forward Secrecy
- **AES-256-GCM** - Authenticated encryption
- **RSA-2048 / SHA-256** - Digital signatures
- **BCrypt** - Password hashing
- **Anti-Replay Protection** - Nonce + Timestamp validation
- **Automatic Key Rotation** - Every 5 minutes
- **Key Revocation** - CRL (Certificate Revocation List)

## Prerequisites

- Java 22
- Docker & Docker Compose
- Maven (or use included `./mvnw`)

## Quick Start

### 1. Start the Database

```bash
docker-compose up -d
```

This starts PostgreSQL with:
- Database: `secure_messaging`
- User: `crypto_user`
- Password: `crypto_pass`
- Port: `5432`

### 2. Run the Application

**Option A - From IDE:**
Run the main Quarkus application

**Option B - From terminal:**
```bash
./mvnw quarkus:dev
```

The application will be available at: **http://localhost:8080**

### API Documentation (Swagger UI)

Access the interactive API documentation at: **http://localhost:8080/q/swagger-ui**

OpenAPI specification available at: **http://localhost:8080/openapi**

---

## Usage Guide

### Step 1: Register a New User

1. Navigate to **http://localhost:8080/register**
2. Enter:
   - **NIF**: Portuguese tax identification number (9 digits)
   - **Password**: Strong password (min 8 characters)
   - **Confirm Password**: Repeat password
3. Click **"Register & Generate Keys"**

The browser will automatically:
- Generate ECDH key pair (for key exchange)
- Generate RSA key pair (for digital signatures)
- Send public keys to server
- Store private keys in browser localStorage

### Step 2: Login

1. Navigate to **http://localhost:8080/login**
2. Enter your **User ID** and **Password**
3. Click **"Login"**

After login, you'll be redirected to the Dashboard.

### Step 3: Dashboard

The dashboard shows:
- List of all registered users
- Online/Offline status
- Key fingerprints for verification
- Unread message count
- WebSocket connection status

### Step 4: Start a Chat

1. From the Dashboard, click on any user to start a chat
2. The system will:
   - Fetch the recipient's public key
   - Derive a shared session key using ECDH
   - Establish a WebSocket connection
3. Type your message and click **"Send"**

Messages are:
- Encrypted with AES-256-GCM before sending
- Signed with your RSA private key
- Transmitted via WebSocket
- Decrypted only on the recipient's browser

### Profile & Key Management

Navigate to **http://localhost:8080/profile** to:
- View your key fingerprints
- Regenerate keys (invalidates all sessions)
- Revoke keys (if compromised)

---

## API Endpoints

### Authentication
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/auth/login` | Login with credentials |
| POST | `/api/auth/logout` | Logout current session |
| GET | `/api/auth/validate` | Validate session token |

### User & Keys
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/keys/register` | Register new user |
| GET | `/api/keys/{userId}` | Get user's public keys |
| GET | `/api/keys/users` | List all users |
| GET | `/api/keys/users/online` | List online users |
| PUT | `/api/keys/{userId}/keys` | Update user's keys |

### Messages
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/messages/history/{userId}` | Get chat history |
| GET | `/api/messages/unread-count` | Get unread count |
| POST | `/api/messages/mark-read/{senderId}` | Mark as read |

### Revocation
| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/api/revocation/revoke` | Revoke a key |
| GET | `/api/revocation/check/{fingerprint}` | Check if revoked |
| GET | `/api/revocation/stats` | Revocation statistics |

### WebSocket
| Endpoint | Description |
|----------|-------------|
| `ws://localhost:8080/chat` | Real-time messaging |

---

## Cryptographic Flow

```
┌─────────────────────────────────────────────────────────────┐
│                    REGISTRATION                              │
├─────────────────────────────────────────────────────────────┤
│  1. Browser generates ECDH key pair (P-256)                 │
│  2. Browser generates RSA key pair (2048-bit)               │
│  3. Public keys + BCrypt(password) → Server                 │
│  4. Private keys → Browser localStorage                     │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    CHAT INITIATION                          │
├─────────────────────────────────────────────────────────────┤
│  1. Alice fetches Bob's ECDH public key                     │
│  2. ECDH: Alice.private + Bob.public → Shared Secret        │
│  3. HKDF(Shared Secret) → AES-256 Session Key               │
│  4. WebSocket connection established                        │
└─────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────┐
│                    MESSAGE EXCHANGE                         │
├─────────────────────────────────────────────────────────────┤
│  SENDER:                                                    │
│  1. Generate random IV (12 bytes)                           │
│  2. Generate nonce (16 bytes)                               │
│  3. AES-256-GCM encrypt(message, sessionKey, IV, AAD)       │
│  4. RSA-SHA256 sign(ciphertext)                             │
│  5. Send via WebSocket                                      │
│                                                             │
│  RECEIVER:                                                  │
│  1. Verify timestamp (< 60 seconds)                         │
│  2. Check nonce not reused (anti-replay)                    │
│  3. RSA-SHA256 verify signature                             │
│  4. AES-256-GCM decrypt                                     │
└─────────────────────────────────────────────────────────────┘
```

---

## Project Structure

```
src/main/java/cv/sousa/
├── server/
│   ├── model/          # JPA entities (User, Message, ChatSession)
│   ├── repository/     # Data access layer
│   ├── service/        # Business logic
│   ├── resource/       # REST API endpoints
│   └── websocket/      # WebSocket endpoint
├── client/
│   ├── service/        # Crypto & HTTP client services
│   └── model/          # Message models
└── web/
    ├── pages/          # Wicket pages
    └── components/     # Wicket panels

src/main/resources/
├── cv/sousa/web/       # HTML templates
├── META-INF/resources/static/
│   ├── css/            # Stylesheets
│   └── js/             # JavaScript (crypto, chat, auth)
└── application.properties
```

---

## Troubleshooting

### Database connection refused
```bash
# Check if PostgreSQL is running
docker ps

# Start if not running
docker-compose up -d
```

### Port 8080 already in use
```bash
# Find process
lsof -i :8080

# Or change port in application.properties
quarkus.http.port=8081
```

### Keys not found after page refresh
Private keys are stored in browser localStorage. If cleared:
1. Register again with the same user ID (will fail - user exists)
2. Or create a new user

---

## Security Considerations

1. **Private keys never leave the browser** - Only public keys are sent to server
2. **End-to-end encryption** - Server cannot read messages
3. **Perfect Forward Secrecy** - Compromised long-term key doesn't expose past messages
4. **Key verification** - Compare fingerprints out-of-band to prevent MITM

---

## Running in Production

```bash
# Package the application
./mvnw package

# Run the JAR
java -jar target/quarkus-app/quarkus-run.jar
```

## License

Academic project for Modern Cryptography course - Universidade de Cabo Verde.
