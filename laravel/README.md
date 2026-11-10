# VaultLine — Zero-Knowledge, Self-Destructing Secret Tool

> "Secrets that burn after reading."

VaultLine is an end-to-end encrypted, zero-knowledge secret sharing platform with atomic burn-after-read guarantees, optional PBKDF2 passphrase protection, and a tamper-evident cryptographic audit ledger.

---

## Folder Structure

```
vaultline/
├── docker-compose.yml              # Multi-container orchestration (web, api, db)
├── Dockerfile.web                  # Frontend production container
├── laravel/
│   ├── .env.example                # Laravel environment configuration
│   ├── Dockerfile.api              # PHP 8.3-FPM + Nginx container
│   ├── app/
│   │   ├── Console/Commands/
│   │   │   └── PurgeExpiredSecrets.php   # Scheduled auto-purge job
│   │   ├── Http/
│   │   │   ├── Controllers/
│   │   │   │   ├── SecretController.php  # Zero-knowledge storage & atomic burn
│   │   │   │   └── AuditController.php   # Tamper-evident ledger & chain verifier
│   │   │   ├── Middleware/
│   │   │   │   └── SecurityHeaders.php   # CSP, anti-caching, frame-ancestors none
│   │   │   └── Requests/
│   │   │       ├── StoreSecretRequest.php
│   │   │       └── RevealSecretRequest.php
│   │   ├── Models/
│   │   │   ├── Secret.php
│   │   │   └── AuditLog.php
│   │   ├── Providers/
│   │   │   └── AppServiceProvider.php    # Per-IP RateLimiter configurations
│   │   └── Services/
│   │       └── AuditLogService.php       # SHA-256 hash-chain verification
│   ├── database/migrations/
│   │   ├── 2026_01_01_000001_create_secrets_table.php
│   │   └── 2026_01_01_000002_create_audit_logs_table.php
│   ├── routes/
│   │   └── api.php                       # REST API route definitions
│   └── tests/
│       ├── Feature/
│       │   └── AtomicBurnTest.php        # Pest / PHPUnit atomic burn test
│       └── Unit/
│           └── CryptoHelperTest.php
├── src/
│   ├── components/
│   │   ├── CreateSecret.tsx              # AES-256-GCM client encryption form
│   │   ├── RevealSecret.tsx              # Safe landing, reveal flow, 60s auto-wipe
│   │   ├── BurnAnimation.tsx             # Reduced-motion aware particle incineration
│   │   ├── AuditLogView.tsx              # Live hash chain verifier UI
│   │   ├── ThreatModelView.tsx           # Interactive Zero-Knowledge architecture
│   │   └── CodebaseExplorer.tsx          # Full source viewer & export
│   ├── lib/
│   │   ├── crypto.ts                     # Pure Web Crypto API (no 3rd-party libs)
│   │   ├── api.ts                        # Typed REST client
│   │   └── strings.ts                    # Centralized UI dictionary
│   ├── App.tsx                           # Main app shell & router
│   ├── main.tsx                          # React entry point
│   └── crypto.test.ts                    # Node test runner suite
└── docs/
    └── THREAT_MODEL.md                   # Full cryptographic threat specification
```

---

## Quickstart with Docker Compose

1. Clone the repository and navigate to the project directory:
   ```bash
   cd vaultline
   ```

2. Copy the environment configuration:
   ```bash
   cp laravel/.env.example laravel/.env
   ```

3. Launch the complete stack (Frontend, Laravel 11 API, MySQL 8.4):
   ```bash
   docker-compose up -d --build
   ```

4. Run migrations inside the API container:
   ```bash
   docker-compose exec api php artisan migrate --force
   ```

5. Access the applications:
   - **Frontend UI**: `http://localhost:3000`
   - **Backend REST API**: `http://localhost:8000/api`
   - **Admin Audit Log**: `http://localhost:8000/api/admin/audit?token=vaultline-admin-demo-token`

---

## Local Development Setup (without Docker)

### Frontend (Next.js / Vite)
```bash
npm install
npm run dev
```

### Backend (Laravel 11 with SQLite)
```bash
cd laravel
composer install
cp .env.example .env
php artisan key:generate
touch database/database.sqlite
php artisan migrate
php artisan serve --port=8000
```

### Running Tests
- **Frontend / Crypto Unit Tests**:
  ```bash
  npm test
  # Runs tsx --test src/crypto.test.ts
  ```
- **Laravel Feature & Pest Tests**:
  ```bash
  cd laravel
  php artisan test
  ```

---

## Core Security Features
- **Zero-Knowledge**: Browser generates 256-bit AES-GCM key. Server receives only ciphertext, IV, and metadata.
- **URL Fragment Key**: Key resides only in `#key`. Fragments are never transmitted in HTTP request lines.
- **Atomic Burn**: Database transaction with `lockForUpdate` guarantees that concurrent requests cannot double-reveal.
- **Bot Safety**: Visiting the reveal URL renders a preview page without consuming the secret. Only an explicit user click executes the reveal.
- **Tamper-Evident Hash Chain**: Append-only SHA-256 chain verifies log integrity without logging secret data.
