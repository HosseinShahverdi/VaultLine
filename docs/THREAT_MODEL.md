# VaultLine Security Specification & Threat Model

VaultLine is designed with a **Zero-Knowledge Architecture**. The backend server, hosting infrastructure, database engine, and intermediate network hops are considered completely untrusted.

---

## 1. What the Server Can See
1. **Ciphertext Blob**: Base64-encoded encrypted data generated with AES-256-GCM. Indistinguishable from random noise (semantic security).
2. **Initialization Vector (IV)**: 12-byte (96-bit) cryptographically random nonce used for AES-GCM. An IV is not secret, but is never reused with the same key.
3. **Wrapped Key & Salt (Optional)**: If a passphrase is used, the content key is wrapped using a PBKDF2-derived key (600,000 iterations, SHA-256) and a 16-byte random salt.
4. **Metadata**: Expiration timestamp (`expires_at`), view limit (`max_views`), view counter (`views`), and creation timestamp.
5. **Truncated IP Hash**: Salted SHA-256 truncated to 16 characters for rate limiting and tamper-evident audit logging.
6. **Tamper-Evident Audit Ledger**: An append-only hash chain of lifecycle events (`created`, `viewed`, `expired`, `deleted`, `failed_attempt`).

---

## 2. What the Server Cannot See
1. **Plaintext Secret Content**: Secrets are encrypted in the sender's browser before any network transmission. The server never holds or caches plaintext in RAM, disk, or swap.
2. **Content Encryption Key**: The 256-bit AES-GCM key lives exclusively in the URL fragment (`https://vault.domain/#s={id}&key={base64url-key}`). Per RFC 3986, URL fragments are processed strictly client-side by user agents and are never transmitted over HTTP request lines or headers.
3. **Passphrase**: When passphrase protection is active, PBKDF2 derivation and key wrapping occur client-side. The server never receives the passphrase or derived key.

---

## 3. Atomic Burn-After-Read Guarantees
- **Race Condition Prevention**: The reveal endpoint executes within a database transaction utilizing pessimistic row locking (`lockForUpdate` in Laravel / mutex in Express).
- **Single-Reader Enforcement**: If two concurrent HTTP POST requests arrive simultaneously for a 1-view secret, only one transaction acquires the exclusive row lock. Upon reading, the row is deleted immediately, and the second transaction receives a `404 Not Found`.
- **Bot/Crawler Protection**: `GET /api/secrets/{id}/meta` inspects availability without incrementing view counters or burning data. Link previewers (Slack, Discord, Apple Messages, Twitter bot) cannot burn secrets.

---

## 4. Known Boundaries & Limitations
1. **Compromised Endpoints**: If the client's machine has active keyloggers, screen grabbers, or malicious browser extensions, the secret can be intercepted in browser memory.
2. **Recipient Retention**: Once decrypted in the recipient's viewport, the recipient can copy, photograph, or record the secret. VaultLine auto-hides secrets after 60 seconds to mitigate visual shoulder surfing.
3. **URL Fragment Exposure via Shoulder Surfing or Browser History**: While browser history generally preserves full URLs including fragments, VaultLine automatically wipes query/fragment strings upon reveal completion to minimize forensic footprints.
