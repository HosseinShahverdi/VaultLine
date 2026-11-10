/**
 * VaultLine — Pure Web Crypto API Implementation
 * Zero third-party crypto libraries. Uses native window.crypto.subtle (or globalThis.crypto.subtle in Node).
 *
 * Algorithms:
 * - Content Encryption: AES-GCM 256-bit, 96-bit random IV
 * - Passphrase Key Wrapping: PBKDF2 (600,000 iterations, SHA-256, 128-bit random salt) + AES-GCM
 * - Tamper-evident Audit Log: SHA-256 Hash Chain
 */

// Safe reference to Web Crypto subtle API in both Browser and Node.js
export const getSubtle = (): SubtleCrypto => {
  if (typeof window !== "undefined" && window.crypto?.subtle) {
    return window.crypto.subtle;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto?.subtle) {
    return globalThis.crypto.subtle;
  }
  throw new Error("Web Crypto API (crypto.subtle) is not available in this environment.");
};

// Safe reference to getRandomValues
export const getRandomValues = (array: Uint8Array): Uint8Array => {
  if (typeof window !== "undefined" && window.crypto?.getRandomValues) {
    window.crypto.getRandomValues(array as unknown as Uint8Array<ArrayBuffer>);
    return array;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto?.getRandomValues) {
    globalThis.crypto.getRandomValues(array as unknown as Uint8Array<ArrayBuffer>);
    return array;
  }
  throw new Error("crypto.getRandomValues is not available in this environment.");
};

/* -------------------------------------------------------------------------- */
/*                          Base64 & Base64URL Helpers                         */
/* -------------------------------------------------------------------------- */

export function uint8ArrayToBase64(bytes: Uint8Array): string {
  let binary = "";
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  if (typeof btoa === "function") {
    return btoa(binary);
  }
  // Node.js fallback
  return Buffer.from(binary, "binary").toString("base64");
}

export function base64ToUint8Array(base64: string): Uint8Array {
  let binary = "";
  if (typeof atob === "function") {
    binary = atob(base64);
  } else {
    binary = Buffer.from(base64, "base64").toString("binary");
  }
  const len = binary.length;
  const bytes = new Uint8Array(len);
  for (let i = 0; i < len; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

export function uint8ArrayToBase64Url(bytes: Uint8Array): string {
  return uint8ArrayToBase64(bytes)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

export function base64UrlToUint8Array(base64url: string): Uint8Array {
  let base64 = base64url.replace(/-/g, "+").replace(/_/g, "/");
  while (base64.length % 4 !== 0) {
    base64 += "=";
  }
  return base64ToUint8Array(base64);
}

/* -------------------------------------------------------------------------- */
/*                       Content Key Generation & Export                      */
/* -------------------------------------------------------------------------- */

/**
 * Generates a high-entropy 256-bit AES-GCM content key.
 */
export async function generateContentKey(): Promise<CryptoKey> {
  const subtle = getSubtle();
  return subtle.generateKey(
    {
      name: "AES-GCM",
      length: 256,
    },
    true, // extractable so it can be formatted into the URL fragment
    ["encrypt", "decrypt"]
  );
}

/**
 * Exports an AES-GCM key to a base64url string suitable for URL fragments (#key).
 */
export async function exportKeyToBase64Url(key: CryptoKey): Promise<string> {
  const subtle = getSubtle();
  const raw = await subtle.exportKey("raw", key);
  return uint8ArrayToBase64Url(new Uint8Array(raw));
}

/**
 * Imports an AES-GCM key from a base64url string.
 */
export async function importKeyFromBase64Url(base64url: string): Promise<CryptoKey> {
  const subtle = getSubtle();
  const rawBytes = base64UrlToUint8Array(base64url);
  return subtle.importKey(
    "raw",
    rawBytes as unknown as BufferSource,
    {
      name: "AES-GCM",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

/* -------------------------------------------------------------------------- */
/*                      Encryption & Decryption (AES-GCM)                     */
/* -------------------------------------------------------------------------- */

export interface EncryptedPayload {
  ciphertext: string; // Base64
  iv: string;         // Base64 (12 bytes)
}

/**
 * Encrypts a UTF-8 plaintext secret with AES-256-GCM using a unique 96-bit random IV.
 */
export async function encryptSecret(
  plaintext: string,
  key: CryptoKey
): Promise<EncryptedPayload> {
  const subtle = getSubtle();
  const iv = getRandomValues(new Uint8Array(12)); // 96-bit recommended for AES-GCM
  const encoder = new TextEncoder();
  const encodedPlaintext = encoder.encode(plaintext);

  const encryptedBuffer = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: iv as unknown as BufferSource,
    },
    key,
    encodedPlaintext
  );

  return {
    ciphertext: uint8ArrayToBase64(new Uint8Array(encryptedBuffer)),
    iv: uint8ArrayToBase64(iv),
  };
}

/**
 * Decrypts a base64 ciphertext using the supplied base64 IV and AES-GCM key.
 */
export async function decryptSecret(
  ciphertextBase64: string,
  ivBase64: string,
  key: CryptoKey
): Promise<string> {
  const subtle = getSubtle();
  const ciphertextBytes = base64ToUint8Array(ciphertextBase64);
  const ivBytes = base64ToUint8Array(ivBase64);

  const decryptedBuffer = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: ivBytes as unknown as BufferSource,
    },
    key,
    ciphertextBytes as unknown as BufferSource
  );

  const decoder = new TextDecoder();
  return decoder.decode(decryptedBuffer);
}

/* -------------------------------------------------------------------------- */
/*                 PBKDF2 Passphrase Key-Wrapping (600k rounds)               */
/* -------------------------------------------------------------------------- */

export interface WrappedKeyResult {
  wrappedKey: string; // Base64
  salt: string;       // Base64 (16 bytes)
}

/**
 * Derives a key wrapping key from a passphrase using PBKDF2 (600,000 iterations, SHA-256).
 */
async function deriveWrappingKey(passphrase: string, salt: Uint8Array): Promise<CryptoKey> {
  const subtle = getSubtle();
  const encoder = new TextEncoder();
  const baseKey = await subtle.importKey(
    "raw",
    encoder.encode(passphrase),
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return subtle.deriveKey(
    {
      name: "PBKDF2",
      salt: salt as unknown as BufferSource,
      iterations: 600000, // OWASP recommended strength for PBKDF2-HMAC-SHA256
      hash: "SHA-256",
    },
    baseKey,
    {
      name: "AES-GCM",
      length: 256,
    },
    false,
    ["encrypt", "decrypt"]
  );
}

/**
 * Wraps the content key using a key derived from the user's passphrase.
 * The wrapped result combines a 12-byte wrap IV with the encrypted raw key bytes.
 */
export async function wrapKeyWithPassphrase(
  contentKey: CryptoKey,
  passphrase: string
): Promise<WrappedKeyResult> {
  const subtle = getSubtle();
  const salt = getRandomValues(new Uint8Array(16)); // 128-bit salt
  const wrapIv = getRandomValues(new Uint8Array(12)); // 96-bit wrap IV
  const wrappingKey = await deriveWrappingKey(passphrase, salt);

  // Export raw 32-byte content key
  const rawContentKey = await subtle.exportKey("raw", contentKey);

  // Encrypt the content key with AES-GCM
  const encryptedKeyBuffer = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv: wrapIv as unknown as BufferSource,
    },
    wrappingKey,
    rawContentKey
  );

  // Combine wrapIv (12 bytes) + encryptedKeyBuffer
  const combined = new Uint8Array(wrapIv.length + encryptedKeyBuffer.byteLength);
  combined.set(wrapIv, 0);
  combined.set(new Uint8Array(encryptedKeyBuffer), wrapIv.length);

  return {
    wrappedKey: uint8ArrayToBase64(combined),
    salt: uint8ArrayToBase64(salt),
  };
}

/**
 * Unwraps a wrapped key using the passphrase and salt.
 * Throws if the passphrase is wrong or the ciphertext has been modified.
 */
export async function unwrapKeyWithPassphrase(
  wrappedKeyBase64: string,
  saltBase64: string,
  passphrase: string
): Promise<CryptoKey> {
  const subtle = getSubtle();
  const combined = base64ToUint8Array(wrappedKeyBase64);
  const salt = base64ToUint8Array(saltBase64);

  if (combined.length < 12) {
    throw new Error("Invalid wrapped key format: payload too short.");
  }

  const wrapIv = combined.slice(0, 12);
  const encryptedKeyBytes = combined.slice(12);

  const wrappingKey = await deriveWrappingKey(passphrase, salt);

  const rawKeyBuffer = await subtle.decrypt(
    {
      name: "AES-GCM",
      iv: wrapIv as unknown as BufferSource,
    },
    wrappingKey,
    encryptedKeyBytes as unknown as BufferSource
  );

  return subtle.importKey(
    "raw",
    rawKeyBuffer,
    {
      name: "AES-GCM",
    },
    true,
    ["encrypt", "decrypt"]
  );
}

/* -------------------------------------------------------------------------- */
/*                  Tamper-Evident SHA-256 Audit Hash Chain                   */
/* -------------------------------------------------------------------------- */

export interface AuditEntry {
  id: number;
  event: "created" | "viewed" | "expired" | "deleted" | "failed_attempt";
  secret_id: string;
  ip_hash: string;
  prev_hash: string;
  hash: string;
  created_at: string;
}

/**
 * Computes the deterministic SHA-256 hash for an audit log entry.
 * Hash input: prev_hash:event:secret_id:ip_hash:created_at
 */
export async function computeAuditEntryHash(
  prevHash: string,
  event: string,
  secretId: string,
  ipHash: string,
  createdAt: string
): Promise<string> {
  const subtle = getSubtle();
  const message = `${prevHash}:${event}:${secretId}:${ipHash}:${createdAt}`;
  const encoder = new TextEncoder();
  const hashBuffer = await subtle.digest("SHA-256", encoder.encode(message));
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
}

/**
 * Validates the entire tamper-evident chain from genesis to head.
 */
export async function verifyAuditChain(
  entries: AuditEntry[]
): Promise<{ isValid: boolean; brokenAt?: number; details?: string }> {
  const GENESIS_HASH = "0000000000000000000000000000000000000000000000000000000000000000";

  for (let i = 0; i < entries.length; i++) {
    const entry = entries[i];
    const expectedPrev = i === 0 ? GENESIS_HASH : entries[i - 1].hash;

    if (entry.prev_hash !== expectedPrev) {
      return {
        isValid: false,
        brokenAt: entry.id,
        details: `Previous hash mismatch at entry #${entry.id}. Expected ${expectedPrev.slice(0, 12)}..., got ${entry.prev_hash.slice(0, 12)}...`,
      };
    }

    const calculatedHash = await computeAuditEntryHash(
      entry.prev_hash,
      entry.event,
      entry.secret_id,
      entry.ip_hash,
      entry.created_at
    );

    if (calculatedHash !== entry.hash) {
      return {
        isValid: false,
        brokenAt: entry.id,
        details: `Hash integrity failure at entry #${entry.id}. Data has been tampered with or corrupted.`,
      };
    }
  }

  return { isValid: true };
}
