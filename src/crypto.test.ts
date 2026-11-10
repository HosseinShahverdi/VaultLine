import test from "node:test";
import assert from "node:assert/strict";
import {
  generateContentKey,
  exportKeyToBase64Url,
  importKeyFromBase64Url,
  encryptSecret,
  decryptSecret,
  computeAuditEntryHash,
  verifyAuditChain,
  AuditEntry,
  uint8ArrayToBase64Url,
  base64UrlToUint8Array,
} from "./lib/crypto.ts";

test("Base64Url roundtrip works accurately", () => {
  const sampleBytes = new Uint8Array([0, 1, 2, 250, 255, 128, 64, 32]);
  const b64url = uint8ArrayToBase64Url(sampleBytes);
  const decoded = base64UrlToUint8Array(b64url);
  assert.deepEqual(Array.from(decoded), Array.from(sampleBytes));
});

test("AES-256-GCM zero-knowledge encryption and decryption roundtrip", async () => {
  const secretMessage = "vaultline-secret-api-key-xyz-9876543210!@#$%^&*()_+";
  
  // 1. Generate key
  const key = await generateContentKey();
  assert.ok(key, "Key should be generated");

  // 2. Export to URL fragment format
  const fragmentKey = await exportKeyToBase64Url(key);
  assert.equal(typeof fragmentKey, "string");
  assert.ok(fragmentKey.length > 20);

  // 3. Encrypt secret
  const { ciphertext, iv } = await encryptSecret(secretMessage, key);
  assert.notEqual(ciphertext, secretMessage, "Ciphertext must not be plaintext");
  assert.ok(iv, "IV must be present");

  // 4. Re-import key from fragment
  const importedKey = await importKeyFromBase64Url(fragmentKey);

  // 5. Decrypt secret
  const decrypted = await decryptSecret(ciphertext, iv, importedKey);
  assert.equal(decrypted, secretMessage, "Decrypted message must match original plaintext");
});

test("Decryption fails when ciphertext is tampered with", async () => {
  const key = await generateContentKey();
  const { ciphertext, iv } = await encryptSecret("classified-doc", key);
  
  // Tamper with first byte of ciphertext
  const tampered = (ciphertext[0] === "A" ? "B" : "A") + ciphertext.slice(1);
  
  await assert.rejects(
    async () => {
      await decryptSecret(tampered, iv, key);
    },
    /operation failed|decryption|tag mismatch|bad decrypt/i
  );
});

test("Tamper-evident audit chain verification catches broken chains", async () => {
  const GENESIS = "0000000000000000000000000000000000000000000000000000000000000000";
  
  // Build entry 1
  const ts1 = "2026-03-30T10:00:00.000Z";
  const hash1 = await computeAuditEntryHash(GENESIS, "created", "sec_123", "ip_abc", ts1);
  const entry1: AuditEntry = {
    id: 1,
    event: "created",
    secret_id: "sec_123",
    ip_hash: "ip_abc",
    prev_hash: GENESIS,
    hash: hash1,
    created_at: ts1,
  };

  // Build entry 2
  const ts2 = "2026-03-30T10:05:00.000Z";
  const hash2 = await computeAuditEntryHash(hash1, "viewed", "sec_123", "ip_def", ts2);
  const entry2: AuditEntry = {
    id: 2,
    event: "viewed",
    secret_id: "sec_123",
    ip_hash: "ip_def",
    prev_hash: hash1,
    hash: hash2,
    created_at: ts2,
  };

  // Valid chain
  const validResult = await verifyAuditChain([entry1, entry2]);
  assert.equal(validResult.isValid, true);

  // Tampered chain (altered event in entry 1)
  const tamperedEntries: AuditEntry[] = [
    { ...entry1, event: "deleted" },
    entry2,
  ];
  const tamperedResult = await verifyAuditChain(tamperedEntries);
  assert.equal(tamperedResult.isValid, false);
  assert.equal(tamperedResult.brokenAt, 1);
});
