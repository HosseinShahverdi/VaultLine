/**
 * VaultLine — Frontend API Client
 * Connects to the backend REST API endpoints.
 */

export interface CreateSecretRequest {
  ciphertext: string;
  iv: string;
  expires_in: "5m" | "1h" | "24h" | "7d";
  max_views: number;
  has_passphrase: boolean;
  wrapped_key?: string | null;
  salt?: string | null;
}

export interface CreateSecretResponse {
  id: string;
  expires_at: string;
  max_views: number;
}

export interface SecretMetaResponse {
  exists: boolean;
  status?: "not_found" | "expired" | "destroyed";
  has_passphrase?: boolean;
  salt?: string | null;
  expires_at?: string;
  max_views?: number;
  views_remaining?: number;
}

export interface RevealSecretResponse {
  ciphertext: string;
  iv: string;
  wrapped_key?: string | null;
  salt?: string | null;
  views: number;
  max_views: number;
  burned: boolean;
}

export interface AuditLogResponse {
  chain_valid: boolean;
  broken_at?: number;
  total_entries: number;
  entries: Array<{
    id: number;
    event: "created" | "viewed" | "expired" | "deleted" | "failed_attempt";
    secret_id: string;
    ip_hash: string;
    prev_hash: string;
    hash: string;
    created_at: string;
  }>;
}

export async function createSecretApi(data: CreateSecretRequest): Promise<CreateSecretResponse> {
  const res = await fetch("/api/secrets", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || `Failed to create secret (${res.status})`);
  }
  return res.json();
}

export async function getSecretMetaApi(id: string): Promise<SecretMetaResponse> {
  const res = await fetch(`/api/secrets/${encodeURIComponent(id)}/meta`, {
    headers: { "Cache-Control": "no-cache" },
  });
  if (!res.ok) {
    throw new Error(`Failed to check secret status (${res.status})`);
  }
  return res.json();
}

export async function revealSecretApi(id: string): Promise<RevealSecretResponse> {
  const res = await fetch(`/api/secrets/${encodeURIComponent(id)}/reveal`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    const error = new Error(err.error || `Failed to reveal secret (${res.status})`);
    // @ts-expect-error attaching status
    error.status = err.status || (res.status === 410 ? "expired" : "destroyed");
    throw error;
  }
  return res.json();
}

export async function fetchAuditLogsApi(token: string): Promise<AuditLogResponse> {
  const res = await fetch(`/api/admin/audit?token=${encodeURIComponent(token)}`, {
    headers: {
      Authorization: `Bearer ${token}`,
      "Cache-Control": "no-cache",
    },
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || `Failed to fetch audit log (${res.status})`);
  }
  return res.json();
}

export async function simulateAuditTamperApi(token: string): Promise<{ message: string; chain_valid: boolean; broken_at?: number }> {
  const res = await fetch("/api/admin/simulate-tamper", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ token }),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({}));
    throw new Error(err.error || "Simulation failed");
  }
  return res.json();
}
