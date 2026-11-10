<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreSecretRequest;
use App\Models\Secret;
use App\Services\AuditLogService;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Str;

class SecretController extends Controller
{
    public function __construct(
        protected AuditLogService $auditService
    ) {}

    /**
     * Store an encrypted secret payload (Zero-Knowledge).
     * Server receives only ciphertext, IV, and metadata.
     */
    public function store(StoreSecretRequest $request): JsonResponse
    {
        $validated = $request->validated();

        $durations = [
            '5m' => 5 * 60,
            '1h' => 60 * 60,
            '24h' => 24 * 60 * 60,
            '7d' => 7 * 24 * 60 * 60,
        ];

        $durationSeconds = $durations[$validated['expires_in']] ?? (24 * 60 * 60);
        $expiresAt = Carbon::now('UTC')->addSeconds($durationSeconds);

        // 128-bit random, non-guessable ID (16 cryptographically random bytes -> base64url)
        $randomBytes = random_bytes(16);
        $id = rtrim(strtr(base64_encode($randomBytes), '+/', '-_'), '=');

        $secret = Secret::create([
            'id' => $id,
            'ciphertext' => $validated['ciphertext'],
            'iv' => $validated['iv'],
            'wrapped_key' => $validated['has_passphrase'] ? ($validated['wrapped_key'] ?? null) : null,
            'salt' => $validated['has_passphrase'] ? ($validated['salt'] ?? null) : null,
            'max_views' => $validated['max_views'] ?? 1,
            'views' => 0,
            'expires_at' => $expiresAt,
            'created_at' => Carbon::now('UTC'),
        ]);

        $this->auditService->recordEvent('created', $id, $request->ip());

        return response()->json([
            'id' => $secret->id,
            'expires_at' => $expiresAt->toIso8601String(),
            'max_views' => $secret->max_views,
        ], 201);
    }

    /**
     * Metadata inspection without consuming a view.
     * Prevents social preview scrapers (Slack, Discord, Twitter, iMessage) from burning secrets.
     */
    public function meta(string $id): JsonResponse
    {
        $secret = Secret::find($id);

        if (!$secret) {
            return response()->json([
                'exists' => false,
                'status' => 'not_found',
            ]);
        }

        if ($secret->isExpired()) {
            $secret->delete();
            $this->auditService->recordEvent('expired', $id, 'system');
            return response()->json([
                'exists' => false,
                'status' => 'expired',
            ]);
        }

        if ($secret->isBurned()) {
            $secret->delete();
            return response()->json([
                'exists' => false,
                'status' => 'destroyed',
            ]);
        }

        return response()->json([
            'exists' => true,
            'has_passphrase' => !empty($secret->wrapped_key),
            'salt' => $secret->salt,
            'expires_at' => $secret->expires_at->toIso8601String(),
            'max_views' => $secret->max_views,
            'views_remaining' => $secret->max_views - $secret->views,
        ]);
    }

    /**
     * Atomically reveals ciphertext and consumes a view using database row-level locking (lockForUpdate).
     * Two simultaneous requests cannot both succeed if max_views is 1.
     */
    public function reveal(Request $request, string $id): JsonResponse
    {
        $clientIp = $request->ip();

        return DB::transaction(function () use ($id, $clientIp) {
            // Pessimistic row-level lock: prevents race conditions and concurrent double-reads
            /** @var Secret|null $secret */
            $secret = Secret::where('id', $id)->lockForUpdate()->first();

            if (!$secret) {
                $this->auditService->recordEvent('failed_attempt', $id, $clientIp);
                return response()->json([
                    'error' => 'Secret not found or already destroyed.',
                    'status' => 'not_found',
                ], 404);
            }

            if ($secret->isExpired()) {
                $secret->delete();
                $this->auditService->recordEvent('expired', $id, $clientIp);
                return response()->json([
                    'error' => 'This secret has expired.',
                    'status' => 'expired',
                ], 410);
            }

            // Atomic burn logic: increment view count
            $secret->views += 1;
            $isBurned = $secret->views >= $secret->max_views;

            $payload = [
                'ciphertext' => $secret->ciphertext,
                'iv' => $secret->iv,
                'wrapped_key' => $secret->wrapped_key,
                'salt' => $secret->salt,
                'views' => $secret->views,
                'max_views' => $secret->max_views,
                'burned' => $isBurned,
            ];

            if ($isBurned) {
                // Permanently and atomically delete secret ciphertext from disk/database
                $secret->delete();
                $this->auditService->recordEvent('viewed', $id, $clientIp);
                $this->auditService->recordEvent('deleted', $id, $clientIp);
            } else {
                $secret->save();
                $this->auditService->recordEvent('viewed', $id, $clientIp);
            }

            return response()->json($payload);
        });
    }
}
