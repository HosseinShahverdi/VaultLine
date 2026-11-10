<?php

namespace App\Services;

use App\Models\AuditLog;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;

class AuditLogService
{
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    /**
     * Compute a truncated, salted SHA-256 hash of the client IP.
     */
    public function hashIp(?string $ip): string
    {
        $ip = $ip ?? '127.0.0.1';
        $salt = config('app.key', 'vaultline-salt');
        return substr(hash('sha256', $ip . $salt), 0, 16);
    }

    /**
     * Atomically append an event to the tamper-evident hash chain.
     */
    public function recordEvent(string $event, string $secretId, ?string $clientIp): AuditLog
    {
        return DB::transaction(function () use ($event, $secretId, $clientIp) {
            // Lock the latest audit log entry to ensure consecutive chain hashes without concurrency collision
            $lastEntry = AuditLog::orderBy('id', 'desc')->lockForUpdate()->first();
            $prevHash = $lastEntry ? $lastEntry->hash : self::GENESIS_HASH;

            $ipHash = $this->hashIp($clientIp);
            $createdAt = Carbon::now('UTC')->toIso8601String();

            // Chain calculation: SHA-256(prev_hash:event:secret_id:ip_hash:created_at)
            $content = "{$prevHash}:{$event}:{$secretId}:{$ipHash}:{$createdAt}";
            $hash = hash('sha256', $content);

            return AuditLog::create([
                'event' => $event,
                'secret_id' => $secretId,
                'ip_hash' => $ipHash,
                'prev_hash' => $prevHash,
                'hash' => $hash,
                'created_at' => $createdAt,
            ]);
        });
    }

    /**
     * Verifies the cryptographic integrity of the entire audit hash chain.
     */
    public function verifyChain(): array
    {
        $logs = AuditLog::orderBy('id', 'asc')->get();
        $expectedPrev = self::GENESIS_HASH;

        foreach ($logs as $log) {
            if ($log->prev_hash !== $expectedPrev) {
                return [
                    'is_valid' => false,
                    'broken_at' => $log->id,
                    'reason' => 'Previous hash mismatch',
                    'total' => $logs->count(),
                ];
            }

            $createdAt = Carbon::parse($log->created_at)->toIso8601String();
            $content = "{$log->prev_hash}:{$log->event}:{$log->secret_id}:{$log->ip_hash}:{$createdAt}";
            $recalculated = hash('sha256', $content);

            if ($recalculated !== $log->hash) {
                return [
                    'is_valid' => false,
                    'broken_at' => $log->id,
                    'reason' => 'Hash integrity signature mismatch',
                    'total' => $logs->count(),
                ];
            }

            $expectedPrev = $log->hash;
        }

        return [
            'is_valid' => true,
            'broken_at' => null,
            'total' => $logs->count(),
        ];
    }
}
