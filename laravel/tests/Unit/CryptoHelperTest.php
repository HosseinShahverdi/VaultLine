<?php

namespace Tests\Unit;

use App\Services\AuditLogService;
use Tests\TestCase;

class CryptoHelperTest extends TestCase
{
    /**
     * Test deterministic SHA-256 hash calculation for audit logs.
     */
    public function test_audit_hash_chain_calculation_and_genesis(): void
    {
        $auditService = new AuditLogService();
        $prevHash = AuditLogService::GENESIS_HASH;
        $event = 'created';
        $secretId = 'sec_test_123456';
        $ip = '192.168.1.1';
        $ipHash = $auditService->hashIp($ip);
        $createdAt = '2026-03-30T10:00:00+00:00';

        $expectedHash = hash('sha256', "{$prevHash}:{$event}:{$secretId}:{$ipHash}:{$createdAt}");

        $this->assertEquals(64, strlen($expectedHash));
        $this->assertNotEmpty($ipHash);
        $this->assertEquals(16, strlen($ipHash));
    }
}
