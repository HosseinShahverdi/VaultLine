<?php

namespace Tests\Feature;

use App\Models\AuditLog;
use App\Models\Secret;
use App\Services\AuditLogService;
use Carbon\Carbon;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AtomicBurnTest extends TestCase
{
    use RefreshDatabase;

    /**
     * Test zero-knowledge secret creation, metadata check, atomic burn on reveal,
     * and immediate 404 rejection on subsequent reveal attempts.
     */
    public function test_atomic_burn_after_read_and_double_reveal_prevention(): void
    {
        // 1. Create a 1-view secret
        $response = $this->postJson('/api/secrets', [
            'ciphertext' => base64_encode('ENCRYPTED_PAYLOAD_TEST'),
            'iv' => base64_encode(random_bytes(12)),
            'expires_in' => '24h',
            'max_views' => 1,
            'has_passphrase' => false,
        ]);

        $response->assertStatus(201);
        $secretId = $response->json('id');
        $this->assertNotEmpty($secretId);

        // Verify secret exists in DB
        $this->assertDatabaseHas('secrets', ['id' => $secretId]);

        // 2. Safe metadata inspection does NOT consume the view
        $metaResponse = $this->getJson("/api/secrets/{$secretId}/meta");
        $metaResponse->assertStatus(200);
        $metaResponse->assertJson([
            'exists' => true,
            'max_views' => 1,
            'views_remaining' => 1,
        ]);

        // Secret must still be in DB after metadata check
        $this->assertDatabaseHas('secrets', ['id' => $secretId]);

        // 3. First reveal: must succeed and burn the secret atomically
        $revealResponse = $this->postJson("/api/secrets/{$secretId}/reveal");
        $revealResponse->assertStatus(200);
        $revealResponse->assertJsonStructure(['ciphertext', 'iv', 'burned']);
        $this->assertTrue($revealResponse->json('burned'));

        // Secret ciphertext must be completely wiped from the database!
        $this->assertDatabaseMissing('secrets', ['id' => $secretId]);

        // 4. Second reveal attempt: MUST return 404 (cannot be read twice)
        $secondReveal = $this->postJson("/api/secrets/{$secretId}/reveal");
        $secondReveal->assertStatus(404);
        $secondReveal->assertJson([
            'status' => 'not_found',
        ]);

        // 5. Subsequent metadata inspection confirms secret is destroyed
        $secondMeta = $this->getJson("/api/secrets/{$secretId}/meta");
        $secondMeta->assertJson([
            'exists' => false,
        ]);

        // 6. Verify audit chain records created, viewed, deleted, failed_attempt without secrets
        $auditService = app(AuditLogService::class);
        $verification = $auditService->verifyChain();
        $this->assertTrue($verification['is_valid'], 'Audit chain must remain cryptographically valid.');

        // Verify no plaintext in audit logs
        $logs = AuditLog::where('secret_id', $secretId)->get();
        $this->assertNotEmpty($logs);
        foreach ($logs as $log) {
            $this->assertStringNotContainsString('ENCRYPTED_PAYLOAD_TEST', $log->toJson());
        }
    }
}
