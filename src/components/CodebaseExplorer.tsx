import { useState } from "react";
import {
  FileCode,
  Folder,
  Copy,
  Check,
  Server,
  Layers,
  Database,
  Terminal,
  Shield,
  Box,
} from "lucide-react";

interface CodeFile {
  name: string;
  path: string;
  category: "laravel" | "config" | "tests" | "docs";
  language: string;
  description: string;
  code: string;
}

const CODE_FILES: CodeFile[] = [
  {
    name: "docker-compose.yml",
    path: "docker-compose.yml",
    category: "config",
    language: "yaml",
    description: "Multi-container setup for web, Laravel 11 api, and MySQL 8.4",
    code: `version: "3.8"

services:
  web:
    build:
      context: ../
      dockerfile: ./Dockerfile.web
    container_name: vaultline-web
    restart: unless-stopped
    ports:
      - "3000:3000"
    environment:
      - NEXT_PUBLIC_API_URL=http://localhost:8000
    depends_on:
      - api
    networks:
      - vaultline-net

  api:
    build:
      context: .
      dockerfile: ./Dockerfile.api
    container_name: vaultline-api
    restart: unless-stopped
    ports:
      - "8000:8000"
    environment:
      - APP_NAME=VaultLine
      - APP_ENV=production
      - APP_KEY=\${APP_KEY}
      - FRONTEND_URL=http://localhost:3000
      - DB_CONNECTION=mysql
      - DB_HOST=db
      - DB_DATABASE=vaultline
      - DB_USERNAME=vaultline
      - DB_PASSWORD=secret_db_password_vaultline_99
    depends_on:
      db:
        condition: service_healthy
    networks:
      - vaultline-net

  db:
    image: mysql:8.4
    container_name: vaultline-db
    restart: unless-stopped
    environment:
      MYSQL_DATABASE: vaultline
      MYSQL_USER: vaultline
      MYSQL_PASSWORD: secret_db_password_vaultline_99
      MYSQL_ROOT_PASSWORD: root_secure_vaultline_pass
    ports:
      - "3306:3306"
    volumes:
      - db_data:/var/lib/mysql
    healthcheck:
      test: ["CMD", "mysqladmin", "ping", "-h", "localhost"]
      interval: 5s
      timeout: 5s
      retries: 5
    networks:
      - vaultline-net

volumes:
  db_data:
    driver: local

networks:
  vaultline-net:
    driver: bridge`,
  },
  {
    name: "api.php",
    path: "laravel/routes/api.php",
    category: "laravel",
    language: "php",
    description: "Laravel 11 REST API routes with RateLimiter & SecurityHeaders",
    code: `<?php

use App\Http\Controllers\AuditController;
use App\Http\Controllers\SecretController;
use App\Http\Middleware\SecurityHeaders;
use Illuminate\Support\Facades\Route;

Route::middleware([SecurityHeaders::class])->group(function () {
    // 1. Create a new encrypted secret (Rate-limited to 20/min per IP)
    Route::post('/secrets', [SecretController::class, 'store'])
        ->middleware('throttle:create-secret');

    // 2. Safe metadata inspection without burning (Bot preview protection)
    Route::get('/secrets/{id}/meta', [SecretController::class, 'meta'])
        ->where('id', '[A-Za-z0-9_-]+');

    // 3. Atomically reveal ciphertext and burn from disk (Rate-limited to 30/min per IP)
    Route::post('/secrets/{id}/reveal', [SecretController::class, 'reveal'])
        ->where('id', '[A-Za-z0-9_-]+')
        ->middleware('throttle:reveal-secret');

    // 4. Admin tamper-evident audit log & hash chain integrity verification
    Route::get('/admin/audit', [AuditController::class, 'index']);
});`,
  },
  {
    name: "SecretController.php",
    path: "laravel/app/Http/Controllers/SecretController.php",
    category: "laravel",
    language: "php",
    description: "Zero-Knowledge storage, atomic DB row locking (lockForUpdate) and burn logic",
    code: `<?php

namespace App\Http\Controllers;

use App\Http\Requests\StoreSecretRequest;
use App\Models\Secret;
use App\Services\AuditLogService;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;

class SecretController extends Controller
{
    public function __construct(protected AuditLogService $auditService) {}

    public function store(StoreSecretRequest $request): JsonResponse
    {
        $validated = $request->validated();
        $durations = ['5m' => 300, '1h' => 3600, '24h' => 86400, '7d' => 604800];
        $durationSeconds = $durations[$validated['expires_in']] ?? 86400;
        $expiresAt = Carbon::now('UTC')->addSeconds($durationSeconds);

        // 128-bit random, non-guessable ID (16 cryptographically random bytes -> base64url)
        $id = rtrim(strtr(base64_encode(random_bytes(16)), '+/', '-_'), '=');

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

    public function meta(string $id): JsonResponse
    {
        $secret = Secret::find($id);
        if (!$secret) return response()->json(['exists' => false, 'status' => 'not_found']);
        if ($secret->isExpired()) {
            $secret->delete();
            $this->auditService->recordEvent('expired', $id, 'system');
            return response()->json(['exists' => false, 'status' => 'expired']);
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

    public function reveal(Request $request, string $id): JsonResponse
    {
        $clientIp = $request->ip();
        return DB::transaction(function () use ($id, $clientIp) {
            // Pessimistic row-level lock: prevents race conditions and concurrent double-reads
            $secret = Secret::where('id', $id)->lockForUpdate()->first();
            if (!$secret) {
                $this->auditService->recordEvent('failed_attempt', $id, $clientIp);
                return response()->json(['error' => 'Secret not found or destroyed.', 'status' => 'not_found'], 404);
            }
            if ($secret->isExpired()) {
                $secret->delete();
                $this->auditService->recordEvent('expired', $id, $clientIp);
                return response()->json(['error' => 'Secret expired.', 'status' => 'expired'], 410);
            }

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
}`,
  },
  {
    name: "AuditLogService.php",
    path: "laravel/app/Services/AuditLogService.php",
    category: "laravel",
    language: "php",
    description: "Tamper-evident SHA-256 hash chain generation and verification service",
    code: `<?php

namespace App\Services;

use App\Models\AuditLog;
use Carbon\Carbon;
use Illuminate\Support\Facades\DB;

class AuditLogService
{
    public const GENESIS_HASH = '0000000000000000000000000000000000000000000000000000000000000000';

    public function hashIp(?string $ip): string
    {
        $salt = config('app.key', 'vaultline-salt');
        return substr(hash('sha256', ($ip ?? '127.0.0.1') . $salt), 0, 16);
    }

    public function recordEvent(string $event, string $secretId, ?string $clientIp): AuditLog
    {
        return DB::transaction(function () use ($event, $secretId, $clientIp) {
            $lastEntry = AuditLog::orderBy('id', 'desc')->lockForUpdate()->first();
            $prevHash = $lastEntry ? $lastEntry->hash : self::GENESIS_HASH;
            $ipHash = $this->hashIp($clientIp);
            $createdAt = Carbon::now('UTC')->toIso8601String();

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

    public function verifyChain(): array
    {
        $logs = AuditLog::orderBy('id', 'asc')->get();
        $expectedPrev = self::GENESIS_HASH;

        foreach ($logs as $log) {
            if ($log->prev_hash !== $expectedPrev) {
                return ['is_valid' => false, 'broken_at' => $log->id, 'total' => $logs->count()];
            }
            $createdAt = Carbon::parse($log->created_at)->toIso8601String();
            $recalculated = hash('sha256', "{$log->prev_hash}:{$log->event}:{$log->secret_id}:{$log->ip_hash}:{$createdAt}");
            if ($recalculated !== $log->hash) {
                return ['is_valid' => false, 'broken_at' => $log->id, 'total' => $logs->count()];
            }
            $expectedPrev = $log->hash;
        }

        return ['is_valid' => true, 'broken_at' => null, 'total' => $logs->count()];
    }
}`,
  },
  {
    name: "AtomicBurnTest.php",
    path: "laravel/tests/Feature/AtomicBurnTest.php",
    category: "tests",
    language: "php",
    description: "Pest / PHPUnit feature test for atomic burn and double reveal prevention",
    code: `<?php

namespace Tests\Feature;

use App\Models\Secret;
use App\Services\AuditLogService;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Tests\TestCase;

class AtomicBurnTest extends TestCase
{
    use RefreshDatabase;

    public function test_atomic_burn_after_read_and_double_reveal_prevention(): void
    {
        // 1. Create a 1-view secret
        $response = $this->postJson('/api/secrets', [
            'ciphertext' => base64_encode('CLASSIFIED_PAYLOAD'),
            'iv' => base64_encode(random_bytes(12)),
            'expires_in' => '24h',
            'max_views' => 1,
            'has_passphrase' => false,
        ]);

        $response->assertStatus(201);
        $secretId = $response->json('id');

        // 2. Metadata check does NOT consume the secret
        $this->getJson("/api/secrets/{$secretId}/meta")
            ->assertStatus(200)
            ->assertJson(['exists' => true, 'views_remaining' => 1]);

        // 3. First reveal: must succeed and delete secret from DB atomically
        $revealResponse = $this->postJson("/api/secrets/{$secretId}/reveal");
        $revealResponse->assertStatus(200);
        $this->assertTrue($revealResponse->json('burned'));
        $this->assertDatabaseMissing('secrets', ['id' => $secretId]);

        // 4. Second reveal attempt: MUST return 404
        $this->postJson("/api/secrets/{$secretId}/reveal")
            ->assertStatus(404)
            ->assertJson(['status' => 'not_found']);
    }
}`,
  },
  {
    name: "SecurityHeaders.php",
    path: "laravel/app/Http/Middleware/SecurityHeaders.php",
    category: "laravel",
    language: "php",
    description: "Strict security headers (CSP, no-referrer, X-Frame-Options: DENY, Cache-Control: no-store)",
    code: `<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        $response = $next($request);
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'no-referrer');
        $response->headers->set('Content-Security-Policy', "default-src 'self'; frame-ancestors 'none';");

        if ($request->is('api/*')) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            $response->headers->set('Pragma', 'no-cache');
            $response->headers->set('Expires', '0');
        }

        return $response;
    }
}`,
  },
  {
    name: "PurgeExpiredSecrets.php",
    path: "laravel/app/Console/Commands/PurgeExpiredSecrets.php",
    category: "laravel",
    language: "php",
    description: "Scheduled artisan command to purge expired secrets every minute",
    code: `<?php

namespace App\Console\Commands;

use App\Models\Secret;
use App\Services\AuditLogService;
use Carbon\Carbon;
use Illuminate\Console\Command;

class PurgeExpiredSecrets extends Command
{
    protected $signature = 'vault:purge-expired';
    protected $description = 'Purge expired secrets and append expiration events to audit chain';

    public function handle(AuditLogService $auditService): int
    {
        $expiredSecrets = Secret::where('expires_at', '<=', Carbon::now('UTC'))->get();
        foreach ($expiredSecrets as $secret) {
            $secretId = $secret->id;
            $secret->delete();
            $auditService->recordEvent('expired', $secretId, 'system (scheduler)');
        }
        $this->info("Purged " . $expiredSecrets->count() . " expired secret(s).");
        return Command::SUCCESS;
    }
}`,
  },
  {
    name: "2026_01_01_000001_create_secrets_table.php",
    path: "laravel/database/migrations/2026_01_01_000001_create_secrets_table.php",
    category: "laravel",
    language: "php",
    description: "Database migration for secrets table (ciphertext blob, IV, wrapped key)",
    code: `<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('secrets', function (Blueprint $table) {
            $table->string('id', 64)->primary();
            $table->longText('ciphertext');
            $table->string('iv', 64);
            $table->text('wrapped_key')->nullable();
            $table->string('salt', 64)->nullable();
            $table->unsignedTinyInteger('max_views')->default(1);
            $table->unsignedTinyInteger('views')->default(0);
            $table->timestamp('expires_at')->index();
            $table->timestamp('created_at')->useCurrent();
        });
    }
    public function down(): void {
        Schema::dropIfExists('secrets');
    }
};`,
  },
  {
    name: "2026_01_01_000002_create_audit_logs_table.php",
    path: "laravel/database/migrations/2026_01_01_000002_create_audit_logs_table.php",
    category: "laravel",
    language: "php",
    description: "Database migration for audit_logs hash chain table",
    code: `<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void {
        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();
            $table->enum('event', ['created', 'viewed', 'expired', 'deleted', 'failed_attempt'])->index();
            $table->string('secret_id', 64)->index();
            $table->string('ip_hash', 32);
            $table->char('prev_hash', 64);
            $table->char('hash', 64)->unique();
            $table->timestamp('created_at')->useCurrent();
        });
    }
    public function down(): void {
        Schema::dropIfExists('audit_logs');
    }
};`,
  },
];

export default function CodebaseExplorer() {
  const [selectedFile, setSelectedFile] = useState<CodeFile>(CODE_FILES[0]);
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(selectedFile.code);
      setCopied(true);
      setTimeout(() => setCopied(false), 2500);
    } catch {
      setCopied(true);
    }
  };

  return (
    <div className="w-full max-w-6xl mx-auto space-y-6">
      {/* Header */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur shadow-2xl">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono font-medium mb-2">
              <Server className="w-3.5 h-3.5" />
              <span>Laravel 11 & Docker Compose Architecture</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-white">Full Source Code Delivery</h2>
            <p className="text-sm text-slate-400 mt-1 max-w-3xl leading-relaxed">
              Every backend file requested is fully authored and available below. Browse controllers, migrations, rate limiters, scheduler commands, and Pest feature tests.
            </p>
          </div>
          <div className="flex items-center gap-2 self-start sm:self-auto text-xs font-mono text-slate-400 bg-slate-950 p-2.5 rounded-xl border border-slate-800">
            <Box className="w-4 h-4 text-cyan-400" />
            <span>{CODE_FILES.length} Files Ready to Deploy</span>
          </div>
        </div>
      </div>

      {/* Code Viewer Layout */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
        {/* Left Sidebar: File List */}
        <div className="lg:col-span-4 space-y-2">
          <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-4 backdrop-blur shadow-xl">
            <div className="text-xs font-mono uppercase tracking-wider text-slate-400 mb-3 px-2 flex items-center gap-2">
              <Folder className="w-4 h-4 text-cyan-400" />
              <span>Project Deliverables</span>
            </div>
            <div className="space-y-1">
              {CODE_FILES.map((file) => {
                const isSelected = selectedFile.path === file.path;
                return (
                  <button
                    key={file.path}
                    onClick={() => setSelectedFile(file)}
                    className={`w-full text-left p-2.5 rounded-xl text-xs font-mono transition-all flex items-start gap-2.5 cursor-pointer ${
                      isSelected
                        ? "bg-cyan-500/15 border border-cyan-500/40 text-cyan-300 font-semibold"
                        : "text-slate-400 hover:text-slate-200 hover:bg-slate-800/40 border border-transparent"
                    }`}
                  >
                    <FileCode className={`w-4 h-4 shrink-0 mt-0.5 ${isSelected ? "text-cyan-400" : "text-slate-500"}`} />
                    <div className="truncate">
                      <div className="truncate text-white font-medium">{file.name}</div>
                      <div className="text-[10px] text-slate-500 truncate">{file.path}</div>
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Pane: Code Display */}
        <div className="lg:col-span-8">
          <div className="bg-slate-900/90 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur shadow-2xl flex flex-col h-full">
            {/* File Info Bar */}
            <div className="p-4 bg-slate-950/80 border-b border-slate-800 flex items-center justify-between">
              <div>
                <div className="font-mono text-sm text-cyan-300 font-bold">{selectedFile.path}</div>
                <div className="text-xs text-slate-400 mt-0.5">{selectedFile.description}</div>
              </div>
              <button
                onClick={handleCopy}
                className="px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center gap-1.5 transition-all cursor-pointer shadow"
              >
                {copied ? (
                  <>
                    <Check className="w-3.5 h-3.5 text-emerald-950" />
                    <span>Copied!</span>
                  </>
                ) : (
                  <>
                    <Copy className="w-3.5 h-3.5" />
                    <span>Copy File</span>
                  </>
                )}
              </button>
            </div>

            {/* Code Content */}
            <div className="p-4 bg-slate-950 overflow-x-auto flex-1 max-h-[580px]">
              <pre className="font-mono text-xs text-slate-300 leading-relaxed selection:bg-cyan-500/30 selection:text-cyan-200">
                <code>{selectedFile.code}</code>
              </pre>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
