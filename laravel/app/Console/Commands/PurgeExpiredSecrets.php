<?php

namespace App\Console\Commands;

use App\Models\Secret;
use App\Services\AuditLogService;
use Carbon\Carbon;
use Illuminate\Console\Command;

class PurgeExpiredSecrets extends Command
{
    /**
     * The name and signature of the console command.
     */
    protected $signature = 'vault:purge-expired';

    /**
     * The console command description.
     */
    protected $description = 'Permanently purge expired encrypted secrets and log expiration in the audit chain';

    /**
     * Execute the console command.
     */
    public function handle(AuditLogService $auditService): int
    {
        $now = Carbon::now('UTC');
        $expiredSecrets = Secret::where('expires_at', '<=', $now)->get();

        $count = $expiredSecrets->count();

        foreach ($expiredSecrets as $secret) {
            $secretId = $secret->id;
            $secret->delete();
            $auditService->recordEvent('expired', $secretId, 'system (scheduler)');
        }

        $this->info("Successfully purged {$count} expired secret(s).");

        return Command::SUCCESS;
    }
}
