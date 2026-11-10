<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::create('audit_logs', function (Blueprint $table) {
            $table->id();

            // Lifecycle event: created, viewed, expired, deleted, failed_attempt
            $table->enum('event', ['created', 'viewed', 'expired', 'deleted', 'failed_attempt'])->index();

            // Correlated secret identifier (without content)
            $table->string('secret_id', 64)->index();

            // Truncated salted IP hash (for rate limit telemetry without identifying users)
            $table->string('ip_hash', 32);

            // Previous entry SHA-256 hash (forming immutable cryptographic blockchain-style hash chain)
            $table->char('prev_hash', 64);

            // SHA-256(prev_hash + event + secret_id + ip_hash + created_at)
            $table->char('hash', 64)->unique();

            $table->timestamp('created_at')->useCurrent();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('audit_logs');
    }
};
