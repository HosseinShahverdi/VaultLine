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
        Schema::create('secrets', function (Blueprint $table) {
            // 128-bit random base64url non-guessable primary key
            $table->string('id', 64)->primary();

            // Zero-knowledge opaque ciphertext (binary BLOB / mediumText)
            $table->longText('ciphertext');

            // 96-bit AES-GCM random initialization vector (base64)
            $table->string('iv', 64);

            // Optional PBKDF2 passphrase-wrapped key and 128-bit salt
            $table->text('wrapped_key')->nullable();
            $table->string('salt', 64)->nullable();

            // Self-destruction parameters
            $table->unsignedTinyInteger('max_views')->default(1);
            $table->unsignedTinyInteger('views')->default(0);

            // Expiration timestamp
            $table->timestamp('expires_at')->index();
            $table->timestamp('created_at')->useCurrent();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('secrets');
    }
};
