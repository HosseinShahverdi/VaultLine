<?php

use App\Http\Controllers\AuditController;
use App\Http\Controllers\SecretController;
use App\Http\Middleware\SecurityHeaders;
use Illuminate\Support\Facades\Route;

/*
|--------------------------------------------------------------------------
| VaultLine REST API Routes (Zero-Knowledge Architecture)
|--------------------------------------------------------------------------
*/

Route::middleware([SecurityHeaders::class])->group(function () {
    // 1. Create a new encrypted secret (Rate-limited to 20/minute per IP)
    Route::post('/secrets', [SecretController::class, 'store'])
        ->middleware('throttle:create-secret');

    // 2. Safe metadata inspection without burning (Bot preview protection)
    Route::get('/secrets/{id}/meta', [SecretController::class, 'meta'])
        ->where('id', '[A-Za-z0-9_-]+');

    // 3. Atomically reveal ciphertext and burn from disk (Rate-limited to 30/minute per IP)
    Route::post('/secrets/{id}/reveal', [SecretController::class, 'reveal'])
        ->where('id', '[A-Za-z0-9_-]+')
        ->middleware('throttle:reveal-secret');

    // 4. Admin tamper-evident audit log & cryptographic chain integrity verification
    Route::get('/admin/audit', [AuditController::class, 'index']);
});
