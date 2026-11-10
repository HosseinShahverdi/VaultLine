<?php

namespace App\Providers;

use Illuminate\Cache\RateLimiting\Limit;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\RateLimiter;
use Illuminate\Support\ServiceProvider;

class AppServiceProvider extends ServiceProvider
{
    /**
     * Register any application services.
     */
    public function register(): void
    {
        //
    }

    /**
     * Bootstrap any application services.
     */
    public function boot(): void
    {
        // Rate limiter for secret creation: 20 per minute per client IP
        RateLimiter::for('create-secret', function (Request $request) {
            return Limit::perMinute(20)->by($request->ip());
        });

        // Rate limiter for reveals: 30 per minute per client IP
        RateLimiter::for('reveal-secret', function (Request $request) {
            return Limit::perMinute(30)->by($request->ip());
        });

        // Strict rate limiter for failed passphrase decryption / unlock attempts: 5 per minute
        RateLimiter::for('passphrase-attempt', function (Request $request) {
            return Limit::perMinute(5)->by($request->ip())->response(function () {
                return response()->json([
                    'error' => 'Too many failed passphrase attempts. Please wait 60 seconds.',
                ], 429);
            });
        });
    }
}
