<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    /**
     * Handle an incoming request and enforce military-grade zero-knowledge HTTP headers.
     */
    public function handle(Request $request, Closure $next): Response
    {
        /** @var Response $response */
        $response = $next($request);

        // Disallow MIME type sniffing
        $response->headers->set('X-Content-Type-Options', 'nosniff');

        // Prevent clickjacking & framing attacks entirely
        $response->headers->set('X-Frame-Options', 'DENY');

        // Never leak URL fragments, paths, or referrers to external domains
        $response->headers->set('Referrer-Policy', 'no-referrer');

        // Strict Content Security Policy
        $csp = "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; frame-ancestors 'none'; form-action 'self'; connect-src 'self';";
        $response->headers->set('Content-Security-Policy', $csp);

        // Strict anti-caching for secret endpoints
        if ($request->is('api/*')) {
            $response->headers->set('Cache-Control', 'no-store, no-cache, must-revalidate, private');
            $response->headers->set('Pragma', 'no-cache');
            $response->headers->set('Expires', '0');
        }

        return $response;
    }
}
