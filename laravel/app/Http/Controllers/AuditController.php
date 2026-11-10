<?php

namespace App\Http\Controllers;

use App\Models\AuditLog;
use App\Services\AuditLogService;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AuditController extends Controller
{
    public function __construct(
        protected AuditLogService $auditService
    ) {}

    /**
     * Admin endpoint to inspect the tamper-evident audit log and verify hash chain integrity.
     */
    public function index(Request $request): JsonResponse
    {
        $expectedToken = config('services.vaultline.admin_token', env('VAULTLINE_ADMIN_TOKEN', 'vaultline-admin-demo-token'));
        $bearerToken = $request->bearerToken() ?? $request->query('token');

        if (!$bearerToken || !hash_equals($expectedToken, $bearerToken)) {
            return response()->json([
                'error' => 'Unauthorized: Invalid admin token.',
            ], 401);
        }

        $verification = $this->auditService->verifyChain();
        $entries = AuditLog::orderBy('id', 'desc')->take(200)->get();

        return response()->json([
            'chain_valid' => $verification['is_valid'],
            'broken_at' => $verification['broken_at'],
            'total_entries' => $verification['total'],
            'entries' => $entries,
        ]);
    }
}
