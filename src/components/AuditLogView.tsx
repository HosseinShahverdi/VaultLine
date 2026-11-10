import { useState, useEffect } from "react";
import {
  ShieldAlert,
  CheckCircle2,
  XCircle,
  RefreshCw,
  Lock,
  Key,
  Database,
  Link as LinkIcon,
  HelpCircle,
  FileText,
} from "lucide-react";
import { STRINGS } from "../lib/strings.ts";
import { fetchAuditLogsApi, simulateAuditTamperApi, AuditLogResponse } from "../lib/api.ts";
import { verifyAuditChain } from "../lib/crypto.ts";

export default function AuditLogView() {
  const [token, setToken] = useState("vaultline-admin-demo-token");
  const [data, setData] = useState<AuditLogResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [simulating, setSimulating] = useState(false);
  const [clientVerification, setClientVerification] = useState<{
    tested: boolean;
    isValid: boolean;
    brokenAt?: number;
    details?: string;
  }>({ tested: false, isValid: true });

  const loadAudit = async (adminToken: string) => {
    try {
      setLoading(true);
      setError(null);
      const res = await fetchAuditLogsApi(adminToken);
      setData(res);

      // Perform independent client-side Web Crypto verification of the hash chain
      // Sort oldest-to-newest for chain verification
      const chronological = res.entries.slice().reverse();
      const clientCheck = await verifyAuditChain(chronological);
      setClientVerification({
        tested: true,
        isValid: clientCheck.isValid,
        brokenAt: clientCheck.brokenAt,
        details: clientCheck.details,
      });
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to load audit logs.");
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadAudit(token);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleSimulateTamper = async () => {
    try {
      setSimulating(true);
      await simulateAuditTamperApi(token);
      await loadAudit(token);
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to simulate tampering");
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto space-y-6">
      {/* Header Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur shadow-2xl">
        <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
          <div>
            <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono font-medium mb-2">
              <LinkIcon className="w-3.5 h-3.5" />
              <span>Cryptographic SHA-256 Hash Chain</span>
            </div>
            <h2 className="text-2xl font-bold tracking-tight text-white">{STRINGS.audit.title}</h2>
            <p className="text-sm text-slate-400 mt-1 max-w-2xl leading-relaxed">
              {STRINGS.audit.subtitle}
            </p>
          </div>

          {/* Chain Integrity Status Card */}
          <div
            className={`p-4 rounded-xl border flex items-center gap-3 self-start md:self-auto ${
              data?.chain_valid && clientVerification.isValid
                ? "bg-emerald-950/30 border-emerald-500/40 text-emerald-300"
                : "bg-red-950/40 border-red-500/50 text-red-200 animate-pulse"
            }`}
          >
            {data?.chain_valid && clientVerification.isValid ? (
              <CheckCircle2 className="w-6 h-6 text-emerald-400 shrink-0" />
            ) : (
              <XCircle className="w-6 h-6 text-red-400 shrink-0" />
            )}
            <div>
              <div className="text-xs font-mono uppercase font-bold tracking-wider">
                {data?.chain_valid && clientVerification.isValid
                  ? "Chain Integrity: Valid"
                  : `Chain Broken at Entry #${data?.broken_at ?? clientVerification.brokenAt}`}
              </div>
              <div className="text-[11px] font-mono text-slate-400">
                {data?.total_entries ?? 0} linked events verified
              </div>
            </div>
          </div>
        </div>

        {/* Token Authentication bar */}
        <div className="mt-6 pt-5 border-t border-slate-800/80 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
          <div className="relative flex-1">
            <Key className="w-4 h-4 text-slate-500 absolute left-3 top-3" />
            <input
              type="text"
              value={token}
              onChange={(e) => setToken(e.target.value)}
              placeholder={STRINGS.audit.tokenPlaceholder}
              className="w-full pl-9 pr-3 py-2 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-300 focus:border-cyan-500 outline-none"
            />
          </div>
          <button
            onClick={() => loadAudit(token)}
            disabled={loading}
            className="px-4 py-2 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold flex items-center justify-center gap-1.5 transition-all cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${loading ? "animate-spin" : ""}`} />
            <span>Verify & Refresh</span>
          </button>
          <button
            onClick={handleSimulateTamper}
            disabled={simulating || loading}
            title="Alters a record in the database to demonstrate that the cryptographic chain immediately flags tampering."
            className="px-4 py-2 rounded-xl bg-slate-800 hover:bg-slate-700 text-amber-300 text-xs font-mono border border-amber-500/30 flex items-center justify-center gap-1.5 transition-all cursor-pointer"
          >
            <ShieldAlert className="w-3.5 h-3.5 text-amber-400" />
            <span>Simulate Tampering</span>
          </button>
        </div>
      </div>

      {error && (
        <div className="p-4 rounded-xl bg-red-950/40 border border-red-500/30 text-red-300 text-xs font-mono flex items-center gap-2">
          <XCircle className="w-4 h-4 shrink-0 text-red-400" />
          <span>{error}</span>
        </div>
      )}

      {/* Audit Log Table */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl overflow-hidden backdrop-blur shadow-2xl">
        <div className="p-4 bg-slate-950/60 border-b border-slate-800 flex items-center justify-between">
          <div className="flex items-center gap-2 text-xs font-mono text-slate-400">
            <Database className="w-4 h-4 text-cyan-400" />
            <span>Append-Only Ledger (Zero Plaintext Logged)</span>
          </div>
          <div className="text-[11px] font-mono text-slate-500">
            Genesis Hash: <span className="text-slate-400">0000000000...</span>
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-slate-950/80 text-slate-400 border-b border-slate-800">
              <tr>
                <th className="py-3 px-4">#</th>
                <th className="py-3 px-4">Timestamp (UTC)</th>
                <th className="py-3 px-4">Event</th>
                <th className="py-3 px-4">Secret ID</th>
                <th className="py-3 px-4">IP Hash (Truncated)</th>
                <th className="py-3 px-4">Previous Hash</th>
                <th className="py-3 px-4">Chain Hash (SHA-256)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/60 text-slate-300">
              {data?.entries && data.entries.length > 0 ? (
                data.entries.map((entry) => {
                  const eventColors: Record<string, string> = {
                    created: "bg-cyan-500/10 text-cyan-400 border-cyan-500/20",
                    viewed: "bg-emerald-500/10 text-emerald-400 border-emerald-500/20",
                    expired: "bg-amber-500/10 text-amber-400 border-amber-500/20",
                    deleted: "bg-red-500/10 text-red-400 border-red-500/20",
                    failed_attempt: "bg-purple-500/10 text-purple-400 border-purple-500/20",
                  };

                  return (
                    <tr key={entry.id} className="hover:bg-slate-800/40 transition-colors">
                      <td className="py-3 px-4 text-slate-500 font-bold">{entry.id}</td>
                      <td className="py-3 px-4 text-slate-400 whitespace-nowrap">
                        {new Date(entry.created_at).toLocaleString()}
                      </td>
                      <td className="py-3 px-4">
                        <span
                          className={`px-2 py-0.5 rounded text-[10px] font-bold border uppercase ${
                            eventColors[entry.event] || "bg-slate-800 text-slate-300"
                          }`}
                        >
                          {entry.event}
                        </span>
                      </td>
                      <td className="py-3 px-4 font-mono text-cyan-300">
                        {entry.secret_id.slice(0, 12)}...
                      </td>
                      <td className="py-3 px-4 text-slate-400">
                        {entry.ip_hash}
                      </td>
                      <td className="py-3 px-4 text-slate-500 font-mono" title={entry.prev_hash}>
                        {entry.prev_hash.slice(0, 10)}...
                      </td>
                      <td className="py-3 px-4 text-cyan-400 font-mono font-medium" title={entry.hash}>
                        {entry.hash.slice(0, 12)}...
                      </td>
                    </tr>
                  );
                })
              ) : (
                <tr>
                  <td colSpan={7} className="py-8 text-center text-slate-500">
                    No audit records found.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
