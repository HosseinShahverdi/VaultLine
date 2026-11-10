import {
  ShieldAlert,
  ShieldCheck,
  Lock,
  EyeOff,
  AlertTriangle,
  Server,
  Cpu,
  Globe,
  Database,
  Terminal,
} from "lucide-react";

export default function ThreatModelView() {
  return (
    <div className="w-full max-w-5xl mx-auto space-y-6">
      {/* Top Banner */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl">
        <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono font-medium mb-3">
          <ShieldCheck className="w-3.5 h-3.5" />
          <span>Cryptographic Security Blueprint</span>
        </div>
        <h2 className="text-2xl font-bold tracking-tight text-white">VaultLine Threat Model & Security Posture</h2>
        <p className="text-sm text-slate-400 mt-2 max-w-3xl leading-relaxed">
          VaultLine is engineered strictly as a <strong>Zero-Knowledge system</strong>. The server is treated as completely untrusted. Even with full root access or physical dump of the database, an adversary cannot recover the secret plaintext.
        </p>
      </div>

      {/* Two Column Grid: What Server Can See vs Cannot See */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* What Server CANNOT See */}
        <div className="bg-slate-900/80 border border-emerald-500/30 rounded-2xl p-6 backdrop-blur shadow-xl space-y-4">
          <div className="flex items-center gap-3 text-emerald-400">
            <div className="w-10 h-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center">
              <EyeOff className="w-5 h-5 text-emerald-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">What the Server Cannot See</h3>
              <p className="text-xs text-slate-400 font-mono">Guaranteed by client-side Web Crypto</p>
            </div>
          </div>

          <ul className="space-y-3 text-xs text-slate-300 font-mono">
            <li className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-950/70 border border-slate-800">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-white block mb-0.5">Plaintext Secret Content</strong>
                Secrets are encrypted inside the browser using AES-256-GCM before any network packet is dispatched.
              </div>
            </li>
            <li className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-950/70 border border-slate-800">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-white block mb-0.5">Content Encryption Key</strong>
                The key is placed solely in the URL fragment (<code className="text-cyan-300">#key</code>). RFC 3986 specifies that fragments are processed exclusively on the client and are never sent in HTTP request lines.
              </div>
            </li>
            <li className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-950/70 border border-slate-800">
              <ShieldCheck className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-white block mb-0.5">Optional Passphrase</strong>
                Passphrases are transformed locally using PBKDF2 with 600,000 iterations to wrap the key. The passphrase is never stored or transmitted.
              </div>
            </li>
          </ul>
        </div>

        {/* What Server CAN See */}
        <div className="bg-slate-900/80 border border-cyan-500/30 rounded-2xl p-6 backdrop-blur shadow-xl space-y-4">
          <div className="flex items-center gap-3 text-cyan-400">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
              <Server className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h3 className="text-lg font-bold text-white">What the Server Can See</h3>
              <p className="text-xs text-slate-400 font-mono">Required for routing & storage</p>
            </div>
          </div>

          <ul className="space-y-3 text-xs text-slate-300 font-mono">
            <li className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-950/70 border border-slate-800">
              <Database className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-white block mb-0.5">Opaque Ciphertext Blob & IV</strong>
                A base64-encoded encrypted blob indistinguishable from random noise, alongside a 96-bit initialization vector.
              </div>
            </li>
            <li className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-950/70 border border-slate-800">
              <Cpu className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-white block mb-0.5">Expiry & View Counters</strong>
                The target expiration timestamp and maximum allowed view count to enforce auto-deletion and atomic burn.
              </div>
            </li>
            <li className="flex items-start gap-2.5 p-3 rounded-xl bg-slate-950/70 border border-slate-800">
              <Globe className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <div>
                <strong className="text-white block mb-0.5">Truncated IP Hash</strong>
                A 16-character salted SHA-256 hash of the requester's IP for rate limiting and tamper-evident audit logging.
              </div>
            </li>
          </ul>
        </div>
      </div>

      {/* Known Limitations & Defense Mechanisms */}
      <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 backdrop-blur shadow-2xl space-y-4">
        <div className="flex items-center gap-3 text-amber-400">
          <div className="w-10 h-10 rounded-xl bg-amber-500/10 border border-amber-500/20 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h3 className="text-lg font-bold text-white">Known Limitations & Mitigations</h3>
            <p className="text-xs text-slate-400 font-mono">Realistic threat boundaries</p>
          </div>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 pt-2">
          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
            <span className="text-amber-400 font-bold block">1. Compromised Client Device</span>
            <p className="text-slate-400 leading-relaxed">
              If the sender or recipient has spyware, malware, or an active keylogger, the secret can be captured in memory or from keystrokes.
            </p>
            <span className="text-cyan-400 text-[11px] block">Mitigation: 60-second screen timeout and memory clearing.</span>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
            <span className="text-amber-400 font-bold block">2. Link-Preview Scrapers</span>
            <p className="text-slate-400 leading-relaxed">
              Chat bots (Slack, Discord, iMessage) fetch URLs to generate rich cards. An immediate burn on GET would destroy secrets prematurely.
            </p>
            <span className="text-cyan-400 text-[11px] block">Mitigation: Separate metadata check; consume ONLY on explicit POST click.</span>
          </div>

          <div className="p-4 rounded-xl bg-slate-950 border border-slate-800 text-xs font-mono space-y-2">
            <span className="text-amber-400 font-bold block">3. Recipient Screen Capture</span>
            <p className="text-slate-400 leading-relaxed">
              Once decrypted in the recipient's browser, the user could take a screenshot or photograph the monitor with a smartphone.
            </p>
            <span className="text-cyan-400 text-[11px] block">Mitigation: Inherent limit of digital displays; out-of-band trust model.</span>
          </div>
        </div>
      </div>
    </div>
  );
}
