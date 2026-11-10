import { useState, useEffect } from "react";
import {
  Flame,
  Shield,
  PlusCircle,
  Unlock,
  Database,
  BookOpen,
  Code2,
  Lock,
  ExternalLink,
} from "lucide-react";
import CreateSecret from "./components/CreateSecret.tsx";
import RevealSecret from "./components/RevealSecret.tsx";
import AuditLogView from "./components/AuditLogView.tsx";
import ThreatModelView from "./components/ThreatModelView.tsx";
import CodebaseExplorer from "./components/CodebaseExplorer.tsx";
import { STRINGS } from "./lib/strings.ts";

export type NavTab = "create" | "reveal" | "audit" | "threat" | "codebase";

export default function App() {
  const [activeTab, setActiveTab] = useState<NavTab>("create");
  const [revealSecretId, setRevealSecretId] = useState("");
  const [revealFragmentKey, setRevealFragmentKey] = useState("");

  // Parse URL hash on mount or hashchange (Zero-Knowledge: fragments are never sent to server)
  useEffect(() => {
    function parseHash() {
      const hash = window.location.hash;
      if (!hash) return;

      // Format 1: #s=ID&key=KEY
      const params = new URLSearchParams(hash.replace(/^#/, ""));
      const s = params.get("s");
      const key = params.get("key");

      if (s && key) {
        setRevealSecretId(s);
        setRevealFragmentKey(key);
        setActiveTab("reveal");
        return;
      }

      // Format 2: Direct path /s/ID#KEY
      const pathname = window.location.pathname;
      const pathMatch = pathname.match(/\/s\/([A-Za-z0-9_-]+)/);
      if (pathMatch && hash.length > 1) {
        setRevealSecretId(pathMatch[1]);
        setRevealFragmentKey(hash.substring(1));
        setActiveTab("reveal");
      }
    }

    parseHash();
    window.addEventListener("hashchange", parseHash);
    return () => window.removeEventListener("hashchange", parseHash);
  }, []);

  const handleSecretCreated = (url: string) => {
    // URL was created, ready for sharing
  };

  return (
    <div className="min-h-screen bg-[#07090e] text-slate-100 flex flex-col font-sans selection:bg-cyan-500/30 selection:text-cyan-200">
      {/* Background radial glow */}
      <div className="fixed inset-0 pointer-events-none overflow-hidden z-0">
        <div className="absolute -top-40 left-1/2 -translate-x-1/2 w-[700px] h-[350px] bg-cyan-600/10 blur-[130px] rounded-full" />
        <div className="absolute top-1/3 -right-40 w-[400px] h-[400px] bg-orange-600/5 blur-[120px] rounded-full" />
      </div>

      {/* Top Header Navigation */}
      <header className="sticky top-0 z-40 border-b border-slate-800/80 bg-[#07090e]/85 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 h-16 flex items-center justify-between">
          {/* Logo & Tagline */}
          <button
            onClick={() => setActiveTab("create")}
            className="flex items-center gap-3 text-left group cursor-pointer"
          >
            <div className="w-9 h-9 rounded-xl bg-gradient-to-br from-cyan-400 to-cyan-600 flex items-center justify-center shadow-lg shadow-cyan-500/20 group-hover:scale-105 transition-transform">
              <Flame className="w-5 h-5 text-slate-950" />
            </div>
            <div>
              <div className="flex items-center gap-2">
                <span className="font-bold text-base tracking-tight text-white group-hover:text-cyan-300 transition-colors">
                  {STRINGS.app.name}
                </span>
                <span className="hidden sm:inline-flex px-2 py-0.5 rounded text-[10px] font-mono uppercase bg-cyan-500/15 border border-cyan-500/30 text-cyan-300 font-semibold tracking-wider">
                  Zero-Knowledge
                </span>
              </div>
              <p className="text-[11px] font-mono text-slate-400 hidden md:block">
                {STRINGS.app.tagline}
              </p>
            </div>
          </button>

          {/* Navigation Links */}
          <nav className="flex items-center gap-1 sm:gap-2">
            <button
              onClick={() => setActiveTab("create")}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === "create"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Create</span>
            </button>

            <button
              onClick={() => setActiveTab("reveal")}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === "reveal"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <Unlock className="w-3.5 h-3.5" />
              <span>Reveal</span>
            </button>

            <button
              onClick={() => setActiveTab("audit")}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === "audit"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <Database className="w-3.5 h-3.5" />
              <span className="hidden sm:inline">Audit Log</span>
              <span className="sm:hidden">Audit</span>
            </button>

            <button
              onClick={() => setActiveTab("threat")}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === "threat"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <Shield className="w-3.5 h-3.5" />
              <span className="hidden md:inline">Threat Model</span>
              <span className="md:hidden">Security</span>
            </button>

            <button
              onClick={() => setActiveTab("codebase")}
              className={`px-3 py-1.5 rounded-xl text-xs font-mono font-medium transition-all flex items-center gap-1.5 cursor-pointer ${
                activeTab === "codebase"
                  ? "bg-cyan-500 text-slate-950 font-bold shadow-md shadow-cyan-500/20"
                  : "text-slate-400 hover:text-white hover:bg-slate-800/60"
              }`}
            >
              <Code2 className="w-3.5 h-3.5" />
              <span className="hidden lg:inline">Laravel Specs</span>
              <span className="lg:hidden">Code</span>
            </button>
          </nav>
        </div>
      </header>

      {/* Main Content Viewport */}
      <main className="flex-1 max-w-7xl w-full mx-auto px-4 sm:px-6 lg:px-8 py-8 sm:py-12 z-10">
        {activeTab === "create" && (
          <CreateSecret onSecretCreated={handleSecretCreated} />
        )}

        {activeTab === "reveal" && (
          <RevealSecret
            initialSecretId={revealSecretId}
            initialFragmentKey={revealFragmentKey}
            onNavigateHome={() => setActiveTab("create")}
          />
        )}

        {activeTab === "audit" && <AuditLogView />}

        {activeTab === "threat" && <ThreatModelView />}

        {activeTab === "codebase" && <CodebaseExplorer />}
      </main>

      {/* Footer */}
      <footer className="border-t border-slate-900 bg-slate-950/60 py-6 text-xs font-mono text-slate-500 z-10">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 flex flex-col sm:flex-row items-center justify-between gap-3">
          <div className="flex items-center gap-2">
            <Lock className="w-3.5 h-3.5 text-cyan-500" />
            <span>VaultLine: End-to-End Client Encrypted with Pure Web Crypto API</span>
          </div>
          <div className="flex items-center gap-4 text-slate-400">
            <button
              onClick={() => setActiveTab("threat")}
              className="hover:text-cyan-300 transition-colors cursor-pointer"
            >
              Zero-Knowledge Threat Model
            </button>
            <span>•</span>
            <button
              onClick={() => setActiveTab("codebase")}
              className="hover:text-cyan-300 transition-colors cursor-pointer"
            >
              Laravel 11 & Docker
            </button>
          </div>
        </div>
      </footer>
    </div>
  );
}
