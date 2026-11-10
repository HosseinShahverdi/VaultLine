import { useState, useEffect, useRef } from "react";
import {
  Flame,
  Lock,
  Unlock,
  KeyRound,
  Copy,
  Check,
  AlertTriangle,
  Clock,
  ShieldAlert,
  ArrowRight,
  EyeOff,
  RefreshCw,
} from "lucide-react";
import { STRINGS } from "../lib/strings.ts";
import {
  importKeyFromBase64Url,
  decryptSecret,
  unwrapKeyWithPassphrase,
} from "../lib/crypto.ts";
import { getSecretMetaApi, revealSecretApi, SecretMetaResponse } from "../lib/api.ts";
import BurnAnimation from "./BurnAnimation.tsx";

interface RevealSecretProps {
  initialSecretId?: string;
  initialFragmentKey?: string;
  onNavigateHome?: () => void;
}

export default function RevealSecret({
  initialSecretId = "",
  initialFragmentKey = "",
  onNavigateHome,
}: RevealSecretProps) {
  const [secretId, setSecretId] = useState(initialSecretId);
  const [fragmentKey, setFragmentKey] = useState(initialFragmentKey);
  
  // Lifecycle states: "initial" | "checking" | "ready" | "passphrase_prompt" | "revealed" | "error"
  const [step, setStep] = useState<
    "input_required" | "ready" | "revealing" | "revealed" | "error"
  >("input_required");
  
  const [meta, setMeta] = useState<SecretMetaResponse | null>(null);
  const [passphrase, setPassphrase] = useState("");
  const [revealedText, setRevealedText] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);
  const [burned, setBurned] = useState(false);
  const [viewsRemaining, setViewsRemaining] = useState<number | null>(null);
  
  // 60-second screen burn countdown
  const [secondsRemaining, setSecondsRemaining] = useState(60);
  const [isAutoHidden, setIsAutoHidden] = useState(false);
  
  // Error display state
  const [errorMessage, setErrorMessage] = useState<{ title: string; desc: string } | null>(null);
  
  const timerRef = useRef<NodeJS.Timeout | null>(null);

  // Synchronize incoming props (e.g. from URL hashtag change)
  useEffect(() => {
    if (initialSecretId) {
      setSecretId(initialSecretId);
    }
    if (initialFragmentKey) {
      setFragmentKey(initialFragmentKey);
    }
  }, [initialSecretId, initialFragmentKey]);

  // When both secretId and fragmentKey are present, query metadata safely without burning
  useEffect(() => {
    if (!secretId) {
      setStep("input_required");
      return;
    }

    let isMounted = true;

    async function checkMeta() {
      try {
        const metadata = await getSecretMetaApi(secretId);
        if (!isMounted) return;

        if (!metadata.exists) {
          setStep("error");
          if (metadata.status === "destroyed") {
            setErrorMessage({
              title: STRINGS.reveal.states.destroyedTitle,
              desc: STRINGS.reveal.states.destroyedDesc,
            });
          } else if (metadata.status === "expired") {
            setErrorMessage({
              title: STRINGS.reveal.states.expiredTitle,
              desc: STRINGS.reveal.states.expiredDesc,
            });
          } else {
            setErrorMessage({
              title: STRINGS.reveal.states.notFoundTitle,
              desc: STRINGS.reveal.states.notFoundDesc,
            });
          }
          return;
        }

        setMeta(metadata);
        setStep("ready");
      } catch (err: unknown) {
        if (!isMounted) return;
        setStep("error");
        setErrorMessage({
          title: "Network Error",
          desc: err instanceof Error ? err.message : "Failed to connect to the vault server.",
        });
      }
    }

    checkMeta();

    return () => {
      isMounted = false;
    };
  }, [secretId]);

  // 60-second countdown for auto-hiding secret on screen
  useEffect(() => {
    if (step === "revealed" && revealedText && !isAutoHidden) {
      setSecondsRemaining(60);
      timerRef.current = setInterval(() => {
        setSecondsRemaining((prev) => {
          if (prev <= 1) {
            clearInterval(timerRef.current!);
            setIsAutoHidden(true);
            setRevealedText(null); // Wipe from memory
            return 0;
          }
          return prev - 1;
        });
      }, 1000);
    }

    return () => {
      if (timerRef.current) clearInterval(timerRef.current);
    };
  }, [step, revealedText, isAutoHidden]);

  // Action: User clicks "Reveal Secret Now"
  const handleReveal = async () => {
    if (!secretId) {
      setStep("error");
      setErrorMessage({
        title: STRINGS.reveal.states.notFoundTitle,
        desc: STRINGS.reveal.states.notFoundDesc,
      });
      return;
    }

    if (!fragmentKey) {
      setStep("error");
      setErrorMessage({
        title: STRINGS.reveal.states.missingKeyTitle,
        desc: STRINGS.reveal.states.missingKeyDesc,
      });
      return;
    }

    // If secret requires passphrase and none is entered yet
    if (meta?.has_passphrase && !passphrase) {
      // Focus on passphrase
      return;
    }

    try {
      setStep("revealing");

      // 1. Atomically consume a view from the server
      const payload = await revealSecretApi(secretId);

      // 2. Prepare content key
      let contentKey: CryptoKey;

      if (meta?.has_passphrase && payload.wrapped_key && payload.salt) {
        try {
          contentKey = await unwrapKeyWithPassphrase(
            payload.wrapped_key,
            payload.salt,
            passphrase
          );
        } catch {
          setStep("error");
          setErrorMessage({
            title: STRINGS.reveal.states.wrongPassphraseTitle,
            desc: STRINGS.reveal.states.wrongPassphraseDesc,
          });
          return;
        }
      } else {
        try {
          contentKey = await importKeyFromBase64Url(fragmentKey);
        } catch {
          setStep("error");
          setErrorMessage({
            title: STRINGS.reveal.states.failedDecryptionTitle,
            desc: STRINGS.reveal.states.failedDecryptionDesc,
          });
          return;
        }
      }

      // 3. Decrypt ciphertext in browser with AES-256-GCM
      const decrypted = await decryptSecret(payload.ciphertext, payload.iv, contentKey);

      setRevealedText(decrypted);
      setBurned(payload.burned);
      setViewsRemaining(Math.max(0, payload.max_views - payload.views));
      setStep("revealed");
    } catch (err: unknown) {
      setStep("error");
      // @ts-expect-error status on error
      if (err.status === "expired") {
        setErrorMessage({
          title: STRINGS.reveal.states.expiredTitle,
          desc: STRINGS.reveal.states.expiredDesc,
        });
      } else {
        setErrorMessage({
          title: STRINGS.reveal.states.destroyedTitle,
          desc: err instanceof Error ? err.message : STRINGS.reveal.states.destroyedDesc,
        });
      }
    }
  };

  const handleCopy = async () => {
    if (!revealedText) return;
    try {
      await navigator.clipboard.writeText(revealedText);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    } catch {
      setCopied(true);
    }
  };

  const handleManualLookup = (e: React.FormEvent) => {
    e.preventDefault();
    if (secretId) {
      setStep("ready");
    }
  };

  return (
    <div className="w-full max-w-2xl mx-auto">
      {/* 1. INPUT REQUIRED STATE (User navigated directly to Reveal tab without URL params) */}
      {step === "input_required" && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl">
          <div className="flex items-center gap-3 text-cyan-400 mb-4">
            <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
              <Lock className="w-5 h-5 text-cyan-400" />
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">Manual Secret Decryption</h2>
              <p className="text-xs text-slate-400 font-mono">
                Paste a secret ID and decryption key, or open any link generated by VaultLine.
              </p>
            </div>
          </div>

          <form onSubmit={handleManualLookup} className="space-y-4">
            <div>
              <label htmlFor="secret-id-input" className="text-xs font-mono uppercase text-slate-400 block mb-1">
                Secret Identifier (128-bit ID)
              </label>
              <input
                id="secret-id-input"
                type="text"
                value={secretId}
                onChange={(e) => setSecretId(e.target.value.trim())}
                placeholder="e.g. 5xG_8JkWq19r..."
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-sm font-mono text-cyan-300 focus:border-cyan-500 outline-none"
                required
              />
            </div>
            <div>
              <label htmlFor="fragment-key-input" className="text-xs font-mono uppercase text-slate-400 block mb-1">
                Decryption Key (#fragment)
              </label>
              <input
                id="fragment-key-input"
                type="text"
                value={fragmentKey}
                onChange={(e) => setFragmentKey(e.target.value.trim())}
                placeholder="e.g. wZ9L61e7k..."
                className="w-full p-3 rounded-xl bg-slate-950 border border-slate-800 text-sm font-mono text-cyan-300 focus:border-cyan-500 outline-none"
                required
              />
            </div>
            <button
              type="submit"
              className="w-full py-3 px-6 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-bold text-sm flex items-center justify-center gap-2 transition-all cursor-pointer shadow-lg shadow-cyan-500/20"
            >
              <span>Load Secret Details</span>
              <ArrowRight className="w-4 h-4" />
            </button>
          </form>
        </div>
      )}

      {/* 2. SAFE LANDING STATE (Bot-proof screen) */}
      {(step === "ready" || step === "revealing") && (
        <div className="bg-slate-900/80 border border-slate-800 hover:border-slate-700/80 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl transition-all text-center">
          <div className="w-16 h-16 rounded-2xl bg-orange-500/10 border border-orange-500/30 flex items-center justify-center mx-auto mb-4">
            <Flame className="w-8 h-8 text-orange-400 animate-pulse" />
          </div>

          <h2 className="text-2xl font-bold tracking-tight text-white mb-2">
            {STRINGS.reveal.title}
          </h2>
          <p className="text-sm font-mono text-orange-400 font-semibold mb-4">
            {STRINGS.reveal.landingNotice}
          </p>

          <div className="max-w-md mx-auto p-3.5 rounded-xl bg-slate-950/70 border border-slate-800 text-xs text-slate-400 font-mono mb-6 leading-relaxed text-left">
            <p className="flex items-start gap-2">
              <ShieldAlert className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
              <span>{STRINGS.reveal.botProtectionNotice}</span>
            </p>
          </div>

          {/* Passphrase field if required */}
          {meta?.has_passphrase && (
            <div className="max-w-md mx-auto mb-6 p-4 rounded-xl bg-cyan-950/20 border border-cyan-800/40 text-left">
              <div className="flex items-center gap-2 text-cyan-300 font-medium text-xs font-mono mb-2">
                <KeyRound className="w-4 h-4 text-cyan-400" />
                <span>{STRINGS.reveal.passphraseRequiredTitle}</span>
              </div>
              <p className="text-xs text-slate-400 mb-3">
                {STRINGS.reveal.passphraseRequiredNotice}
              </p>
              <input
                type="password"
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder={STRINGS.reveal.passphraseInputPlaceholder}
                className="w-full px-3.5 py-2.5 rounded-lg bg-slate-950 border border-slate-700 text-sm font-mono text-white placeholder-slate-600 focus:border-cyan-500 outline-none"
              />
            </div>
          )}

          {/* Reveal button */}
          <button
            onClick={handleReveal}
            disabled={step === "revealing" || (meta?.has_passphrase && !passphrase)}
            className="w-full max-w-md mx-auto py-3.5 px-6 rounded-xl bg-gradient-to-r from-orange-500 to-amber-500 hover:from-orange-400 hover:to-amber-400 disabled:opacity-50 text-slate-950 font-bold text-sm flex items-center justify-center gap-2 transition-all shadow-xl shadow-orange-500/20 cursor-pointer active:scale-95"
          >
            {step === "revealing" ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                <span>{STRINGS.reveal.revealing}</span>
              </>
            ) : (
              <>
                <Unlock className="w-4 h-4" />
                <span>{meta?.has_passphrase ? STRINGS.reveal.passphraseSubmit : STRINGS.reveal.revealButton}</span>
              </>
            )}
          </button>
        </div>
      )}

      {/* 3. REVEALED STATE (Decrypted secret shown with copy button, burn flame, & 60s countdown) */}
      {step === "revealed" && (
        <div className="bg-slate-900/90 border border-cyan-500/40 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl shadow-cyan-950/40">
          {/* Flame animation upon destruction */}
          {burned && <BurnAnimation />}

          {/* Header */}
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 mb-6">
            <div>
              <div className="flex items-center gap-2">
                <span className="px-2.5 py-0.5 rounded text-[11px] font-mono font-bold bg-red-500/20 text-red-400 border border-red-500/30">
                  {STRINGS.reveal.burnBadge}
                </span>
                {viewsRemaining !== null && viewsRemaining > 0 && (
                  <span className="px-2.5 py-0.5 rounded text-[11px] font-mono bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    {viewsRemaining} view left
                  </span>
                )}
              </div>
              <h2 className="text-xl font-bold text-white mt-1.5">{STRINGS.reveal.secretRevealedTitle}</h2>
              <p className="text-xs text-slate-400 font-mono">{STRINGS.reveal.secretRevealedSubtitle}</p>
            </div>

            {/* Countdown Badge */}
            <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-slate-950 border border-slate-800 text-xs font-mono text-cyan-400 self-start sm:self-auto">
              <Clock className="w-3.5 h-3.5 animate-spin" style={{ animationDuration: "3s" }} />
              <span>Auto-wipe in {secondsRemaining}s</span>
            </div>
          </div>

          {/* Secret Container */}
          {isAutoHidden ? (
            <div className="p-8 rounded-xl bg-slate-950 border border-slate-800 text-center space-y-3">
              <EyeOff className="w-8 h-8 text-slate-600 mx-auto" />
              <p className="text-sm font-mono text-slate-400">
                Secret obscured for security. 60-second viewing timeout elapsed.
              </p>
              <button
                onClick={onNavigateHome}
                className="inline-flex items-center gap-1.5 px-4 py-2 rounded-lg bg-slate-800 hover:bg-slate-700 text-xs font-mono text-cyan-300 cursor-pointer"
              >
                Create New Secret
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              <div className="relative">
                <pre className="w-full p-4 rounded-xl bg-slate-950 border border-slate-800 font-mono text-sm text-cyan-200 overflow-x-auto whitespace-pre-wrap break-all selection:bg-cyan-500/40">
                  {revealedText}
                </pre>
                <button
                  onClick={handleCopy}
                  className="absolute top-3 right-3 px-3.5 py-1.5 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-semibold text-xs flex items-center gap-1.5 transition-all shadow cursor-pointer active:scale-95"
                  aria-label="Copy secret"
                >
                  {copied ? (
                    <>
                      <Check className="w-3.5 h-3.5 text-emerald-950" />
                      <span>{STRINGS.reveal.secretCopied}</span>
                    </>
                  ) : (
                    <>
                      <Copy className="w-3.5 h-3.5" />
                      <span>{STRINGS.reveal.copySecret}</span>
                    </>
                  )}
                </button>
              </div>

              {/* Security timeout bar */}
              <div className="w-full bg-slate-950 rounded-full h-1.5 overflow-hidden">
                <div
                  className="bg-cyan-500 h-full transition-all duration-1000 ease-linear"
                  style={{ width: `${(secondsRemaining / 60) * 100}%` }}
                />
              </div>

              <div className="flex items-center justify-between pt-4 border-t border-slate-800 text-xs font-mono text-slate-400">
                <span className="flex items-center gap-1.5">
                  <Flame className="w-3.5 h-3.5 text-orange-400" />
                  No traces left on the server
                </span>
                <button
                  onClick={onNavigateHome}
                  className="text-cyan-400 hover:text-cyan-300 font-medium cursor-pointer"
                >
                  {STRINGS.reveal.backHome} &rarr;
                </button>
              </div>
            </div>
          )}
        </div>
      )}

      {/* 4. ERROR STATES (Already viewed, expired, not found, wrong passphrase) */}
      {step === "error" && errorMessage && (
        <div className="bg-slate-900/80 border border-slate-800 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl text-center">
          <div className="w-14 h-14 rounded-2xl bg-red-500/10 border border-red-500/20 flex items-center justify-center mx-auto mb-4">
            <AlertTriangle className="w-7 h-7 text-red-400" />
          </div>

          <h3 className="text-xl font-bold text-white mb-2">{errorMessage.title}</h3>
          <p className="text-sm text-slate-400 font-mono max-w-md mx-auto mb-6 leading-relaxed">
            {errorMessage.desc}
          </p>

          <div className="flex justify-center gap-4">
            <button
              onClick={onNavigateHome}
              className="px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold cursor-pointer shadow-lg shadow-cyan-500/20"
            >
              {STRINGS.reveal.backHome}
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
