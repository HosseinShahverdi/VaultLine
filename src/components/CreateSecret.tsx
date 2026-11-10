import { useState, useId } from "react";
import {
  ShieldCheck,
  KeyRound,
  Clock,
  Eye,
  Copy,
  Check,
  Flame,
  AlertCircle,
  RefreshCw,
  Lock,
  ChevronDown,
  Sparkles,
} from "lucide-react";
import { STRINGS } from "../lib/strings.ts";
import {
  generateContentKey,
  exportKeyToBase64Url,
  encryptSecret,
  wrapKeyWithPassphrase,
} from "../lib/crypto.ts";
import { createSecretApi } from "../lib/api.ts";

interface CreateSecretProps {
  onSecretCreated?: (url: string) => void;
}

export default function CreateSecret({ onSecretCreated }: CreateSecretProps) {
  const [plaintext, setPlaintext] = useState("");
  const [expiresIn, setExpiresIn] = useState<"5m" | "1h" | "24h" | "7d">("24h");
  const [maxViews, setMaxViews] = useState<number>(1);
  const [usePassphrase, setUsePassphrase] = useState(false);
  const [passphrase, setPassphrase] = useState("");
  const [passphraseConfirm, setPassphraseConfirm] = useState("");
  
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  // Output state
  const [createdLink, setCreatedLink] = useState<string | null>(null);
  const [expiresAt, setExpiresAt] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  const secretInputId = useId();
  const passphraseInputId = useId();
  const passphraseConfirmId = useId();

  const charCount = plaintext.length;
  const maxChars = 10000;

  const handleCreate = async (e: React.FormEvent) => {
    e.preventDefault();
    setError(null);

    const trimmed = plaintext.trim();
    if (!trimmed) {
      setError(STRINGS.create.errorEmpty);
      return;
    }

    if (trimmed.length > maxChars) {
      setError(STRINGS.create.errorTooLong);
      return;
    }

    if (usePassphrase) {
      if (!passphrase || passphrase.length < 4) {
        setError("Passphrase must be at least 4 characters long.");
        return;
      }
      if (passphrase !== passphraseConfirm) {
        setError(STRINGS.create.passphraseMismatch);
        return;
      }
    }

    try {
      setIsSubmitting(true);

      // Step 1: Generate high-entropy 256-bit AES-GCM content key
      const contentKey = await generateContentKey();

      // Step 2: Encrypt secret locally with AES-256-GCM + 96-bit random IV
      const { ciphertext, iv } = await encryptSecret(trimmed, contentKey);

      // Step 3: Optional PBKDF2 passphrase key wrapping (600,000 iterations)
      let wrappedKey: string | null = null;
      let salt: string | null = null;

      if (usePassphrase) {
        const wrapResult = await wrapKeyWithPassphrase(contentKey, passphrase);
        wrappedKey = wrapResult.wrappedKey;
        salt = wrapResult.salt;
      }

      // Step 4: Export raw content key to URL fragment format
      const fragmentKey = await exportKeyToBase64Url(contentKey);

      // Step 5: Send only ciphertext and metadata to the server.
      // NOTE: Neither the plaintext nor the contentKey is ever transmitted!
      const response = await createSecretApi({
        ciphertext,
        iv,
        expires_in: expiresIn,
        max_views: maxViews,
        has_passphrase: usePassphrase,
        wrapped_key: wrappedKey,
        salt: salt,
      });

      // Construct zero-knowledge link: key is ONLY in URL fragment (#)
      // Browsers never send fragments to servers in HTTP requests
      const origin = window.location.origin;
      const fullUrl = `${origin}/#s=${response.id}&key=${fragmentKey}`;

      setCreatedLink(fullUrl);
      setExpiresAt(response.expires_at);
      onSecretCreated?.(fullUrl);

      // Wipe sensitive memory states
      setPlaintext("");
      setPassphrase("");
      setPassphraseConfirm("");
    } catch (err: unknown) {
      setError(err instanceof Error ? err.message : "Failed to encrypt and store secret.");
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleCopy = async () => {
    if (!createdLink) return;
    try {
      await navigator.clipboard.writeText(createdLink);
      setCopied(true);
      setTimeout(() => setCopied(false), 3000);
    } catch {
      // Fallback
      setCopied(true);
    }
  };

  const handleReset = () => {
    setCreatedLink(null);
    setExpiresAt(null);
    setError(null);
    setPlaintext("");
    setPassphrase("");
    setPassphraseConfirm("");
    setUsePassphrase(false);
  };

  if (createdLink) {
    return (
      <div className="w-full max-w-2xl mx-auto bg-slate-900/80 border border-cyan-500/30 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl shadow-cyan-950/20">
        <div className="flex items-center gap-3 text-cyan-400 mb-3">
          <div className="w-10 h-10 rounded-xl bg-cyan-500/10 border border-cyan-500/20 flex items-center justify-center">
            <ShieldCheck className="w-6 h-6 text-cyan-400" />
          </div>
          <div>
            <h2 className="text-xl font-bold tracking-tight text-white">{STRINGS.create.createdTitle}</h2>
            <p className="text-xs text-slate-400">{STRINGS.create.createdSubtitle}</p>
          </div>
        </div>

        {/* Secret link display */}
        <div className="my-6 space-y-3">
          <label className="text-xs font-mono uppercase tracking-wider text-slate-400 block">
            One-Time Decryption Link
          </label>
          <div className="relative group">
            <div className="p-3.5 pr-28 rounded-xl bg-slate-950 border border-slate-700/80 font-mono text-sm text-cyan-300 break-all select-all focus-within:border-cyan-500 transition-colors">
              {createdLink}
            </div>
            <button
              onClick={handleCopy}
              className="absolute right-2 top-2 bottom-2 px-4 rounded-lg bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-medium text-xs flex items-center gap-1.5 transition-all shadow-md shadow-cyan-500/20 cursor-pointer active:scale-95"
              aria-label="Copy secret link to clipboard"
            >
              {copied ? (
                <>
                  <Check className="w-4 h-4 text-emerald-950" />
                  <span>{STRINGS.create.copied}</span>
                </>
              ) : (
                <>
                  <Copy className="w-4 h-4" />
                  <span>Copy Link</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Expiry and views info */}
        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 p-4 rounded-xl bg-slate-950/60 border border-slate-800 text-xs text-slate-300 font-mono">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-cyan-400" />
            <span>
              Expires: {expiresAt ? new Date(expiresAt).toLocaleString() : expiresIn}
            </span>
          </div>
          <div className="flex items-center gap-2">
            <Flame className="w-4 h-4 text-orange-400" />
            <span>View Limit: {maxViews} {maxViews === 1 ? "view (immediate burn)" : "views"}</span>
          </div>
        </div>

        {/* Security badge notice */}
        <div className="mt-5 p-3.5 rounded-xl bg-cyan-950/30 border border-cyan-800/40 text-xs text-cyan-200/90 leading-relaxed space-y-2">
          <div className="flex items-start gap-2">
            <Lock className="w-4 h-4 text-cyan-400 shrink-0 mt-0.5" />
            <p>{STRINGS.create.fragmentNotice}</p>
          </div>
          {usePassphrase && (
            <div className="flex items-start gap-2 pt-2 border-t border-cyan-800/30 text-amber-200">
              <KeyRound className="w-4 h-4 text-amber-400 shrink-0 mt-0.5" />
              <p>{STRINGS.create.passphraseReminder}</p>
            </div>
          )}
        </div>

        {/* Actions */}
        <div className="mt-8 flex flex-col sm:flex-row items-center justify-between gap-4">
          <a
            href={createdLink}
            className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-slate-800 hover:bg-slate-700 text-cyan-300 text-xs font-mono font-medium border border-cyan-500/20 flex items-center justify-center gap-2 transition-colors cursor-pointer"
          >
            <Eye className="w-4 h-4" />
            Test Reveal Page (Recipient View)
          </a>
          <button
            onClick={handleReset}
            className="w-full sm:w-auto px-5 py-2.5 rounded-xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 text-xs font-semibold flex items-center justify-center gap-2 transition-all cursor-pointer shadow-lg shadow-cyan-500/20"
          >
            <RefreshCw className="w-4 h-4" />
            {STRINGS.create.createAnother}
          </button>
        </div>
      </div>
    );
  }

  return (
    <div className="w-full max-w-2xl mx-auto">
      <div className="bg-slate-900/80 border border-slate-800 hover:border-slate-700/80 rounded-2xl p-6 sm:p-8 backdrop-blur shadow-2xl transition-all">
        {/* Header */}
        <div className="mb-6">
          <div className="inline-flex items-center gap-2 px-2.5 py-1 rounded-full bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-mono font-medium mb-3">
            <Sparkles className="w-3.5 h-3.5" />
            <span>Client-Side AES-256-GCM Encryption</span>
          </div>
          <h2 className="text-2xl font-bold tracking-tight text-white">{STRINGS.create.title}</h2>
          <p className="text-sm text-slate-400 mt-1 leading-relaxed">
            {STRINGS.create.subtitle}
          </p>
        </div>

        {error && (
          <div
            role="alert"
            className="mb-6 p-4 rounded-xl bg-red-950/40 border border-red-500/30 text-red-200 text-sm flex items-start gap-3"
          >
            <AlertCircle className="w-5 h-5 text-red-400 shrink-0 mt-0.5" />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={handleCreate} className="space-y-6">
          {/* Plaintext Textarea */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label
                htmlFor={secretInputId}
                className="text-xs font-mono uppercase tracking-wider text-slate-300 font-medium"
              >
                Confidential Secret Plaintext
              </label>
              <span
                className={`text-xs font-mono ${
                  charCount > maxChars ? "text-red-400" : "text-slate-500"
                }`}
              >
                {charCount.toLocaleString()} / {maxChars.toLocaleString()} characters
              </span>
            </div>
            <textarea
              id={secretInputId}
              value={plaintext}
              onChange={(e) => setPlaintext(e.target.value)}
              placeholder={STRINGS.create.textareaPlaceholder}
              rows={6}
              maxLength={maxChars}
              className="w-full p-4 rounded-xl bg-slate-950/90 border border-slate-800 focus:border-cyan-500 focus:ring-1 focus:ring-cyan-500 text-slate-100 placeholder-slate-600 font-mono text-sm leading-relaxed outline-none transition-all resize-y min-h-[140px]"
              required
            />
          </div>

          {/* Options Grid: Expiry & Max Views */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            {/* Expiry Selector */}
            <div className="space-y-2">
              <label className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Clock className="w-3.5 h-3.5 text-cyan-400" />
                {STRINGS.create.expiryLabel}
              </label>
              <div className="grid grid-cols-2 gap-2">
                {(["5m", "1h", "24h", "7d"] as const).map((opt) => (
                  <button
                    key={opt}
                    type="button"
                    onClick={() => setExpiresIn(opt)}
                    className={`py-2 px-3 rounded-lg text-xs font-mono border transition-all cursor-pointer ${
                      expiresIn === opt
                        ? "bg-cyan-500/15 border-cyan-500 text-cyan-300 font-semibold shadow-sm shadow-cyan-500/20"
                        : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    {STRINGS.create.expiryOptions[opt]}
                  </button>
                ))}
              </div>
            </div>

            {/* View Limit */}
            <div className="space-y-2">
              <label className="text-xs font-mono uppercase tracking-wider text-slate-400 flex items-center gap-1.5">
                <Flame className="w-3.5 h-3.5 text-orange-400" />
                {STRINGS.create.viewLimitLabel}
              </label>
              <div className="flex gap-2">
                {[1, 2, 3, 5].map((views) => (
                  <button
                    key={views}
                    type="button"
                    onClick={() => setMaxViews(views)}
                    className={`flex-1 py-2 rounded-lg text-xs font-mono border transition-all cursor-pointer ${
                      maxViews === views
                        ? "bg-orange-500/15 border-orange-500 text-orange-300 font-semibold shadow-sm shadow-orange-500/20"
                        : "bg-slate-950 border-slate-800 text-slate-400 hover:border-slate-700"
                    }`}
                  >
                    {views === 1 ? "1 view" : `${views} views`}
                  </button>
                ))}
              </div>
              <p className="text-[11px] text-slate-500 font-mono">
                {maxViews === 1
                  ? "Standard: Burns and deletes immediately on first reveal."
                  : `Burns permanently after ${maxViews} successful reveals.`}
              </p>
            </div>
          </div>

          {/* Optional Passphrase Accordion */}
          <div className="border border-slate-800/80 rounded-xl overflow-hidden bg-slate-950/40">
            <button
              type="button"
              onClick={() => setUsePassphrase(!usePassphrase)}
              className="w-full p-4 flex items-center justify-between text-left text-xs font-mono text-slate-300 hover:text-white transition-colors cursor-pointer"
            >
              <div className="flex items-center gap-2.5">
                <KeyRound className={`w-4 h-4 ${usePassphrase ? "text-cyan-400" : "text-slate-500"}`} />
                <span className="font-medium">{STRINGS.create.passphraseToggle}</span>
                {usePassphrase && (
                  <span className="px-1.5 py-0.5 rounded text-[10px] bg-cyan-500/20 text-cyan-300 font-mono">
                    PBKDF2 Enabled
                  </span>
                )}
              </div>
              <ChevronDown
                className={`w-4 h-4 text-slate-500 transition-transform ${
                  usePassphrase ? "rotate-180" : ""
                }`}
              />
            </button>

            {usePassphrase && (
              <div className="p-4 pt-0 space-y-3 border-t border-slate-800/60 mt-2">
                <p className="text-xs text-slate-400 font-mono leading-relaxed">
                  {STRINGS.create.passphraseHint}
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label htmlFor={passphraseInputId} className="sr-only">Passphrase</label>
                    <input
                      id={passphraseInputId}
                      type="password"
                      value={passphrase}
                      onChange={(e) => setPassphrase(e.target.value)}
                      placeholder={STRINGS.create.passphrasePlaceholder}
                      className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white placeholder-slate-600 focus:border-cyan-500 outline-none"
                    />
                  </div>
                  <div>
                    <label htmlFor={passphraseConfirmId} className="sr-only">Confirm Passphrase</label>
                    <input
                      id={passphraseConfirmId}
                      type="password"
                      value={passphraseConfirm}
                      onChange={(e) => setPassphraseConfirm(e.target.value)}
                      placeholder={STRINGS.create.passphraseConfirmPlaceholder}
                      className="w-full px-3.5 py-2.5 rounded-lg bg-slate-900 border border-slate-700 text-sm font-mono text-white placeholder-slate-600 focus:border-cyan-500 outline-none"
                    />
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Submit Button */}
          <button
            type="submit"
            disabled={isSubmitting || !plaintext.trim()}
            className="w-full py-3.5 px-6 rounded-xl bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 disabled:pointer-events-none text-slate-950 font-bold text-sm flex items-center justify-center gap-2 transition-all shadow-lg shadow-cyan-500/25 cursor-pointer active:scale-[0.99]"
          >
            {isSubmitting ? (
              <>
                <RefreshCw className="w-4 h-4 animate-spin text-slate-950" />
                <span>{STRINGS.create.encrypting}</span>
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                <span>{STRINGS.create.submitButton}</span>
              </>
            )}
          </button>
        </form>
      </div>
    </div>
  );
}
