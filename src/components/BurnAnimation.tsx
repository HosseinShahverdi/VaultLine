import { useEffect, useRef } from "react";

interface BurnAnimationProps {
  onComplete?: () => void;
}

export default function BurnAnimation({ onComplete }: BurnAnimationProps) {
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    // Check for user preference for reduced motion
    const prefersReducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    if (prefersReducedMotion) {
      const timer = setTimeout(() => {
        onComplete?.();
      }, 1000);
      return () => clearTimeout(timer);
    }

    const canvas = canvasRef.current;
    if (!canvas) return;
    const ctx = canvas.getContext("2d");
    if (!ctx) return;

    let animationFrameId: number;
    const width = (canvas.width = canvas.parentElement?.clientWidth || 400);
    const height = (canvas.height = 120);

    // Particle system for the flame and glowing ash
    const particles: Array<{
      x: number;
      y: number;
      vx: number;
      vy: number;
      size: number;
      color: string;
      alpha: number;
      decay: number;
    }> = [];

    const colors = ["#06b6d4", "#22d3ee", "#38bdf8", "#f97316", "#ef4444", "#fbbf24"];

    // Spawn burst particles
    for (let i = 0; i < 90; i++) {
      particles.push({
        x: width / 2 + (Math.random() - 0.5) * 160,
        y: height - 15,
        vx: (Math.random() - 0.5) * 3,
        vy: -(Math.random() * 4 + 1.5),
        size: Math.random() * 4 + 2,
        color: colors[Math.floor(Math.random() * colors.length)],
        alpha: 1,
        decay: Math.random() * 0.02 + 0.015,
      });
    }

    const startTime = performance.now();
    const duration = 2200; // ms

    function render(currentTime: number) {
      const elapsed = currentTime - startTime;
      ctx!.clearRect(0, 0, width, height);

      // Render flame particles
      for (let i = particles.length - 1; i >= 0; i--) {
        const p = particles[i];
        p.x += p.vx;
        p.y += p.vy;
        p.alpha -= p.decay;
        p.size = Math.max(0.5, p.size * 0.98);

        if (p.alpha <= 0) {
          particles.splice(i, 1);
          continue;
        }

        ctx!.save();
        ctx!.globalAlpha = Math.max(0, p.alpha);
        ctx!.fillStyle = p.color;
        ctx!.shadowColor = p.color;
        ctx!.shadowBlur = 10;
        ctx!.beginPath();
        ctx!.arc(p.x, p.y, p.size, 0, Math.PI * 2);
        ctx!.fill();
        ctx!.restore();
      }

      if (elapsed < duration || particles.length > 0) {
        animationFrameId = requestAnimationFrame(render);
      } else {
        onComplete?.();
      }
    }

    animationFrameId = requestAnimationFrame(render);

    return () => {
      cancelAnimationFrame(animationFrameId);
    };
  }, [onComplete]);

  return (
    <div className="relative w-full h-24 overflow-hidden rounded-lg flex items-center justify-center my-2 pointer-events-none">
      <div className="absolute inset-0 bg-gradient-to-t from-cyan-950/20 via-orange-950/20 to-transparent blur-sm" />
      <canvas ref={canvasRef} className="relative z-10 w-full h-full" />
      <div className="absolute bottom-2 flex items-center gap-2 text-xs font-mono text-cyan-400/90 tracking-widest uppercase">
        <span className="w-2 h-2 rounded-full bg-cyan-400 animate-ping inline-block" />
        Ciphertext incinerated on server
      </div>
    </div>
  );
}
