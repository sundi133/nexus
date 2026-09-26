/** Placeholder logo: a stable color per app name until catalog apps bring real logos. */
export function AppIcon({ name, size = 36 }: { name: string; size?: number }) {
  let h = 0;
  for (const ch of name) h = (h * 17 + ch.charCodeAt(0)) % 360;
  return (
    <span
      aria-hidden
      className="inline-flex shrink-0 items-center justify-center rounded-lg font-semibold text-white"
      style={{ width: size, height: size, background: `linear-gradient(135deg, hsl(${h} 65% 55%), hsl(${(h + 40) % 360} 65% 45%))`, fontSize: size * 0.42 }}
    >
      {name.trim()[0]?.toUpperCase() ?? "?"}
    </span>
  );
}
