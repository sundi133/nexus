import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export const cn = (...inputs: ClassValue[]) => twMerge(clsx(inputs));

const rtf = new Intl.RelativeTimeFormat("en", { numeric: "auto" });
const UNITS: [Intl.RelativeTimeFormatUnit, number][] = [
  ["year", 31536000],
  ["month", 2592000],
  ["day", 86400],
  ["hour", 3600],
  ["minute", 60],
];

export function timeAgo(iso: string | null | undefined) {
  if (!iso) return "Never";
  const secs = (new Date(iso).getTime() - Date.now()) / 1000;
  for (const [unit, size] of UNITS) if (Math.abs(secs) >= size) return rtf.format(Math.round(secs / size), unit);
  return "just now";
}

export const formatDateTime = (iso: string) =>
  new Date(iso).toLocaleString(undefined, { dateStyle: "medium", timeStyle: "short" });

export const initials = (name: string) =>
  name
    .split(/[\s@.]+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((s) => s[0]!.toUpperCase())
    .join("");

const IRREGULAR: Record<string, string> = { person: "people" };
export const pluralize = (n: number, word: string) => {
  const last = word.split(" ").pop()!;
  const plural = IRREGULAR[last] ? word.slice(0, -last.length) + IRREGULAR[last] : `${word}s`;
  return `${n.toLocaleString()} ${n === 1 ? word : plural}`;
};

export const ROLE_LABELS: Record<string, string> = {
  owner: "Owner",
  admin: "Admin",
  helpdesk: "Help desk",
  security_analyst: "Security analyst",
  readonly: "Read-only",
};
