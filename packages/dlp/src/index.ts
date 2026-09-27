/**
 * Sensitive-data detectors for text people paste or send into AI apps. They run in the browser;
 * what's found is never sent anywhere. Only the detector, a count and a masked hint are reported.
 * Each detector trades a little recall for few false positives: people stop reading warnings
 * that cry wolf.
 */

export type DetectorId = "secret" | "private_key" | "credit_card" | "us_ssn" | "iban" | "email_list";
export type Custom = { id: string; name: string; pattern: string };
export type Finding = { detector: string; name: string; count: number; hint: string };

export const DETECTORS: Record<DetectorId, string> = {
  secret: "API keys, tokens and passwords",
  private_key: "Private keys",
  credit_card: "Payment card numbers",
  us_ssn: "US Social Security numbers",
  iban: "Bank account numbers (IBAN)",
  email_list: "Lists of email addresses (10 or more)",
};

// Credentials with a recognizable shape (the same families the agent redacts from command lines).
const SECRET_PATTERNS: [string, RegExp][] = [
  ["AWS access key", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["GitHub token", /\bgh[pousr]_[A-Za-z0-9]{36,}\b/g],
  ["GitHub token", /\bgithub_pat_[A-Za-z0-9_]{60,}\b/g],
  ["Slack token", /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
  ["Anthropic key", /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g],
  ["OpenAI key", /\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}\b/g],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ["Stripe key", /\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b/g],
  ["JWT", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/g],
  ["Connection string with a password", /\b[a-z][a-z0-9+.-]*:\/\/[^\s:/@]+:[^\s@/]{3,}@[^\s/]+/gi],
  ["Password", /\b(?:password|passwd|pwd|secret|api[_-]?key|access[_-]?token|client[_-]?secret)\s*[:=]\s*["']?[^\s"']{8,}/gi],
];

const PRIVATE_KEY = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----/g;
const CARD = /\b(?:\d[ -]?){12,18}\d\b/g;
const SSN = /\b(?!000|666|9\d\d)\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b/g;
const IBAN = /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){2,7}(?:[ ]?[A-Z0-9]{1,4})?\b/g;
const EMAIL = /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g;

/** Luhn checksum, so a random 16-digit number isn't taken for a card. */
export function luhn(digits: string): boolean {
  let sum = 0;
  for (let i = 0; i < digits.length; i++) {
    let d = digits.charCodeAt(digits.length - 1 - i) - 48;
    if (i % 2 === 1) {
      d *= 2;
      if (d > 9) d -= 9;
    }
    sum += d;
  }
  return sum % 10 === 0;
}

/** Card networks' number ranges (Visa, Mastercard, Amex, Discover, JCB, Diners, UnionPay). */
const CARD_PREFIX = /^(?:4\d{12}(?:\d{3}){0,2}|5[1-5]\d{14}|2(?:2[2-9][1-9]|[3-6]\d\d|7[01]\d|720)\d{12}|3[47]\d{13}|6(?:011|5\d\d)\d{12,15}|35(?:2[89]|[3-8]\d)\d{12,15}|3(?:0[0-5]|[68]\d)\d{11,16}|62\d{14,17})$/;

/** IBAN mod-97 check (ISO 13616). */
export function ibanValid(raw: string): boolean {
  const s = raw.replace(/\s+/g, "").toUpperCase();
  if (s.length < 15 || s.length > 34) return false;
  const moved = s.slice(4) + s.slice(0, 4);
  let rem = 0;
  for (const ch of moved) {
    const v = /\d/.test(ch) ? ch : String(ch.charCodeAt(0) - 55);
    for (const c of v) rem = (rem * 10 + (c.charCodeAt(0) - 48)) % 97;
  }
  return rem === 1;
}

/**
 * `password = "Tr0ub4dor&3"` is a secret; `password = input.value;` or `password=getPassword()` is
 * code people ask AI about all day. Only quoted values, or values that don't read as an
 * identifier, property path or call, count.
 */
function literalValue(match: string): boolean {
  const v = match.replace(/^[^:=]*[:=]\s*/, "");
  if (/^["']/.test(v)) return true;
  return !/^[A-Za-z_$][\w$]*(?:\.[\w$]+)*(?:\(.*)?[;,)]*$/.test(v) && !v.includes("(") && !v.startsWith("$") && !v.startsWith("{");
}

/** Shows the kind of thing found, never the thing: "AKIA…7Q" or "•••• 4242". */
function mask(s: string, keepEnd = 2) {
  const t = s.trim();
  if (t.length <= 8) return "••••";
  return `${t.slice(0, 4)}…${t.slice(-keepEnd)}`;
}

const MAX_SCAN = 200_000; // characters: a huge paste is scanned in its first 200 KB

/** Scans text with the enabled detectors, plus the organization's own patterns. */
export function scan(text: string, enabled: readonly string[], custom: readonly Custom[] = []): Finding[] {
  const t = text.length > MAX_SCAN ? text.slice(0, MAX_SCAN) : text;
  const on = new Set(enabled);
  const out: Finding[] = [];
  const add = (detector: string, name: string, matches: string[], hint: (m: string) => string) => {
    if (matches.length) out.push({ detector, name, count: matches.length, hint: hint(matches[0]!) });
  };
  if (on.has("secret")) {
    for (const [name, re] of SECRET_PATTERNS) {
      let m: string[] = t.match(re) ?? [];
      if (name === "Password") m = m.filter(literalValue);
      if (m.length) {
        add("secret", name, m, (x) => mask(x));
        break; // one secret finding is enough to act on
      }
    }
  }
  if (on.has("private_key")) add("private_key", "Private key", t.match(PRIVATE_KEY) ?? [], () => "-----BEGIN … PRIVATE KEY-----");
  if (on.has("credit_card")) {
    const cards = (t.match(CARD) ?? []).filter((m) => {
      const d = m.replace(/[ -]/g, "");
      return CARD_PREFIX.test(d) && luhn(d);
    });
    add("credit_card", "Payment card number", cards, (m) => `•••• ${m.replace(/[ -]/g, "").slice(-4)}`);
  }
  if (on.has("us_ssn")) add("us_ssn", "US Social Security number", t.match(SSN) ?? [], (m) => `•••-••-${m.slice(-4)}`);
  if (on.has("iban")) add("iban", "IBAN", (t.match(IBAN) ?? []).filter(ibanValid), (m) => `${m.replace(/\s+/g, "").slice(0, 4)}…${m.replace(/\s+/g, "").slice(-2)}`);
  if (on.has("email_list")) {
    const emails = new Set((t.match(EMAIL) ?? []).map((e) => e.toLowerCase()));
    if (emails.size >= 10) out.push({ detector: "email_list", name: "List of email addresses", count: emails.size, hint: `${emails.size} addresses` });
  }
  for (const c of custom) {
    let re: RegExp;
    try {
      re = new RegExp(c.pattern, "gi");
    } catch {
      continue; // the server validates patterns; an invalid one never blocks anything
    }
    add(`custom:${c.id}`, c.name, t.match(re) ?? [], (m) => mask(m));
  }
  return out;
}

export type Redaction = { text: string; findings: Finding[] };

const PRIVATE_KEY_BLOCK = /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED |PGP )?PRIVATE KEY(?: BLOCK)?-----[\s\S]*?(?:-----END [A-Z ]*PRIVATE KEY(?: BLOCK)?-----|$)/g;

/**
 * Replaces what the enabled detectors find with "[redacted: <kind>]", with the same checks as
 * scan() (Luhn, IBAN checksum, code-shaped passwords left alone). For data on its way to an AI:
 * tool results, for example.
 */
export function redact(text: string, enabled: readonly string[], custom: readonly Custom[] = []): Redaction {
  const on = new Set(enabled);
  const findings: Finding[] = [];
  let out = text;
  const sub = (detector: string, name: string, re: RegExp, valid?: (m: string) => boolean, hint: (m: string) => string = (m) => mask(m)) => {
    let n = 0;
    let first = "";
    out = out.replace(re, (m) => {
      if (valid && !valid(m)) return m;
      if (!n) first = m;
      n++;
      return `[redacted: ${name}]`;
    });
    if (n) findings.push({ detector, name, count: n, hint: hint(first) });
  };
  if (on.has("private_key")) sub("private_key", "Private key", PRIVATE_KEY_BLOCK, undefined, () => "-----BEGIN … PRIVATE KEY-----");
  if (on.has("secret")) for (const [name, re] of SECRET_PATTERNS) sub("secret", name, re, name === "Password" ? literalValue : undefined);
  if (on.has("credit_card")) {
    sub("credit_card", "Payment card number", CARD, (m) => {
      const d = m.replace(/[ -]/g, "");
      return CARD_PREFIX.test(d) && luhn(d);
    }, (m) => `•••• ${m.replace(/[ -]/g, "").slice(-4)}`);
  }
  if (on.has("us_ssn")) sub("us_ssn", "US Social Security number", SSN, undefined, (m) => `•••-••-${m.slice(-4)}`);
  if (on.has("iban")) sub("iban", "IBAN", IBAN, ibanValid);
  if (on.has("email_list") && new Set((out.match(EMAIL) ?? []).map((e) => e.toLowerCase())).size >= 10) sub("email_list", "Email address", EMAIL, undefined, () => "list of addresses");
  for (const c of custom) {
    let re: RegExp;
    try {
      re = new RegExp(c.pattern, "gi");
    } catch {
      continue;
    }
    sub(`custom:${c.id}`, c.name, re);
  }
  return { text: out, findings };
}
