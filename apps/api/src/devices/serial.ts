/**
 * Serial numbers tie a Nexus device to its MDM record, and so to the MDM's
 * compliance verdict and to remote lock and wipe. Many PCs, boards and VMs
 * report a placeholder instead of a real serial ("To Be Filled By O.E.M.",
 * "Default string", "0"), shared by every machine of that model, so those must
 * never match anything.
 */

const PLACEHOLDERS = new Set(
  [
    "to be filled by o.e.m.",
    "system serial number",
    "chassis serial number",
    "base board serial number",
    "default string",
    "not specified",
    "not available",
    "not applicable",
    "none",
    "null",
    "undefined",
    "unknown",
    "invalid",
    "empty",
    "serial",
    "serial number",
    "oem",
    "o.e.m.",
    "n/a",
    "123456789",
    "1234567890",
    "0123456789",
    "12345678",
    "abcdefgh",
  ].map((s) => s.replace(/[^a-z0-9]/g, "")),
);

/** The serial, lowercased and trimmed, or null when it can't identify one machine. */
export function usableSerial(raw: string | null | undefined): string | null {
  const s = (raw ?? "").trim().toLowerCase();
  const alnum = s.replace(/[^a-z0-9]/g, "");
  if (alnum.length < 4) return null; // "", "0", "n/a", "-"
  if (/^(.)\1*$/.test(alnum)) return null; // 00000000, XXXXXXXX, Hyper-V's 0000-0000-…
  if (PLACEHOLDERS.has(alnum)) return null;
  return s;
}
