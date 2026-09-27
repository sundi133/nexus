import { DOMParser } from "@xmldom/xmldom";

/**
 * Parses untrusted XML (SAML messages, metadata): size-limited, and refused
 * outright if it has a DOCTYPE, which closes off XXE and entity expansion.
 */
export function parseXml(xml: string, maxBytes = 64 * 1024) {
  if (Buffer.byteLength(xml) > maxBytes) throw new Error("XML too large");
  if (/<!DOCTYPE/i.test(xml)) throw new Error("DOCTYPE is not allowed");
  const errors: string[] = [];
  const doc = new DOMParser({ onError: (level, msg) => void (level !== "warning" && errors.push(msg)) }).parseFromString(xml, "text/xml");
  if (errors.length || !doc.documentElement) throw new Error("Malformed XML");
  return doc;
}
