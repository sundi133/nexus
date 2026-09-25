import { createHash, createHmac } from "node:crypto";

/**
 * AWS Signature Version 4, for S3-compatible object storage (Amazon S3, Google
 * Cloud Storage's interoperability API with HMAC keys, MinIO). Small enough to
 * own instead of pulling in an SDK; checked against AWS's published example.
 */

export type SigV4Credentials = { accessKeyId: string; secretAccessKey: string; region: string; service?: string };

const sha256Hex = (data: string | Buffer) => createHash("sha256").update(data).digest("hex");
const hmac = (key: string | Buffer, data: string) => createHmac("sha256", key).update(data).digest();
/** RFC 3986 encoding, as SigV4 requires (encodeURIComponent leaves !'()* alone). */
const encode = (s: string) => encodeURIComponent(s).replace(/[!'()*]/g, (ch) => `%${ch.charCodeAt(0).toString(16).toUpperCase()}`);

/** Returns the headers to send: the given ones plus host, x-amz-date, x-amz-content-sha256 and authorization. */
export function signV4(
  req: { method: string; url: URL; headers?: Record<string, string>; body?: string | Buffer },
  creds: SigV4Credentials,
  now = new Date(),
): Record<string, string> {
  const amzDate = now.toISOString().replace(/[-:]|\.\d{3}/g, "");
  const day = amzDate.slice(0, 8);
  const service = creds.service ?? "s3";
  const payloadHash = sha256Hex(req.body ?? "");
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(req.headers ?? {})) headers[k.toLowerCase()] = v;
  Object.assign(headers, { host: req.url.host, "x-amz-date": amzDate, "x-amz-content-sha256": payloadHash });

  const names = Object.keys(headers).sort();
  const canonicalHeaders = names.map((n) => `${n}:${headers[n]!.trim().replace(/\s+/g, " ")}\n`).join("");
  const signedHeaders = names.join(";");
  const canonicalUri = req.url.pathname.split("/").map((s) => encode(decodeURIComponent(s))).join("/") || "/";
  const canonicalQuery = [...req.url.searchParams]
    .map(([k, v]) => [encode(k), encode(v)] as const)
    .sort(([a, x], [b, y]) => (a === b ? (x < y ? -1 : 1) : a < b ? -1 : 1))
    .map(([k, v]) => `${k}=${v}`)
    .join("&");
  const canonicalRequest = [req.method, canonicalUri, canonicalQuery, canonicalHeaders, signedHeaders, payloadHash].join("\n");

  const scope = `${day}/${creds.region}/${service}/aws4_request`;
  const stringToSign = ["AWS4-HMAC-SHA256", amzDate, scope, sha256Hex(canonicalRequest)].join("\n");
  const signingKey = hmac(hmac(hmac(hmac(`AWS4${creds.secretAccessKey}`, day), creds.region), service), "aws4_request");
  const signature = createHmac("sha256", signingKey).update(stringToSign).digest("hex");
  return { ...headers, authorization: `AWS4-HMAC-SHA256 Credential=${creds.accessKeyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}
