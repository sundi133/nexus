import { z } from "@hono/zod-openapi";
import { createHash, createPublicKey, verify, type KeyObject } from "node:crypto";
import { createReadStream } from "node:fs";
import { readdir, readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import type { Config } from "../config.js";

/**
 * Signed agent releases (DEV-07, ADR-017). The release pipeline signs each
 * binary with an Ed25519 release key; agents verify with keys compiled into
 * them, so this server can only *offer* updates. We verify too (defense in
 * depth, and so admins never see a release agents would reject).
 */

const Artifact = z.object({
  os: z.enum(["darwin", "windows", "linux"]),
  arch: z.enum(["amd64", "arm64"]),
  file: z.string().regex(/^nexus-agent-[a-z0-9]+-[a-z0-9]+(\.exe)?$/),
  sha256: z.string().regex(/^[0-9a-f]{64}$/),
  size: z.number().int().positive(),
  key_id: z.string(),
  signature: z.string(),
});
const Manifest = z.object({
  version: z.string().regex(/^\d+\.\d+\.\d+(-[0-9A-Za-z.-]+)?$/),
  published_at: z.string(),
  notes: z.string().default(""),
  artifacts: z.array(Artifact),
});
export type ReleaseArtifact = z.infer<typeof Artifact>;
export type AgentRelease = z.infer<typeof Manifest>;

/** Same order as the agent's release.Compare: 1.2.3-rc.1 < 1.2.3; unparseable sorts first. */
export function compareVersions(a: string, b: string): number {
  const parse = (v: string) => {
    const m = /^v?(\d+)\.(\d+)\.(\d+)(?:-(.+))?$/.exec(v);
    return m ? { n: [Number(m[1]), Number(m[2]), Number(m[3])], pre: m[4] ?? "" } : null;
  };
  const pa = parse(a);
  const pb = parse(b);
  if (!pa || !pb) return !pa && !pb ? Math.sign(a.localeCompare(b)) : !pa ? -1 : 1;
  for (let i = 0; i < 3; i++) if (pa.n[i] !== pb.n[i]) return pa.n[i]! < pb.n[i]! ? -1 : 1;
  if (pa.pre === pb.pre) return 0;
  if (!pa.pre) return 1;
  if (!pb.pre) return -1;
  return pa.pre < pb.pre ? -1 : 1;
}

export const statement = (version: string, os: string, arch: string, sha256: string, size: number) =>
  Buffer.from(`nexus-agent-release-v1\n${version}\n${os}/${arch}\n${sha256.toLowerCase()}\n${size}`);

const SPKI_ED25519_PREFIX = Buffer.from("302a300506032b6570032100", "hex");

function parseKeys(s: string): Map<string, KeyObject> {
  const keys = new Map<string, KeyObject>();
  for (const part of s.split(",").map((p) => p.trim()).filter(Boolean)) {
    const raw = Buffer.from(part, "base64");
    if (raw.length !== 32) throw new Error(`Invalid agent release key: ${part}`);
    const id = createHash("sha256").update(raw).digest("hex").slice(0, 16);
    keys.set(id, createPublicKey({ key: Buffer.concat([SPKI_ED25519_PREFIX, raw]), format: "der", type: "spki" }));
  }
  return keys;
}

/** Platform names as devices report them → Go's GOOS. */
export const GOOS: Record<string, "darwin" | "windows" | "linux"> = { macos: "darwin", windows: "windows", linux: "linux" };

const RESCAN_MS = 30_000;

export class ReleaseStore {
  private keys: Map<string, KeyObject>;
  private cache: { at: number; releases: AgentRelease[] } | null = null;
  private hashes = new Map<string, { mtimeMs: number; size: number; sha256: string }>();

  constructor(
    private dir: string,
    keys: string,
  ) {
    this.keys = parseKeys(keys);
  }

  /** Verified releases, newest first. */
  async list(): Promise<AgentRelease[]> {
    if (this.cache && Date.now() - this.cache.at < RESCAN_MS) return this.cache.releases;
    const releases: AgentRelease[] = [];
    let entries: string[] = [];
    try {
      entries = await readdir(this.dir);
    } catch {
      entries = []; // no releases published yet
    }
    for (const name of entries) {
      const r = await this.load(name).catch((err: Error) => {
        console.warn(`[releases] ignoring ${name}: ${err.message}`);
        return null;
      });
      if (r) releases.push(r);
    }
    releases.sort((a, b) => compareVersions(b.version, a.version));
    this.cache = { at: Date.now(), releases };
    return releases;
  }

  async get(version: string) {
    return (await this.list()).find((r) => r.version === version) ?? null;
  }

  async latest() {
    return (await this.list())[0] ?? null;
  }

  /** Forget the scan (tests, or right after publishing). */
  refresh() {
    this.cache = null;
  }

  filePath(version: string, file: string) {
    return join(this.dir, version, file);
  }

  open(version: string, file: string) {
    return createReadStream(this.filePath(version, file));
  }

  private async load(name: string): Promise<AgentRelease | null> {
    const manifestPath = join(this.dir, name, "release.json");
    const raw = await readFile(manifestPath, "utf8").catch(() => null);
    if (raw === null) return null;
    const m = Manifest.parse(JSON.parse(raw));
    if (m.version !== name) throw new Error(`manifest version ${m.version} doesn't match its directory`);
    const artifacts: ReleaseArtifact[] = [];
    for (const a of m.artifacts) {
      const problem = await this.check(m.version, a);
      if (problem) console.warn(`[releases] ${m.version} ${a.file}: ${problem}`);
      else artifacts.push(a);
    }
    if (artifacts.length === 0) throw new Error("no valid artifacts");
    return { ...m, artifacts };
  }

  private async check(version: string, a: ReleaseArtifact): Promise<string | null> {
    const key = this.keys.get(a.key_id);
    if (!key) return `signed by unknown key ${a.key_id}`;
    if (!verify(null, statement(version, a.os, a.arch, a.sha256, a.size), key, Buffer.from(a.signature, "base64"))) return "bad signature";
    const path = this.filePath(version, a.file);
    const st = await stat(path).catch(() => null);
    if (!st) return "file missing";
    if (st.size !== a.size) return `file is ${st.size} bytes, signed as ${a.size}`;
    let h = this.hashes.get(path);
    if (!h || h.mtimeMs !== st.mtimeMs || h.size !== st.size) {
      const sha256 = await new Promise<string>((resolve, reject) => {
        const hash = createHash("sha256");
        createReadStream(path).on("data", (d) => hash.update(d)).on("end", () => resolve(hash.digest("hex"))).on("error", reject);
      });
      h = { mtimeMs: st.mtimeMs, size: st.size, sha256 };
      this.hashes.set(path, h);
    }
    return h.sha256 === a.sha256 ? null : "file doesn't match its signed checksum";
  }
}

const stores = new Map<string, ReleaseStore>();
export function releaseStore(cfg: Pick<Config, "agentReleasesDir" | "agentReleaseKeys">) {
  const k = `${cfg.agentReleasesDir}\n${cfg.agentReleaseKeys}`;
  let s = stores.get(k);
  if (!s) stores.set(k, (s = new ReleaseStore(cfg.agentReleasesDir, cfg.agentReleaseKeys)));
  return s;
}
