import { SignJWT, importPKCS8 } from "jose";

/**
 * Google's Android Management API, as a Nexus organization's EMM (docs/ANDROID.md). Calls are
 * made as the organization's own Google Cloud service account: a signed JWT is exchanged for an
 * access token, cached until shortly before it expires.
 */

export type ServiceAccount = { type: "service_account"; project_id?: string; client_email: string; private_key: string; private_key_id?: string; token_uri?: string };

export class AmapiError extends Error {
  constructor(
    message: string,
    readonly status = 0,
  ) {
    super(message);
  }
}

const SCOPE = "https://www.googleapis.com/auth/androidmanagement";

/** Checks a service-account key file looks like one (before storing it). */
export function readServiceAccount(json: string, tokenUrl: string): ServiceAccount {
  let sa: Partial<ServiceAccount>;
  try {
    sa = JSON.parse(json);
  } catch {
    throw new AmapiError("That isn't a JSON key file");
  }
  if (sa.type !== "service_account" || !sa.client_email || !sa.private_key?.includes("PRIVATE KEY")) throw new AmapiError("That isn't a Google Cloud service-account key (type, client_email and private_key are needed)");
  // Tokens only ever come from Google's endpoint, whatever the file says.
  if (sa.token_uri && sa.token_uri !== tokenUrl) throw new AmapiError(`Unexpected token_uri in the key file: ${sa.token_uri}`);
  return sa as ServiceAccount;
}

export type AmapiDevice = {
  name: string;
  managementMode?: string;
  ownership?: string;
  state?: string;
  appliedState?: string;
  policyCompliant?: boolean;
  nonComplianceDetails?: { settingName?: string; nonComplianceReason?: string; packageName?: string }[];
  enrollmentTime?: string;
  lastStatusReportTime?: string;
  enrollmentTokenData?: string;
  hardwareInfo?: { brand?: string; model?: string; serialNumber?: string; manufacturer?: string };
  softwareInfo?: { androidVersion?: string; securityPatchLevel?: string };
};

export class Amapi {
  private token: { value: string; exp: number } | null = null;
  constructor(
    private readonly base: string,
    private readonly tokenUrl: string,
    private readonly sa: ServiceAccount,
  ) {}

  private async accessToken() {
    if (this.token && this.token.exp > Date.now() + 60_000) return this.token.value;
    const key = await importPKCS8(this.sa.private_key, "RS256");
    const now = Math.floor(Date.now() / 1000);
    const assertion = await new SignJWT({ scope: SCOPE })
      .setProtectedHeader({ alg: "RS256", typ: "JWT", ...(this.sa.private_key_id ? { kid: this.sa.private_key_id } : {}) })
      .setIssuer(this.sa.client_email)
      .setAudience(this.tokenUrl)
      .setIssuedAt(now)
      .setExpirationTime(now + 3600)
      .sign(key);
    const res = await fetch(this.tokenUrl, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({ grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer", assertion }),
      signal: AbortSignal.timeout(20_000),
    });
    const body = (await res.json().catch(() => ({}))) as { access_token?: string; expires_in?: number; error_description?: string };
    if (!res.ok || !body.access_token) throw new AmapiError(`Google refused the service account: ${body.error_description ?? `HTTP ${res.status}`}`, res.status);
    this.token = { value: body.access_token, exp: Date.now() + (body.expires_in ?? 3600) * 1000 };
    return this.token.value;
  }

  async call<T>(method: string, path: string, opts: { query?: Record<string, string>; body?: unknown } = {}): Promise<T> {
    const url = new URL(`${this.base}/${path}`);
    for (const [k, v] of Object.entries(opts.query ?? {})) url.searchParams.set(k, v);
    const res = await fetch(url, {
      method,
      headers: { authorization: `Bearer ${await this.accessToken()}`, ...(opts.body !== undefined ? { "content-type": "application/json" } : {}) },
      ...(opts.body !== undefined ? { body: JSON.stringify(opts.body) } : {}),
      signal: AbortSignal.timeout(30_000),
    });
    const text = await res.text();
    if (!res.ok) {
      let msg = text.slice(0, 300);
      try {
        msg = (JSON.parse(text) as { error?: { message?: string } }).error?.message ?? msg;
      } catch {
        /* keep the raw text */
      }
      throw new AmapiError(`Android Management API: ${msg} (HTTP ${res.status})`, res.status);
    }
    return (text ? JSON.parse(text) : {}) as T;
  }

  /** Step 1 of connecting: a Google page where an admin creates (or picks) the Android enterprise. */
  signupUrl(projectId: string, callbackUrl: string) {
    return this.call<{ name: string; url: string }>("POST", "signupUrls", { query: { projectId, callbackUrl } });
  }
  createEnterprise(projectId: string, signupUrlName: string, enterpriseToken: string, displayName: string) {
    return this.call<{ name: string; enterpriseDisplayName?: string }>("POST", "enterprises", { query: { projectId, signupUrlName, enterpriseToken }, body: { enterpriseDisplayName: displayName } });
  }
  patchPolicy(policyName: string, policy: Record<string, unknown>) {
    return this.call<{ name: string; version?: string }>("PATCH", policyName, { body: policy });
  }
  enrollmentToken(enterprise: string, body: Record<string, unknown>) {
    return this.call<{ name: string; value: string; qrCode: string; expirationTimestamp: string }>("POST", `${enterprise}/enrollmentTokens`, { body });
  }
  async devices(enterprise: string) {
    const out: AmapiDevice[] = [];
    let pageToken: string | undefined;
    for (let i = 0; i < 200; i++) {
      const r = await this.call<{ devices?: AmapiDevice[]; nextPageToken?: string }>("GET", `${enterprise}/devices`, { query: { pageSize: "100", ...(pageToken ? { pageToken } : {}) } });
      out.push(...(r.devices ?? []));
      pageToken = r.nextPageToken;
      if (!pageToken) break;
    }
    return out;
  }
  issueCommand(deviceName: string, command: Record<string, unknown>) {
    return this.call<{ name: string }>("POST", `${deviceName}:issueCommand`, { body: command });
  }
  deleteDevice(deviceName: string, wipeReason: string) {
    return this.call<Record<string, never>>("DELETE", deviceName, { query: { wipeReasonMessage: wipeReason.slice(0, 200) } });
  }
}

/** The Google policy built from Nexus's settings. */
export type PolicySettings = {
  password_min_length: number;
  lock_after_minutes: number;
  block_unknown_sources: boolean;
  disable_camera: boolean;
  apps: { package: string; install: "force" | "available" | "blocked" }[];
};
export const DEFAULT_POLICY: PolicySettings = { password_min_length: 6, lock_after_minutes: 5, block_unknown_sources: true, disable_camera: false, apps: [] };

export function buildPolicy(s: PolicySettings) {
  const install = { force: "FORCE_INSTALLED", available: "AVAILABLE", blocked: "BLOCKED" } as const;
  return {
    passwordPolicies: s.password_min_length
      ? [
          { passwordScope: "SCOPE_DEVICE", passwordQuality: "NUMERIC_COMPLEX", passwordMinimumLength: s.password_min_length },
          { passwordScope: "SCOPE_PROFILE", passwordQuality: "NUMERIC_COMPLEX", passwordMinimumLength: s.password_min_length },
        ]
      : [],
    maximumTimeToLock: String(s.lock_after_minutes * 60_000),
    advancedSecurityOverrides: { untrustedAppsPolicy: s.block_unknown_sources ? "DISALLOW_INSTALL" : "ALLOW_INSTALL_DEVICE_WIDE" },
    cameraAccess: s.disable_camera ? "CAMERA_ACCESS_DISABLED" : "CAMERA_ACCESS_USER_CHOICE",
    applications: s.apps.map((a) => ({ packageName: a.package, installType: install[a.install] })),
    statusReportingSettings: { softwareInfoEnabled: true, hardwareStatusEnabled: true, deviceSettingsEnabled: true },
  };
}
