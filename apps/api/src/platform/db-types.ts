import type { ColumnType, Generated } from "kysely";

type Timestamp = ColumnType<Date, Date | string | undefined, Date | string>;
type NullableTimestamp = ColumnType<Date | null, Date | string | null | undefined, Date | string | null>;
type Json<T = Record<string, unknown>> = ColumnType<T, string | undefined, string>;

export type DevicePlatform = "macos" | "windows" | "linux";
export type Compliance = "compliant" | "non_compliant" | "unknown";
export type CheckStatus = "pass" | "fail" | "unknown" | "not_applicable";

export type SessionState = "pending_mfa" | "enroll_mfa" | "active";

export type UserStatus = "staged" | "active" | "suspended" | "deprovisioned";

export interface Database {
  organizations: {
    id: string;
    name: string;
    slug: string;
    settings: Json;
    created_at: Generated<Date>;
    updated_at: Generated<Date>;
  };
  users: {
    id: string;
    org_id: string;
    email: string;
    given_name: Generated<string>;
    family_name: Generated<string>;
    title: Generated<string>;
    department: Generated<string>;
    status: Generated<UserStatus>;
    password_hash: string | null;
    attributes: Json;
    last_login_at: NullableTimestamp;
    created_at: Generated<Date>;
    updated_at: Timestamp;
  };
  user_roles: {
    org_id: string;
    user_id: string;
    role: string;
    created_at: Generated<Date>;
  };
  groups: {
    id: string;
    org_id: string;
    name: string;
    description: Generated<string>;
    created_at: Generated<Date>;
    updated_at: Timestamp;
  };
  group_members: {
    org_id: string;
    group_id: string;
    user_id: string;
    created_at: Generated<Date>;
  };
  sessions: {
    id: string;
    org_id: string;
    user_id: string;
    token_hash: Buffer;
    state: SessionState;
    client: string;
    ip: string;
    user_agent: string;
    mfa_at: NullableTimestamp;
    created_at: Generated<Date>;
    last_seen_at: Timestamp;
    expires_at: Timestamp;
    revoked_at: NullableTimestamp;
    factor_id: ColumnType<string | null, string | null | undefined, string | null>;
    device_id: ColumnType<string | null, string | null | undefined, string | null>;
    device_verified_at: NullableTimestamp;
  };
  auth_factors: {
    id: string;
    org_id: string;
    user_id: string;
    type: "totp" | "push" | "webauthn";
    name: string;
    secret_sealed: Buffer | null;
    public_key: Buffer | null;
    verified_at: NullableTimestamp;
    last_used_at: NullableTimestamp;
    created_at: Generated<Date>;
    last_totp_step: number | null;
    credential_id: string | null;
    sign_count: Generated<number>;
    transports: Generated<string[]>;
  };
  auth_challenges: {
    id: string;
    org_id: string;
    user_id: string;
    purpose: "webauthn_register" | "webauthn_authenticate";
    challenge: string;
    created_at: Generated<Date>;
    expires_at: Timestamp;
  };
  invitations: {
    id: string;
    org_id: string;
    user_id: string;
    token_hash: Buffer;
    invited_by: string | null;
    created_at: Generated<Date>;
    expires_at: Timestamp;
    accepted_at: NullableTimestamp;
    revoked_at: NullableTimestamp;
  };
  mfa_challenges: {
    id: string;
    org_id: string;
    user_id: string;
    session_id: string;
    number: number;
    choices: number[];
    status: Generated<"pending" | "approved" | "denied" | "expired">;
    context: Json;
    created_at: Generated<Date>;
    expires_at: Timestamp;
    decided_at: NullableTimestamp;
    factor_id: ColumnType<string | null, string | null | undefined, string | null>;
    decision_reason: ColumnType<string | null, string | null | undefined, string | null>;
  };
  applications: {
    id: string;
    org_id: string;
    name: string;
    protocol: "oidc" | "saml";
    catalog_key: string | null;
    status: Generated<"active" | "disabled">;
    launch_url: Generated<string>;
    client_id: string | null;
    client_secret_hash: Buffer | null;
    redirect_uris: Generated<string[]>;
    config: Json;
    created_at: Generated<Date>;
    updated_at: Timestamp;
  };
  app_assignments: {
    org_id: string;
    app_id: string;
    principal_type: "user" | "group";
    principal_id: string;
    created_at: Generated<Date>;
  };
  signing_keys: {
    id: string;
    org_id: string;
    kid: string;
    alg: Generated<string>;
    public_jwk: Json;
    private_key_sealed: Buffer;
    status: Generated<"next" | "active" | "retired">;
    created_at: Generated<Date>;
    retired_at: NullableTimestamp;
    purpose: Generated<"oidc" | "saml">;
    cert_pem: string | null;
    not_after: NullableTimestamp;
  };
  oidc_codes: {
    id: string;
    org_id: string;
    code_hash: Buffer;
    app_id: string;
    user_id: string;
    session_id: string | null;
    redirect_uri: string;
    scope: string;
    nonce: string | null;
    code_challenge: string | null;
    auth_time: Timestamp;
    amr: string[];
    created_at: Generated<Date>;
    expires_at: Timestamp;
    used_at: NullableTimestamp;
  };
  device_enrollment_tokens: {
    id: string;
    org_id: string;
    name: string;
    token_hash: Buffer;
    assign_user_id: string | null;
    created_by: string | null;
    max_uses: number | null;
    uses: Generated<number>;
    expires_at: Timestamp;
    revoked_at: NullableTimestamp;
    created_at: Generated<Date>;
  };
  devices: {
    id: string;
    org_id: string;
    hostname: string;
    platform: DevicePlatform;
    os_name: Generated<string>;
    os_version: Generated<string>;
    os_build: Generated<string>;
    arch: Generated<string>;
    model: Generated<string>;
    serial: Generated<string>;
    agent_version: Generated<string>;
    public_jwk: Json;
    key_thumbprint: string;
    primary_user_id: string | null;
    enrollment_token_id: string | null;
    status: Generated<"active" | "removed">;
    compliance: Generated<Compliance>;
    compliance_changed_at: NullableTimestamp;
    inventory: Json;
    posture: Json;
    enrolled_at: Generated<Date>;
    last_seen_at: NullableTimestamp;
    last_ip: Generated<string>;
    created_at: Generated<Date>;
    updated_at: Timestamp;
  };
  device_checks: {
    org_id: string;
    device_id: string;
    check_key: string;
    status: CheckStatus;
    detail: string;
    updated_at: Timestamp;
  };
  device_policies: {
    org_id: string;
    check_key: string;
    enabled: boolean;
    params: Json;
    updated_at: Timestamp;
  };
  agent_nonces: {
    jti: string;
    org_id: string;
    device_id: string;
    expires_at: Timestamp;
  };
  access_policies: {
    id: string;
    org_id: string;
    name: string;
    enabled: Generated<boolean>;
    mode: Generated<"report_only" | "enforce">;
    requirement: "require_mfa" | "require_managed_device" | "require_compliant_device" | "block";
    conditions: Json;
    created_at: Generated<Date>;
    updated_at: Timestamp;
  };
  directory_connections: {
    id: string;
    org_id: string;
    provider: "google" | "entra";
    name: string;
    config: Json;
    secret: Buffer;
    enabled: Generated<boolean>;
    sync_groups: Generated<boolean>;
    group_filter: Generated<string[]>;
    deprovision: Generated<"suspend" | "none">;
    invite_new_users: Generated<boolean>;
    interval_minutes: Generated<number>;
    last_sync_at: NullableTimestamp;
    last_status: Generated<"never" | "ok" | "error" | "needs_approval">;
    last_result: Json;
    last_error: Generated<string>;
    created_by: string | null;
    created_at: Generated<Date>;
    updated_at: Generated<Date>;
  };
  directory_links: {
    org_id: string;
    connection_id: string;
    kind: "user" | "group";
    external_id: string;
    local_id: string;
    suspended_by_sync: Generated<boolean>;
  };
  jobs: {
    id: string;
    org_id: string;
    kind: string;
    payload: Json;
    status: Generated<"queued" | "running" | "done" | "dead">;
    run_at: Timestamp;
    attempts: Generated<number>;
    max_attempts: Generated<number>;
    locked_until: NullableTimestamp;
    last_error: Generated<string>;
    dedupe_key: string | null;
    created_at: Generated<Date>;
    finished_at: NullableTimestamp;
  };
  agent_update_settings: {
    org_id: string;
    auto_rollout: Generated<boolean>;
    advance_after_hours: Generated<number>;
    updated_at: Generated<Date>;
  };
  agent_rollouts: {
    id: string;
    org_id: string;
    version: string;
    stage: Generated<"canary" | "early" | "all">;
    status: Generated<"active" | "paused" | "halted" | "completed" | "cancelled">;
    canary_device_ids: Generated<string[]>;
    stage_started_at: Generated<Date>;
    failures_since: Generated<Date>;
    halted_reason: Generated<string>;
    created_by: string | null;
    created_at: Generated<Date>;
    updated_at: Generated<Date>;
  };
  device_updates: {
    org_id: string;
    device_id: string;
    version: string;
    state: "offered" | "installed" | "failed" | "rolled_back";
    error: Generated<string>;
    from_version: Generated<string>;
    updated_at: Generated<Date>;
  };
  device_trust_challenges: {
    id: string;
    org_id: string;
    session_id: string;
    nonce: string;
    created_at: Generated<Date>;
    expires_at: Timestamp;
    used_at: NullableTimestamp;
  };
  device_pairings: {
    id: string;
    org_id: string;
    user_id: string;
    session_id: string | null;
    code_hash: Buffer;
    created_at: Generated<Date>;
    expires_at: Timestamp;
    used_at: NullableTimestamp;
  };
  push_registrations: {
    id: string;
    org_id: string;
    user_id: string;
    factor_id: string | null;
    platform: "ios" | "android" | "web";
    token: string;
    created_at: Generated<Date>;
    last_seen_at: Timestamp;
  };
  audit_events: {
    id: string;
    org_id: string;
    ts: Generated<Date>;
    type: string;
    outcome: "success" | "failure" | "denied";
    actor_type: string;
    actor_id: string | null;
    actor_display: string;
    target_type: string;
    target_id: string | null;
    target_display: string;
    session_id: string | null;
    ip: string;
    user_agent: string;
    details: Json;
  };
  notifications: {
    id: string;
    org_id: string;
    recipient_user_id: string;
    category: string;
    severity: "info" | "warning" | "critical";
    title: string;
    body: string;
    entity_type: string;
    entity_id: string | null;
    link: string;
    actions: Json<NotificationAction[]>;
    created_at: Generated<Date>;
    read_at: NullableTimestamp;
    archived_at: NullableTimestamp;
    acted_at: NullableTimestamp;
  };
}

export type NotificationAction = { id: string; label: string; style?: "primary" | "danger" };
