import type { ColumnType, Generated } from "kysely";

type Timestamp = ColumnType<Date, Date | string | undefined, Date | string>;
type NullableTimestamp = ColumnType<Date | null, Date | string | null | undefined, Date | string | null>;
type Json<T = Record<string, unknown>> = ColumnType<T, string | undefined, string>;

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
