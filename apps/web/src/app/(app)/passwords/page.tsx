"use client";

import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { Copy, Eye, EyeOff, KeyRound, Lock, Pencil, Plus, RefreshCw, Share2, Trash2, UserMinus } from "lucide-react";
import { useCallback, useEffect, useMemo, useState } from "react";
import { toast } from "sonner";
import { Button } from "@/components/ui/button";
import { Field, Input, Select } from "@/components/ui/input";
import { Badge, Card, CardHeader, EmptyState, ErrorBanner, PageHeader, Skeleton } from "@/components/ui/misc";
import { Dialog, DialogContent } from "@/components/ui/overlay";
import { api, unwrap } from "@/lib/api";
import { useMe } from "@/lib/queries";
import * as vc from "@/lib/vault-crypto";
import { cn } from "@/lib/utils";

/**
 * The password manager. Everything is decrypted here, in memory, with keys that never leave the
 * browser: the master password opens the private key, which unwraps each vault's key.
 */

const IDLE_LOCK_MS = 10 * 60_000;
const CLIPBOARD_CLEAR_MS = 30_000;

type Role = "owner" | "editor" | "viewer";
type OpenVault = { id: string; kind: "personal" | "shared"; name: string; role: Role; key: CryptoKey; members: number; items: number };
type OpenItem = vc.Item & { id: string; updated_at: string };

export default function PasswordsPage() {
  const account = useQuery({ queryKey: ["vault-account"], queryFn: () => unwrap(api.GET("/v1/vault/account")) });
  const qc = useQueryClient();
  const [privateKey, setKey] = useState<CryptoKey | null>(null);
  // Locking drops the keys and every decrypted copy React Query holds.
  const setPrivateKey = useCallback(
    (k: CryptoKey | null) => {
      if (!k) for (const key of ["vaults-open", "vault-items-open"]) qc.removeQueries({ queryKey: [key] });
      setKey(k);
    },
    [qc],
  );

  // Lock after a while without activity; the keys are simply dropped.
  useEffect(() => {
    if (!privateKey) return;
    let t = setTimeout(() => setPrivateKey(null), IDLE_LOCK_MS);
    const bump = () => {
      clearTimeout(t);
      t = setTimeout(() => setPrivateKey(null), IDLE_LOCK_MS);
    };
    const evs = ["pointerdown", "keydown"] as const;
    evs.forEach((e) => window.addEventListener(e, bump));
    return () => {
      clearTimeout(t);
      evs.forEach((e) => window.removeEventListener(e, bump));
    };
  }, [privateKey, setPrivateKey]);

  return (
    <>
      <PageHeader
        title="Passwords"
        description="Your passwords and your team's, end-to-end encrypted. Nexus stores only ciphertext: not even administrators can read them."
        actions={privateKey ? <Button onClick={() => setPrivateKey(null)}><Lock /> Lock</Button> : null}
      />
      {account.isPending ? (
        <Skeleton className="h-40" />
      ) : account.error ? (
        <ErrorBanner error={account.error} />
      ) : !account.data ? (
        <SetUp onDone={setPrivateKey} />
      ) : !privateKey ? (
        <Unlock account={account.data} onDone={setPrivateKey} />
      ) : (
        <Vaults privateKey={privateKey} account={account.data} />
      )}
    </>
  );
}

type Account = { public_key: string; private_key_enc: vc.Sealed; kdf: vc.Kdf };

function strength(pw: string) {
  const classes = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  return pw.length >= 14 && classes >= 3 ? "strong" : pw.length >= 12 ? "ok" : "weak";
}

function SetUp({ onDone }: { onDone: (k: CryptoKey) => void }) {
  const qc = useQueryClient();
  const [pw, setPw] = useState("");
  const [again, setAgain] = useState("");
  const [understood, setUnderstood] = useState(false);
  const go = useMutation({
    mutationFn: async () => {
      const acct = await vc.createAccount(pw);
      await unwrap(api.PUT("/v1/vault/account", { body: { public_key: acct.publicKey, private_key_enc: acct.privateKeyEnc, kdf: acct.kdf } }));
      const key = await vc.newVaultKey();
      await unwrap(api.POST("/v1/vault/vaults", { body: { kind: "personal", name_enc: await vc.encryptJson(key, "Personal"), wrapped_key: await vc.wrapFor(key, acct.publicKey) } }));
      return acct.privateKey;
    },
    onSuccess: (k) => {
      qc.invalidateQueries({ queryKey: ["vault-account"] });
      onDone(k);
    },
  });
  const s = strength(pw);
  return (
    <Card className="max-w-lg p-5">
      <h2 className="text-sm font-semibold">Set up your password manager</h2>
      <p className="mt-1 text-[13px] text-fg-muted">
        Choose a master password. It encrypts your vault on this device and is never sent to Nexus, so <strong>nobody can reset it</strong>: if you forget it, your personal
        vault can't be recovered (shared vaults can be re-shared to you).
      </p>
      <form
        className="mt-4 space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          go.mutate();
        }}
      >
        <Field label="Master password" htmlFor="mp" hint={pw ? `Strength: ${s}. Use at least 12 characters; a few random words work well.` : "At least 12 characters"}>
          <Input id="mp" type="password" autoComplete="new-password" value={pw} onChange={(e) => setPw(e.target.value)} />
        </Field>
        <Field label="Again" htmlFor="mp2" error={again && again !== pw ? "Doesn't match" : undefined}>
          <Input id="mp2" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
        </Field>
        <label className="flex items-start gap-2 text-[13px]">
          <input type="checkbox" className="mt-0.5" checked={understood} onChange={(e) => setUnderstood(e.target.checked)} />I understand Nexus can't recover this password.
        </label>
        <ErrorBanner error={go.error} />
        <Button type="submit" variant="primary" loading={go.isPending} disabled={pw.length < 12 || pw !== again || !understood}>
          Create my vault
        </Button>
        {go.isPending ? <p className="text-xs text-fg-muted">Generating keys…</p> : null}
      </form>
    </Card>
  );
}

function Unlock({ account, onDone }: { account: Account; onDone: (k: CryptoKey) => void }) {
  const [pw, setPw] = useState("");
  const go = useMutation({ mutationFn: () => vc.unlock(pw, account.kdf, account.private_key_enc), onSuccess: onDone });
  return (
    <Card className="max-w-sm p-5">
      <form
        className="space-y-3"
        onSubmit={(e) => {
          e.preventDefault();
          go.mutate();
        }}
      >
        <div className="flex items-center gap-2 text-sm font-semibold">
          <Lock className="size-4" /> Unlock your vaults
        </div>
        <Field label="Master password" htmlFor="unlock-pw">
          <Input id="unlock-pw" type="password" autoFocus autoComplete="current-password" value={pw} onChange={(e) => setPw(e.target.value)} />
        </Field>
        <ErrorBanner error={go.error} />
        <Button type="submit" variant="primary" loading={go.isPending} disabled={!pw}>
          Unlock
        </Button>
      </form>
    </Card>
  );
}

async function copySecret(text: string) {
  await navigator.clipboard.writeText(text);
  // Clear it again unless the person copied something else since.
  setTimeout(async () => {
    try {
      if ((await navigator.clipboard.readText()) === text) await navigator.clipboard.writeText("");
    } catch {
      /* no clipboard read permission: leave it */
    }
  }, CLIPBOARD_CLEAR_MS);
}

function Vaults({ privateKey, account }: { privateKey: CryptoKey; account: Account }) {
  const qc = useQueryClient();
  const raw = useQuery({ queryKey: ["vaults"], queryFn: () => unwrap(api.GET("/v1/vault/vaults")) });
  const vaults = useQuery({
    queryKey: ["vaults-open", raw.data],
    enabled: !!raw.data,
    gcTime: 0, // decrypted: not kept once nothing shows it
    queryFn: async (): Promise<OpenVault[]> =>
      Promise.all(
        raw.data!.data.map(async (v) => {
          const key = await vc.unwrap(v.wrapped_key, privateKey);
          return { id: v.id, kind: v.kind, role: v.role, members: v.members, items: v.items, key, name: await vc.decryptJson<string>(key, v.name_enc) };
        }),
      ),
  });
  const [selected, setSelected] = useState<string | null>(null);
  const [newVault, setNewVault] = useState(false);
  const [changePw, setChangePw] = useState(false);
  const list = vaults.data ?? [];
  const current = list.find((v) => v.id === selected) ?? list.find((v) => v.kind === "personal") ?? list[0];

  return (
    <div className="grid gap-4 md:grid-cols-[220px_1fr]">
      <div className="space-y-1">
        {vaults.isPending ? <Skeleton className="h-24" /> : null}
        <ErrorBanner error={raw.error ?? vaults.error} />
        {list.map((v) => (
          <button
            key={v.id}
            type="button"
            onClick={() => setSelected(v.id)}
            className={cn("flex w-full items-center justify-between rounded-md px-2.5 py-1.5 text-left text-[13px] hover:bg-bg-muted", current?.id === v.id && "bg-bg-muted font-medium")}
          >
            <span className="truncate">{v.name}</span>
            <span className="text-xs text-fg-subtle">{v.kind === "shared" ? `${v.members} people` : v.items}</span>
          </button>
        ))}
        <Button size="sm" variant="ghost" className="w-full justify-start" onClick={() => setNewVault(true)}>
          <Plus /> New shared vault
        </Button>
        <Button size="sm" variant="ghost" className="w-full justify-start" onClick={() => setChangePw(true)}>
          <KeyRound /> Change master password
        </Button>
      </div>
      {current ? <VaultItems vault={current} /> : null}
      <NewVaultDialog open={newVault} onOpenChange={setNewVault} publicKey={account.public_key} onCreated={(id) => (setSelected(id), qc.invalidateQueries({ queryKey: ["vaults"] }))} />
      <ChangePasswordDialog open={changePw} onOpenChange={setChangePw} account={account} />
    </div>
  );
}

function VaultItems({ vault }: { vault: OpenVault }) {
  const qc = useQueryClient();
  const raw = useQuery({ queryKey: ["vault-items", vault.id], queryFn: () => unwrap(api.GET("/v1/vault/vaults/{id}/items", { params: { path: { id: vault.id } } })) });
  const items = useQuery({
    queryKey: ["vault-items-open", vault.id, raw.data],
    enabled: !!raw.data,
    gcTime: 0,
    queryFn: async (): Promise<OpenItem[]> =>
      Promise.all(raw.data!.data.map(async (i) => ({ ...(await vc.decryptJson<vc.Item>(vault.key, i.data)), id: i.id, updated_at: i.updated_at }))),
  });
  const [q, setQ] = useState("");
  const [editing, setEditing] = useState<OpenItem | "new" | null>(null);
  const [sharing, setSharing] = useState(false);
  const writable = vault.role !== "viewer";
  const shown = useMemo(() => {
    const s = q.toLowerCase();
    return (items.data ?? []).filter((i) => [i.title, i.url, i.username].some((f) => f?.toLowerCase().includes(s))).sort((a, b) => a.title.localeCompare(b.title));
  }, [items.data, q]);
  const refresh = useCallback(() => {
    qc.invalidateQueries({ queryKey: ["vault-items", vault.id] });
    qc.invalidateQueries({ queryKey: ["vaults"] });
  }, [qc, vault.id]);
  const del = useMutation({ mutationFn: (id: string) => unwrap(api.DELETE("/v1/vault/items/{id}", { params: { path: { id } } })), onSuccess: refresh });
  const delVault = useMutation({
    mutationFn: () => unwrap(api.DELETE("/v1/vault/vaults/{id}", { params: { path: { id: vault.id } } })),
    onSuccess: () => qc.invalidateQueries({ queryKey: ["vaults"] }),
  });

  return (
    <Card>
      <CardHeader
        title={
          <span className="flex items-center gap-2">
            {vault.name} <Badge>{vault.role}</Badge>
          </span>
        }
        description={vault.kind === "personal" ? "Only you can open this vault." : `Shared with ${vault.members} ${vault.members === 1 ? "person" : "people"}.`}
        actions={
          <div className="flex gap-2">
            {vault.kind === "shared" ? (
              <Button size="sm" onClick={() => setSharing(true)}>
                <Share2 /> {vault.role === "owner" ? "Share" : "Members"}
              </Button>
            ) : null}
            {vault.kind === "shared" && vault.role === "owner" ? (
              <Button size="sm" variant="danger-outline" loading={delVault.isPending} onClick={() => confirm(`Delete "${vault.name}" and everything in it, for everyone?`) && delVault.mutate()}>
                <Trash2 />
              </Button>
            ) : null}
            {writable ? (
              <Button size="sm" variant="primary" onClick={() => setEditing("new")}>
                <Plus /> Add
              </Button>
            ) : null}
          </div>
        }
      />
      <div className="p-4 pt-0">
        {items.data?.length ? <Input className="mb-3 max-w-xs" placeholder="Search" value={q} onChange={(e) => setQ(e.target.value)} aria-label="Search passwords" /> : null}
        <ErrorBanner error={raw.error ?? items.error ?? del.error ?? delVault.error} />
        {items.isPending || raw.isPending ? (
          <Skeleton className="h-24" />
        ) : !items.data?.length ? (
          <EmptyState icon={<KeyRound />} title="Nothing here yet" description={writable ? "Add a login, and it's encrypted before it leaves this page." : "The owners haven't added anything yet."} />
        ) : (
          <ul className="divide-y divide-border">
            {shown.map((i) => (
              <ItemRow key={i.id} item={i} writable={writable} onEdit={() => setEditing(i)} onDelete={() => confirm(`Delete "${i.title}"?`) && del.mutate(i.id)} />
            ))}
          </ul>
        )}
      </div>
      <ItemDialog vault={vault} item={editing} onClose={() => setEditing(null)} onSaved={refresh} />
      {vault.kind === "shared" ? <ShareDialog open={sharing} onOpenChange={setSharing} vault={vault} /> : null}
    </Card>
  );
}

function ItemRow({ item, writable, onEdit, onDelete }: { item: OpenItem; writable: boolean; onEdit: () => void; onDelete: () => void }) {
  const [shown, setShown] = useState(false);
  const used = (action: "revealed" | "copied_password" | "copied_username") => void api.POST("/v1/vault/items/{id}/used", { params: { path: { id: item.id } }, body: { action } });
  return (
    <li className="flex items-center gap-3 py-2.5">
      <div className="min-w-0 flex-1">
        <p className="truncate text-[13px] font-medium">{item.title}</p>
        <p className="truncate text-xs text-fg-muted">
          {item.username}
          {item.url ? (
            <>
              {item.username ? " · " : ""}
              <a href={item.url} target="_blank" rel="noopener noreferrer" className="hover:underline">
                {item.url.replace(/^https?:\/\//, "")}
              </a>
            </>
          ) : null}
        </p>
        {shown && item.password ? <code className="mt-1 block break-all font-mono text-xs">{item.password}</code> : null}
      </div>
      {item.username ? (
        <Button size="sm" variant="ghost" title="Copy username" onClick={async () => (await navigator.clipboard.writeText(item.username!), used("copied_username"), toast.success("Username copied"))}>
          <Copy /> User
        </Button>
      ) : null}
      {item.password ? (
        <>
          <Button size="sm" variant="ghost" title="Copy password (cleared from the clipboard after 30 seconds)" onClick={async () => (await copySecret(item.password!), used("copied_password"), toast.success("Password copied"))}>
            <Copy /> Password
          </Button>
          <Button size="icon" variant="ghost" aria-label={shown ? "Hide password" : "Show password"} onClick={() => (setShown(!shown), !shown && used("revealed"))}>
            {shown ? <EyeOff /> : <Eye />}
          </Button>
        </>
      ) : null}
      {writable ? (
        <>
          <Button size="icon" variant="ghost" aria-label="Edit" onClick={onEdit}>
            <Pencil />
          </Button>
          <Button size="icon" variant="ghost" aria-label="Delete" onClick={onDelete}>
            <Trash2 />
          </Button>
        </>
      ) : null}
    </li>
  );
}

function ItemDialog({ vault, item, onClose, onSaved }: { vault: OpenVault; item: OpenItem | "new" | null; onClose: () => void; onSaved: () => void }) {
  const [f, setF] = useState<vc.Item>({ title: "" });
  const [show, setShow] = useState(false);
  useEffect(() => {
    if (item) setF(item === "new" ? { title: "", url: "", username: "", password: vc.generatePassword(), notes: "" } : { title: item.title, url: item.url, username: item.username, password: item.password, notes: item.notes });
    setShow(false);
  }, [item]);
  const save = useMutation({
    mutationFn: async () => {
      const clean = Object.fromEntries(Object.entries(f).filter(([, v]) => v)) as vc.Item;
      const data = await vc.encryptJson(vault.key, clean);
      if (item === "new") await unwrap(api.POST("/v1/vault/vaults/{id}/items", { params: { path: { id: vault.id } }, body: { data } }));
      else if (item) await unwrap(api.PUT("/v1/vault/items/{id}", { params: { path: { id: item.id } }, body: { data } }));
    },
    onSuccess: () => (onSaved(), onClose()),
  });
  const set = (k: keyof vc.Item) => (e: React.ChangeEvent<HTMLInputElement | HTMLTextAreaElement>) => setF({ ...f, [k]: e.target.value });
  return (
    <Dialog open={!!item} onOpenChange={(o) => !o && onClose()}>
      <DialogContent title={item === "new" ? "Add a login" : "Edit login"} description={`Encrypted in this browser before it's saved to "${vault.name}".`}>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            save.mutate();
          }}
        >
          <Field label="Name" htmlFor="it-title">
            <Input id="it-title" value={f.title} onChange={set("title")} placeholder="GitHub" autoFocus />
          </Field>
          <Field label="Website" htmlFor="it-url">
            <Input id="it-url" type="url" value={f.url ?? ""} onChange={set("url")} placeholder="https://github.com" />
          </Field>
          <Field label="Username" htmlFor="it-user">
            <Input id="it-user" autoComplete="off" value={f.username ?? ""} onChange={set("username")} />
          </Field>
          <Field label="Password" htmlFor="it-pw">
            <div className="flex gap-2">
              <Input id="it-pw" type={show ? "text" : "password"} autoComplete="new-password" className="font-mono" value={f.password ?? ""} onChange={set("password")} />
              <Button type="button" size="icon" aria-label={show ? "Hide" : "Show"} onClick={() => setShow(!show)}>
                {show ? <EyeOff /> : <Eye />}
              </Button>
              <Button type="button" size="icon" aria-label="Generate a password" title="Generate" onClick={() => (setF({ ...f, password: vc.generatePassword() }), setShow(true))}>
                <RefreshCw />
              </Button>
            </div>
          </Field>
          <Field label="Notes" htmlFor="it-notes">
            <textarea id="it-notes" rows={3} className="w-full rounded-md border border-border bg-bg px-2.5 py-1.5 text-[13px]" value={f.notes ?? ""} onChange={set("notes")} />
          </Field>
          <ErrorBanner error={save.error} />
          <Button type="submit" variant="primary" loading={save.isPending} disabled={!f.title.trim()}>
            Save
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function NewVaultDialog({ open, onOpenChange, publicKey, onCreated }: { open: boolean; onOpenChange: (o: boolean) => void; publicKey: string; onCreated: (id: string) => void }) {
  const [name, setName] = useState("");
  const go = useMutation({
    mutationFn: async () => {
      const key = await vc.newVaultKey();
      return unwrap(api.POST("/v1/vault/vaults", { body: { kind: "shared", name_enc: await vc.encryptJson(key, name.trim()), wrapped_key: await vc.wrapFor(key, publicKey) } }));
    },
    onSuccess: (r) => (onCreated(r.id), onOpenChange(false), setName("")),
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="New shared vault" description="You'll be its owner, and can share it with anyone who has set up the password manager.">
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            go.mutate();
          }}
        >
          <Field label="Name" htmlFor="nv-name">
            <Input id="nv-name" value={name} onChange={(e) => setName(e.target.value)} placeholder="Engineering" autoFocus />
          </Field>
          <ErrorBanner error={go.error} />
          <Button type="submit" variant="primary" loading={go.isPending} disabled={!name.trim()}>
            Create
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}

function ShareDialog({ open, onOpenChange, vault }: { open: boolean; onOpenChange: (o: boolean) => void; vault: OpenVault }) {
  const qc = useQueryClient();
  const me = useMe();
  const members = useQuery({ queryKey: ["vault-members", vault.id], enabled: open, queryFn: () => unwrap(api.GET("/v1/vault/vaults/{id}/members", { params: { path: { id: vault.id } } })) });
  const people = useQuery({ queryKey: ["vault-people"], enabled: open && vault.role === "owner", queryFn: () => unwrap(api.GET("/v1/vault/people")) });
  const [who, setWho] = useState("");
  const [role, setRole] = useState<Role>("viewer");
  const person = people.data?.data.find((p) => p.user_id === who);
  const fp = useQuery({ queryKey: ["vault-fp", person?.public_key], enabled: !!person, queryFn: () => vc.fingerprint(person!.public_key) });
  const done = () => {
    qc.invalidateQueries({ queryKey: ["vault-members", vault.id] });
    qc.invalidateQueries({ queryKey: ["vaults"] });
  };
  const add = useMutation({
    mutationFn: async () =>
      unwrap(api.PUT("/v1/vault/vaults/{id}/members/{user_id}", { params: { path: { id: vault.id, user_id: who } }, body: { role, wrapped_key: await vc.wrapFor(vault.key, person!.public_key) } })),
    onSuccess: () => (setWho(""), done()),
  });
  const change = useMutation({
    mutationFn: (m: { user_id: string; role: Role }) => unwrap(api.PUT("/v1/vault/vaults/{id}/members/{user_id}", { params: { path: { id: vault.id, user_id: m.user_id } }, body: { role: m.role } })),
    onSuccess: done,
  });
  const remove = useMutation({ mutationFn: (userId: string) => unwrap(api.DELETE("/v1/vault/vaults/{id}/members/{user_id}", { params: { path: { id: vault.id, user_id: userId } } })), onSuccess: done });
  const leave = useMutation({
    mutationFn: () => unwrap(api.DELETE("/v1/vault/vaults/{id}/members/{user_id}", { params: { path: { id: vault.id, user_id: me.data!.user.id } } })),
    onSuccess: () => (onOpenChange(false), done()),
  });
  const isMember = new Set(members.data?.data.map((m) => m.user_id));
  const owner = vault.role === "owner";

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title={`Share "${vault.name}"`} description="Viewers can read and copy; editors can also add and change; owners can also share." className="max-w-lg">
        <ul className="mb-4 divide-y divide-border rounded-md border border-border">
          {members.data?.data.map((m) => (
            <li key={m.user_id} className="flex items-center gap-2 px-3 py-2 text-[13px]">
              <span className="min-w-0 flex-1 truncate">{m.email}</span>
              {owner ? (
                <Select value={m.role} onChange={(e) => change.mutate({ user_id: m.user_id, role: e.target.value as Role })} aria-label={`Role for ${m.email}`}>
                  <option value="viewer">Viewer</option>
                  <option value="editor">Editor</option>
                  <option value="owner">Owner</option>
                </Select>
              ) : (
                <Badge>{m.role}</Badge>
              )}
              {owner ? (
                <Button size="icon" variant="ghost" aria-label={`Remove ${m.email}`} onClick={() => remove.mutate(m.user_id)}>
                  <UserMinus />
                </Button>
              ) : null}
            </li>
          ))}
        </ul>
        <ErrorBanner error={members.error ?? change.error ?? remove.error} />
        {owner ? (
          <form
            className="space-y-3"
            onSubmit={(e) => {
              e.preventDefault();
              add.mutate();
            }}
          >
            <div className="flex gap-2">
              <Select className="min-w-0 flex-1" value={who} onChange={(e) => setWho(e.target.value)} aria-label="Person">
                <option value="">Add someone…</option>
                {people.data?.data
                  .filter((p) => !isMember.has(p.user_id))
                  .map((p) => (
                    <option key={p.user_id} value={p.user_id}>
                      {p.name} ({p.email})
                    </option>
                  ))}
              </Select>
              <Select value={role} onChange={(e) => setRole(e.target.value as Role)} aria-label="Role">
                <option value="viewer">Viewer</option>
                <option value="editor">Editor</option>
                <option value="owner">Owner</option>
              </Select>
            </div>
            {person && fp.data ? (
              <p className="text-xs text-fg-muted">
                Their key fingerprint is <code className="font-mono">{fp.data}</code>. For sensitive vaults, check it matches what they see under Passwords → Change master password.
              </p>
            ) : null}
            <p className="text-xs text-fg-muted">Only people who have set up their password manager are listed.</p>
            <ErrorBanner error={add.error} />
            <Button type="submit" variant="primary" loading={add.isPending} disabled={!person}>
              Share
            </Button>
          </form>
        ) : (
          <>
            <ErrorBanner error={leave.error} />
            <Button variant="danger-outline" loading={leave.isPending} disabled={!me.data} onClick={() => confirm(`Leave "${vault.name}"? An owner would have to share it with you again.`) && leave.mutate()}>
              Leave this vault
            </Button>
          </>
        )}
      </DialogContent>
    </Dialog>
  );
}

function ChangePasswordDialog({ open, onOpenChange, account }: { open: boolean; onOpenChange: (o: boolean) => void; account: Account }) {
  const qc = useQueryClient();
  const [cur, setCur] = useState("");
  const [next, setNext] = useState("");
  const [again, setAgain] = useState("");
  const fp = useQuery({ queryKey: ["vault-fp", account.public_key], queryFn: () => vc.fingerprint(account.public_key) });
  const go = useMutation({
    mutationFn: async () => {
      const r = await vc.rewrapPrivateKey(cur, next, account.kdf, account.private_key_enc);
      await unwrap(api.PUT("/v1/vault/account", { body: { public_key: account.public_key, private_key_enc: r.privateKeyEnc, kdf: r.kdf } }));
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ["vault-account"] });
      toast.success("Master password changed");
      setCur("");
      setNext("");
      setAgain("");
      onOpenChange(false);
    },
  });
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent title="Change master password" description={fp.data ? <>Your key fingerprint: <code className="font-mono">{fp.data}</code></> : undefined}>
        <form
          className="space-y-3"
          onSubmit={(e) => {
            e.preventDefault();
            go.mutate();
          }}
        >
          <Field label="Current master password" htmlFor="cp-cur">
            <Input id="cp-cur" type="password" autoComplete="current-password" value={cur} onChange={(e) => setCur(e.target.value)} />
          </Field>
          <Field label="New master password" htmlFor="cp-new" hint="At least 12 characters">
            <Input id="cp-new" type="password" autoComplete="new-password" value={next} onChange={(e) => setNext(e.target.value)} />
          </Field>
          <Field label="Again" htmlFor="cp-again" error={again && again !== next ? "Doesn't match" : undefined}>
            <Input id="cp-again" type="password" autoComplete="new-password" value={again} onChange={(e) => setAgain(e.target.value)} />
          </Field>
          <ErrorBanner error={go.error} />
          <Button type="submit" variant="primary" loading={go.isPending} disabled={!cur || next.length < 12 || next !== again}>
            Change
          </Button>
        </form>
      </DialogContent>
    </Dialog>
  );
}
