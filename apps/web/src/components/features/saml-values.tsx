"use client";

import type { Schemas } from "@nexus/api-client";
import { Download } from "lucide-react";
import { Button } from "@/components/ui/button";
import { CopyField } from "@/components/ui/copy";

type Saml = NonNullable<Schemas["Application"]["saml"]>;

/** The IdP-side values an admin pastes into a SAML app. */
export function SamlIdpValues({ saml }: { saml: Saml }) {
  return (
    <div className="space-y-3">
      <CopyField label="IdP metadata URL (easiest, if the app accepts it)" value={saml.idp_metadata_url} />
      <CopyField label="IdP sign-in URL (SSO URL)" value={saml.idp_sso_url} />
      <CopyField label="IdP entity ID (Issuer)" value={saml.idp_entity_id} />
      <div>
        <p className="mb-1 text-xs font-medium text-fg-muted">Signing certificate</p>
        <div className="flex items-center justify-between gap-2 rounded-md border border-border px-2.5 py-1.5">
          <code className="min-w-0 truncate font-mono text-[11px] text-fg-muted" title={saml.certificate_fingerprint}>
            SHA-256 {saml.certificate_fingerprint.slice(0, 23)}…
          </code>
          <Button asChild size="sm" variant="ghost">
            <a href={`data:application/x-pem-file;charset=utf-8,${encodeURIComponent(saml.idp_certificate)}`} download="nexus-saml-signing.pem">
              <Download /> Download .pem
            </a>
          </Button>
        </div>
        <p className="mt-1 text-[11px] text-fg-subtle">Valid until {new Date(saml.certificate_expires_at).toLocaleDateString()}</p>
      </div>
    </div>
  );
}
