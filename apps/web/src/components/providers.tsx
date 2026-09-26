"use client";

import { MutationCache, QueryCache, QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { useState } from "react";
import { Toaster, toast } from "sonner";
import { ApiProblem } from "@/lib/api";
import { StepUpProvider } from "./step-up";

function handleAuthError(err: unknown) {
  if (!(err instanceof ApiProblem) || typeof window === "undefined") return false;
  if (err.status !== 401) return false;
  const here = window.location.pathname + window.location.search;
  if (err.code === "mfa_required") window.location.assign(`/login?step=mfa&next=${encodeURIComponent(here)}`);
  else if (err.code === "mfa_enrollment_required") window.location.assign(`/setup-mfa?next=${encodeURIComponent(here)}`);
  else if (err.code === "unauthenticated") window.location.assign(`/login?next=${encodeURIComponent(here)}`);
  else return false; // e.g. step_up_required is handled by the caller
  return true;
}

export function Providers({ children }: { children: React.ReactNode }) {
  const [client] = useState(
    () =>
      new QueryClient({
        queryCache: new QueryCache({ onError: handleAuthError }),
        mutationCache: new MutationCache({
          onError: (err, _v, _c, mutation) => {
            if (handleAuthError(err) || mutation.options.onError) return;
            toast.error(err instanceof Error ? err.message : "Something went wrong");
          },
        }),
        defaultOptions: {
          queries: {
            staleTime: 15_000,
            retry: (count, err) => !(err instanceof ApiProblem && err.status < 500) && count < 2,
            refetchOnWindowFocus: true,
          },
        },
      }),
  );
  return (
    <QueryClientProvider client={client}>
      <StepUpProvider>{children}</StepUpProvider>
      <Toaster position="bottom-right" richColors closeButton />
    </QueryClientProvider>
  );
}
