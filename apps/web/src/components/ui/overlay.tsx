"use client";

import { Dialog as D, DropdownMenu as DM, Tabs as T } from "radix-ui";
import { X } from "lucide-react";
import * as React from "react";
import { cn } from "@/lib/utils";

// ---- Dialog -----------------------------------------------------------------------

export const Dialog = D.Root;
export const DialogTrigger = D.Trigger;
export const DialogClose = D.Close;

export function DialogContent({
  title,
  description,
  children,
  className,
}: {
  title: string;
  description?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
}) {
  return (
    <D.Portal>
      <D.Overlay className="fixed inset-0 z-50 bg-black/40 backdrop-blur-[1px]" />
      <D.Content
        className={cn(
          "fixed left-1/2 top-[12vh] z-50 w-[calc(100vw-32px)] max-w-md -translate-x-1/2 rounded-lg border border-border bg-bg p-5 shadow-2xl focus:outline-none",
          className,
        )}
      >
        <div className="mb-4 pr-6">
          <D.Title className="text-base font-semibold">{title}</D.Title>
          {description ? <D.Description className="mt-1 text-[13px] text-fg-muted">{description}</D.Description> : <D.Description className="sr-only">{title}</D.Description>}
        </div>
        {children}
        <D.Close className="absolute right-3 top-3 rounded p-1 text-fg-muted hover:bg-bg-muted" aria-label="Close">
          <X className="size-4" />
        </D.Close>
      </D.Content>
    </D.Portal>
  );
}

/** Right-hand drawer (inbox, peek views). */
export function SheetContent({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <D.Portal>
      <D.Overlay className="fixed inset-0 z-50 bg-black/20" />
      <D.Content className="fixed inset-y-0 right-0 z-50 flex w-full max-w-md flex-col border-l border-border bg-bg shadow-2xl focus:outline-none">
        <div className="flex items-center justify-between border-b border-border px-4 py-3">
          <D.Title className="text-sm font-semibold">{title}</D.Title>
          <D.Description className="sr-only">{title}</D.Description>
          <D.Close className="rounded p-1 text-fg-muted hover:bg-bg-muted" aria-label="Close">
            <X className="size-4" />
          </D.Close>
        </div>
        {children}
      </D.Content>
    </D.Portal>
  );
}

// ---- Dropdown menu ----------------------------------------------------------------

export const Menu = DM.Root;
export const MenuTrigger = DM.Trigger;

export function MenuContent({ children, align = "end" }: { children: React.ReactNode; align?: "start" | "end" }) {
  return (
    <DM.Portal>
      <DM.Content
        align={align}
        sideOffset={6}
        className="z-50 min-w-48 rounded-md border border-border bg-bg p-1 text-[13px] shadow-xl"
      >
        {children}
      </DM.Content>
    </DM.Portal>
  );
}

export function MenuItem({
  children,
  onSelect,
  danger,
  disabled,
  shortcut,
}: {
  children: React.ReactNode;
  onSelect?: () => void;
  danger?: boolean;
  disabled?: boolean;
  shortcut?: string;
}) {
  return (
    <DM.Item
      disabled={disabled}
      onSelect={onSelect}
      className={cn(
        "flex cursor-default items-center gap-2 rounded px-2 py-1.5 outline-none data-[disabled]:opacity-40 data-[highlighted]:bg-bg-muted [&_svg]:size-4",
        danger ? "text-danger" : "text-fg",
      )}
    >
      {children}
      {shortcut ? <span className="ml-auto font-mono text-[11px] text-fg-subtle">{shortcut}</span> : null}
    </DM.Item>
  );
}

export const MenuSeparator = () => <DM.Separator className="my-1 h-px bg-border" />;
export const MenuLabel = ({ children }: { children: React.ReactNode }) => (
  <DM.Label className="px-2 py-1 text-[11px] font-medium uppercase tracking-wide text-fg-subtle">{children}</DM.Label>
);

// ---- Tabs -------------------------------------------------------------------------

export const Tabs = T.Root;
export const TabsContent = T.Content;

export function TabsList({ tabs }: { tabs: { value: string; label: React.ReactNode }[] }) {
  return (
    <T.List className="mb-4 flex gap-1 border-b border-border">
      {tabs.map((t) => (
        <T.Trigger
          key={t.value}
          value={t.value}
          className="-mb-px border-b-2 border-transparent px-3 py-2 text-[13px] font-medium text-fg-muted hover:text-fg data-[state=active]:border-primary data-[state=active]:text-fg"
        >
          {t.label}
        </T.Trigger>
      ))}
    </T.List>
  );
}
