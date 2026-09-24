import {
  Activity,
  AppWindow,
  Bot,
  FileClock,
  Home,
  KeyRound,
  LayoutGrid,
  Laptop,
  ScrollText,
  Server,
  Settings,
  ShieldCheck,
  Users,
  UsersRound,
  Wrench,
  type LucideIcon,
} from "lucide-react";

export type NavItem = { label: string; href: string; icon: LucideIcon; soon?: string; shortcut?: string };
export type NavSection = { title?: string; items: NavItem[] };

// Mirrors docs/UI.md §3. "soon" marks what is on the roadmap but not built yet, so admins see where the product is going.
export const NAV: NavSection[] = [
  {
    items: [
      { label: "Overview", href: "/", icon: Home, shortcut: "G O" },
      { label: "My apps", href: "/my-apps", icon: LayoutGrid },
    ],
  },
  {
    title: "Identity",
    items: [
      { label: "Users", href: "/users", icon: Users, shortcut: "G U" },
      { label: "Groups", href: "/groups", icon: UsersRound, shortcut: "G G" },
    ],
  },
  {
    title: "Devices",
    items: [
      { label: "All devices", href: "/devices", icon: Laptop, soon: "A2" },
      { label: "Device policies", href: "/device-policies", icon: Wrench, soon: "A2" },
    ],
  },
  {
    title: "Access",
    items: [
      { label: "Applications", href: "/apps", icon: AppWindow },
      { label: "Conditional access", href: "/conditional-access", icon: ShieldCheck, soon: "A2" },
    ],
  },
  {
    title: "AI security",
    items: [
      { label: "Agents", href: "/agents", icon: Bot, soon: "A3" },
      { label: "MCP servers", href: "/mcp", icon: Server, soon: "A3" },
    ],
  },
  {
    title: "Insights",
    items: [{ label: "Audit log", href: "/audit", icon: ScrollText, shortcut: "G A" }],
  },
  {
    title: "Settings",
    items: [
      { label: "My security", href: "/settings/security", icon: KeyRound },
      { label: "Organization", href: "/settings/organization", icon: Settings },
    ],
  },
];

export const ICONS = { Activity, FileClock };
