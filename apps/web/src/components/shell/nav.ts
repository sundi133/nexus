import {
  Activity,
  Apple,
  AppWindow,
  BellRing,
  Ban,
  Bot,
  BrainCircuit,
  ClipboardCheck,
  FileBarChart,
  FileClock,
  FolderSync,
  Globe,
  Home,
  Key,
  KeyRound,
  LayoutGrid,
  LockKeyhole,
  LogIn,
  Network,
  MonitorSmartphone,
  PackageCheck,
  PackagePlus,
  PackageSearch,
  Radio,
  RefreshCcwDot,
  Laptop,
  ScrollText,
  Server,
  Settings,
  ShieldAlert,
  ShieldCheck,
  TerminalSquare,
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
      { label: "My devices", href: "/my-devices", icon: MonitorSmartphone },
      { label: "Passwords", href: "/passwords", icon: LockKeyhole },
    ],
  },
  {
    title: "Identity",
    items: [
      { label: "Users", href: "/users", icon: Users, shortcut: "G U" },
      { label: "Groups", href: "/groups", icon: UsersRound, shortcut: "G G" },
      { label: "Directory sync", href: "/directory-sync", icon: FolderSync },
    ],
  },
  {
    title: "Devices",
    items: [
      { label: "All devices", href: "/devices", icon: Laptop, shortcut: "G D" },
      { label: "Device management", href: "/mdm", icon: Server },
      { label: "Apple MDM", href: "/apple-mdm", icon: Apple },
      { label: "Device policies", href: "/device-policies", icon: Wrench },
      { label: "Software", href: "/software", icon: PackageSearch },
      { label: "OS updates", href: "/updates", icon: RefreshCcwDot },
      { label: "App deployment", href: "/app-deployment", icon: PackagePlus },
      { label: "Live query", href: "/live-query", icon: TerminalSquare },
      { label: "Scripts", href: "/scripts", icon: ScrollText },
      { label: "Block rules", href: "/block-rules", icon: Ban },
      { label: "Agent updates", href: "/agent-updates", icon: PackageCheck },
    ],
  },
  {
    title: "Access",
    items: [
      { label: "Applications", href: "/apps", icon: AppWindow },
      { label: "Conditional access", href: "/conditional-access", icon: ShieldCheck },
      { label: "Access requests", href: "/access-requests", icon: KeyRound },
      { label: "Access reviews", href: "/access-reviews", icon: ClipboardCheck },
    ],
  },
  {
    title: "AI security",
    items: [
      { label: "Agents", href: "/agents", icon: Bot },
      { label: "MCP servers", href: "/mcp", icon: Server },
      { label: "AI on devices", href: "/ai-devices", icon: BrainCircuit },
      { label: "AI in browsers", href: "/ai-browsers", icon: Globe },
      { label: "Access graph", href: "/access-graph", icon: Network },
    ],
  },
  {
    title: "Insights",
    items: [
      { label: "Alerts", href: "/alerts", icon: BellRing },
      { label: "Detections", href: "/detections", icon: ShieldAlert },
      { label: "Audit log", href: "/audit", icon: ScrollText, shortcut: "G A" },
      { label: "Reports", href: "/reports", icon: FileBarChart },
    ],
  },
  {
    title: "Settings",
    items: [
      { label: "My security", href: "/settings/security", icon: KeyRound },
      { label: "Organization", href: "/settings/organization", icon: Settings },
      { label: "Roles", href: "/settings/roles", icon: ShieldCheck },
      { label: "Single sign-on", href: "/settings/identity-providers", icon: LogIn },
      { label: "LDAP & RADIUS", href: "/settings/directory-services", icon: Network },
      { label: "Integrations", href: "/settings/integrations", icon: Radio },
      { label: "API keys", href: "/settings/api-keys", icon: Key },
    ],
  },
];

export const ICONS = { Activity, FileClock };
