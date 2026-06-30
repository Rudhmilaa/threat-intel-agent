import { Breadcrumbs } from "@/components/breadcrumb";
import { NavBar } from "@/components/navbar";
import { AppSidebar } from "@/components/sidebar";
import { SidebarProvider } from "@/components/ui/sidebar";
import { Box, Container } from "@mui/material";
import { StoreCountProvider } from "@/lib/hooks/use-store-count-context";
import { UpdateChecker } from "@/components/update-checker";

/** Evaluate THREAT_FEEDS_ENABLED per request (not only at `next build`). */
export const dynamic = "force-dynamic";

const threatFeedsGroup = {
  group: "Threat Feeds",
  items: [
    { label: "Threat Feeds", icon: "federated-sharing", href: "/threat-feeds" },
    { label: "Block lists", icon: "safe-blocklist", href: "/block-lists" },
    { label: "Safelist", icon: "safe-blocklist", href: "/safelist" },
  ],
};

function buildDashboardRoutes() {
  const threatFeedsEnabled = process.env.THREAT_FEEDS_ENABLED === "true";

  return [
  {
    group: "",
    items: [
      {
        label: "Dashboard",
        icon: "dashboard",
        href: "/dashboard",
      },
    ],
  },
  {
    group: "Hosts & Honeypots",
    items: [
      {
        label: "Manage Hosts",
        icon: "manage-host",
        href: "/hosts",
      },
      {
        label: "Manage Honeypots",
        icon: "manage-hp",
        href: "/sensors",
      },
      {
        label: "Honeypot Store",
        icon: "store",
        href: "/hp-store",
      },
      {
        label: "Deploy Honeypot",
        icon: "deploy-hp",
        href: "/deploy",
      },
      {
        label: "Deployment Log",
        icon: "deployment-log",
        href: "/deployments",
      },
    ],
  },
  {
    group: "Honeypot Data",
    items: [
      {
        label: "Attack Analysis",
        icon: "attack-analysis",
        href: "/sessions",
      },
    ],
  },
  {
    group: "Security Tools",
    items: [
      {
        label: "DNS Scanner",
        icon: "vulnerability-scan",
        href: "/dns-scanner",
      },
      {
        label: "IDS/IPS Rules",
        icon: "ids-rules",
        href: "/ids-rules",
      },
    ],
  },
  ...(threatFeedsEnabled ? [threatFeedsGroup] : []),
  {
    group: "Settings",
    items: [
      {
        label: "Settings",
        icon: "settings",
        href: "/settings",
      },
      {
        label: "Users",
        icon: "user-management",
        href: "/users",
      },
    ],
  },
  {
    group: "Documentation",
    items: [
      {
        label: "User Guide",
        icon: "help",
        href: "/docs",
      },
    ],
  },
  {
    excludeSidebar: true,
    group: "",
    items: [
      {
        label: "Account",
        icon: "",
        href: "/account",
      },
    ],
  },
  ];
}

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const routes = buildDashboardRoutes();

  return (
    <StoreCountProvider>
      <SidebarProvider>
        <AppSidebar routes={routes} />
        <UpdateChecker />
        <Box
          sx={{
            bgcolor: "customColors.dashboardBackground",
            width: "100%",
          }}
        >
          <main id="main-content" className="w-full bg-[#363636] overflow-x-hidden">
            <div className="fixed md:left-[250px] left-0 top-0 right-0 z-50">
              <NavBar routes={routes} />
            </div>
            <div className="relative top-[64px] bg-white rounded-tl-md overflow-x-hidden flex flex-col h-[calc(100vh-64px)]">
              <div className="h-[48px] px-4 shrink-0">
                <Breadcrumbs routes={routes} />
              </div>
              <div className="flex-1 px-4 overflow-x-hidden overflow-y-auto min-h-0 basis-0">{children}</div>
              <footer role="contentinfo" className="shrink-0 px-4 py-2 text-sm text-gray-500 border-t border-gray-200">
                STINGAR - Shared Threat Intelligence for Higher Education and Research
              </footer>
            </div>
          </main>
        </Box>
      </SidebarProvider>
    </StoreCountProvider>
  );
}
