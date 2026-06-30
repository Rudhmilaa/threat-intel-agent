"use client";

import { Button, Link } from "@mui/material";
import OpenInNewIcon from "@mui/icons-material/OpenInNew";
import { useEffect, useState } from "react";
import { debugLog } from "@/lib/debug";
import { usePageTitle } from "@/lib/hooks/use-page-title";
import { useIsMobile } from "@/components/hooks/use-viewport";
import NextLink from "next/link";

const KIBANA_DASHBOARD_URL =
  "/kibana/app/dashboards#/view/default_dashboard?embed=true&_g=(filters%3A!()%2CrefreshInterval%3A(pause%3A!t%2Cvalue%3A0)%2Ctime%3A(from%3Anow-30d%2Cto%3Anow))&hide-filter-bar=true";

// Persists the intro / quick-links panel collapse state across visits.
const DASHBOARD_INTRO_COLLAPSED_KEY = "stingar_dashboard_intro_collapsed";

function readIntroCollapsed(): boolean {
  try {
    return localStorage.getItem(DASHBOARD_INTRO_COLLAPSED_KEY) === "true";
  } catch {
    return false;
  }
}

function writeIntroCollapsed(collapsed: boolean): void {
  try {
    localStorage.setItem(DASHBOARD_INTRO_COLLAPSED_KEY, String(collapsed));
  } catch {
    // Ignore quota / private-browsing errors; in-memory state still works.
  }
}

export default function Dashboard() {
  const [isCollapsed, setIsCollapsed] = useState(false);
  const isMobile = useIsMobile();
  usePageTitle("Dashboard");

  useEffect(() => {
    setIsCollapsed(readIntroCollapsed());
    debugLog("STINGAR Dashboard initialized");
    debugLog("Version:", process.env.NEXT_PUBLIC_VERSION || "development");
  }, []);

  const toggleIntroCollapsed = () => {
    setIsCollapsed((prev) => {
      const next = !prev;
      writeIntroCollapsed(next);
      return next;
    });
  };

  return (
    <div className="flex flex-col h-full min-h-0">
      <div className="flex items-center justify-between relative flex-shrink-0">
        <h1 className="text-xl font-bold text-left flex-1">
          STINGAR: Shared Threat Intelligence for Network Gatekeeping &
          Automated Response
        </h1>
        <div className="flex items-center gap-2">
          <Button
            onClick={toggleIntroCollapsed}
            variant="outlined"
            size="small"
            sx={{ minWidth: 'auto', padding: '4px 8px' }}
            aria-label={isCollapsed ? "Expand content section" : "Collapse content section"}
            aria-expanded={!isCollapsed}
          >
            {isCollapsed ? '+' : '-'}
          </Button>
          <Link
            href="/kibana"
            target="_blank"
            rel="noopener noreferrer"
            aria-label="Launch Kibana Console (opens in new tab)"
          >
            <Button color="primary" endIcon={<OpenInNewIcon aria-hidden />}>
              Launch Kibana Console
            </Button>
          </Link>
        </div>
      </div>

      {!isCollapsed && (
        <div className="max-w-7xl py-1 flex flex-col gap-4 shrink-0">
          <div className="flex flex-col gap-1">
            <p className="text-sm leading-tight">
              STINGAR enables real time generation of threat intelligence, data
              sharing and action on threat intelligence.
            </p>
            <p className="text-sm leading-tight">
              <a className="font-bold underline text-blue-700" href="/docs/" aria-label="User Documentation">
                User Documentation
              </a>
              {" "} contains a guide to STINGAR and FAQ.
            </p>
            <p className="text-sm leading-tight">
              <a
                className="font-bold underline text-blue-700"
                href="https://join.slack.com/t/stingar/shared_invite/zt-2ili90jaa-b1GFA7t75VF3xs_IoD570A"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Join STINGAR Slack channel (opens in new tab)"
              >
                Join STINGAR Slack channel
              </a>
              {" "} for support questions, to report bugs or make new feature requests.
            </p>
            <p className="text-sm leading-tight">
              <a
                className="font-bold underline text-blue-700"
                href="https://forewarned.io/blog/"
                target="_blank"
                rel="noopener noreferrer"
                aria-label="Visit Forewarned website (opens in new tab)"
              >
                Visit Forewarned website
              </a>
              {" "} for product update announcements and company news.
            </p>
          </div>

          {/* Quick Links Section - WCAG 2.4.5 Multiple Ways */}
          <div className="border-t pt-4">
            <h3 className="text-base font-semibold mb-3">Quick Links</h3>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              <NextLink
                href="/hosts"
                className="p-3 border rounded-md hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                <p className="font-medium text-sm">Manage Hosts</p>
                <p className="text-xs text-gray-600 mt-1">Configure and manage your hosts</p>
              </NextLink>
              <NextLink
                href="/sensors"
                className="p-3 border rounded-md hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                <p className="font-medium text-sm">Manage Honeypots</p>
                <p className="text-xs text-gray-600 mt-1">View and manage honeypot sensors</p>
              </NextLink>
              <NextLink
                href="/sessions"
                className="p-3 border rounded-md hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                <p className="font-medium text-sm">Attack Analysis</p>
                <p className="text-xs text-gray-600 mt-1">View attack sessions and analysis</p>
              </NextLink>
              <NextLink
                href="/deploy"
                className="p-3 border rounded-md hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                <p className="font-medium text-sm">Deploy Honeypot</p>
                <p className="text-xs text-gray-600 mt-1">Deploy new honeypot instances</p>
              </NextLink>
              <NextLink
                href="/settings"
                className="p-3 border rounded-md hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                <p className="font-medium text-sm">Settings</p>
                <p className="text-xs text-gray-600 mt-1">Configure application settings</p>
              </NextLink>
              <NextLink
                href="/users"
                className="p-3 border rounded-md hover:bg-gray-50 transition-colors focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
              >
                <p className="font-medium text-sm">User Management</p>
                <p className="text-xs text-gray-600 mt-1">Manage user accounts</p>
              </NextLink>
            </div>
          </div>
        </div>
      )}

      <Link
        href={KIBANA_DASHBOARD_URL}
        target="_blank"
        rel="noopener noreferrer"
        className="inline-flex items-center gap-1 text-sm text-blue-600 hover:text-blue-800 shrink-0 py-2"
        aria-label="Open dashboard in new tab"
      >
        <OpenInNewIcon fontSize="small" aria-hidden />
        Open dashboard in new tab
      </Link>
      {!isMobile && (
        <div className="relative flex-1 min-h-[max(400px,calc(100vh-220px))] w-full">
          <iframe
            src={KIBANA_DASHBOARD_URL}
            className="absolute inset-0 w-full h-full"
            title="Kibana Dashboard - STINGAR Threat Intelligence Visualization"
          />
        </div>
      )}
    </div>
  );
}
