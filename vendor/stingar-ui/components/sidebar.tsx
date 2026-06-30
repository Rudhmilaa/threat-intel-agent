"use client";

import Image from "next/image";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useEffect, useRef } from "react";
import { X } from "lucide-react";

import {
  Sidebar,
  SidebarContent,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  useSidebar,
} from "@/components/ui/sidebar";
import { Button } from "@/components/ui/button";
import { Icon } from "./icon";
import { useStoreCountContext } from "@/lib/hooks/use-store-count-context";
import { useStoreEnabled } from "@/lib/hooks/use-store";
import { useSystemVersion } from "@/lib/hooks/use-system-version";
import { useUpdateCheck } from "@/lib/hooks/use-update-check";
import { useIsMobile } from "@/components/hooks/use-mobile";

export function AppSidebar({
  routes,
}: {
  routes: Array<{
    excludeSidebar?: boolean;
    group: string;
    items: Array<{ label: string; icon: string; href: string }>;
  }>;
}) {
  const pathname = usePathname();
  const { count, loading, error, refetch } = useStoreCountContext();
  const { isEnabled: storeEnabled, isLoading: enabledLoading } = useStoreEnabled();
  const { version: systemVersion, loading: versionLoading } = useSystemVersion();
  const { updateAvailable } = useUpdateCheck();
  const { setOpenMobile } = useSidebar();
  const isMobile = useIsMobile();
  const r = routes.filter((route) => !route.excludeSidebar);

  // Refetch count when store becomes enabled (only once, not on every loading change)
  const hasRefetchedRef = useRef(false);
  useEffect(() => {
    // Only refetch when store becomes enabled for the first time
    if (storeEnabled && !enabledLoading && !hasRefetchedRef.current) {
      hasRefetchedRef.current = true;
      refetch();
    }
    // Reset refetch flag if store becomes disabled
    if (!storeEnabled) {
      hasRefetchedRef.current = false;
    }
  }, [storeEnabled, enabledLoading, refetch]);
  return (
    <Sidebar style={{ border: 0 }} collapsible="icon">
      <SidebarHeader>
        <div className="flex flex-col items-center justify-center p-2 relative">
          {/* Close button for mobile mode */}
          {isMobile && (
            <Button
              variant="ghost"
              size="icon"
              className="absolute top-2 left-2 h-8 w-8 text-sidebar-foreground hover:bg-sidebar-accent hover:text-sidebar-accent-foreground"
              onClick={() => setOpenMobile(false)}
              aria-label="Close sidebar"
            >
              <X className="h-5 w-5" />
            </Button>
          )}
          <Link href={routes[0].items[0].href} aria-label="Go to Dashboard">
            <Image
              src="/images/stingar_label.svg"
              alt="STINGAR Logo"
              width={175}
              height={100}
            />
          </Link>
          <label className={"flex text-[12px] justify-center w-[175px]"}>
            {versionLoading
              ? '...'
              : systemVersion
                ? `Version ${systemVersion}`
                : `Version ${process.env.NEXT_PUBLIC_VERSION || 'unknown'}`}
          </label>
        </div>
      </SidebarHeader>
      <SidebarContent className="gap-0">
        <SidebarGroup className="pt-0">
          {r.map((group) => (
            <SidebarGroup key={group.group} className="py-1">
              <SidebarGroupLabel className="px-2 py-1 text-sm font-medium">{group.group}</SidebarGroupLabel>
              <SidebarGroupContent>
                <SidebarMenu>
                  {group.items.map((item) => (
                    <SidebarMenuItem key={item.label}>
                      <SidebarMenuButton
                        asChild
                        isActive={pathname === item.href}
                        className="py-3 text-base h-16 min-h-16 flex-shrink-0 [&>svg]:!size-10 [&>svg]:shrink-0"
                      >
                        <Link
                          href={
                            item.label === "Settings" && updateAvailable
                              ? "/settings?tab=updates"
                              : item.href
                          }
                          className="relative flex items-center w-full h-full focus-visible:outline-none focus-visible:ring-0 focus-visible:z-10 focus-visible:rounded-md"
                          aria-label={item.label}
                        >
                          <Icon className="mr-3 shrink-0" iconId={item.icon} size="10" ariaLabel={undefined} />
                          <span className="font-medium text-base">{item.label}</span>
                          {/* Badge for Honeypot Store - only show if REMOTE_STORE_ENABLED is true */}
                          {item.label === "Honeypot Store" && storeEnabled && !enabledLoading && (
                            <div className="absolute top-1 right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center font-bold z-10">
                              {loading ? '?' : (error ? '!' : (count !== null ? (count > 99 ? '99+' : count.toString()) : '?'))}
                            </div>
                          )}
                          {/* Badge for Settings when update available */}
                          {item.label === "Settings" && updateAvailable && (
                            <div className="absolute top-1 right-1 bg-red-500 text-white text-xs rounded-full h-5 w-5 flex items-center justify-center font-bold z-10" aria-label="Update available">
                              *
                            </div>
                          )}
                        </Link>
                      </SidebarMenuButton>
                    </SidebarMenuItem>
                  ))}
                </SidebarMenu>
              </SidebarGroupContent>
            </SidebarGroup>
          ))}
        </SidebarGroup>
      </SidebarContent>
    </Sidebar>
  );
}
