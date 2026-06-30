"use client";

import { useState, useMemo, KeyboardEvent } from "react";
import { useRouter } from "next/navigation";
import { Search, X } from "lucide-react";
import { Button } from "@/components/ui/button";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";

interface Route {
  excludeSidebar?: boolean;
  group: string;
  items: Array<{ label: string; icon: string; href: string }>;
}

interface NavbarSearchProps {
  routes: Route[];
}

export function NavbarSearch({ routes }: NavbarSearchProps) {
  const [isOpen, setIsOpen] = useState(false);
  const [searchQuery, setSearchQuery] = useState("");
  const router = useRouter();

  // Flatten all routes into a searchable list
  const searchableRoutes = useMemo(() => {
    return routes
      .filter((route) => !route.excludeSidebar)
      .flatMap((route) =>
        route.items.map((item) => ({
          label: item.label,
          href: item.href,
          group: route.group || "Main",
        }))
      );
  }, [routes]);

  // Filter routes based on search query
  const filteredRoutes = useMemo(() => {
    if (!searchQuery.trim()) {
      return searchableRoutes;
    }
    const query = searchQuery.toLowerCase();
    return searchableRoutes.filter(
      (route) =>
        route.label.toLowerCase().includes(query) ||
        route.group.toLowerCase().includes(query) ||
        route.href.toLowerCase().includes(query)
    );
  }, [searchQuery, searchableRoutes]);

  const handleSelectRoute = (href: string) => {
    router.push(href);
    setIsOpen(false);
    setSearchQuery("");
  };

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "Escape") {
      setIsOpen(false);
      setSearchQuery("");
    } else if (e.key === "Enter" && filteredRoutes.length > 0) {
      handleSelectRoute(filteredRoutes[0].href);
    }
  };

  return (
    <>
      <Button
        variant="ghost"
        size="sm"
        onClick={() => setIsOpen(true)}
        className="text-white hover:bg-gray-700"
        aria-label="Search pages"
        title="Search pages (Ctrl+K)"
      >
        <Search className="h-5 w-5" aria-hidden="true" />
      </Button>

      <Dialog open={isOpen} onOpenChange={setIsOpen}>
        <DialogContent className="sm:max-w-[600px]">
          <DialogHeader>
            <DialogTitle>Search Pages</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 transform -translate-y-1/2 h-4 w-4 text-gray-400" />
              <Input
                type="text"
                placeholder="Search by page name, group, or path..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleKeyDown}
                className="pl-10"
                autoFocus
                aria-label="Search input"
              />
            </div>

            {searchQuery.trim() && filteredRoutes.length === 0 && (
              <p className="text-sm text-gray-500 text-center py-4">
                No pages found matching &quot;{searchQuery}&quot;
              </p>
            )}

            {filteredRoutes.length > 0 && (
              <div className="border rounded-md max-h-[400px] overflow-y-auto">
                <ul role="listbox" aria-label="Search results">
                  {filteredRoutes.map((route, index) => (
                    <li
                      key={`${route.href}-${index}`}
                      role="option"
                      tabIndex={0}
                      onClick={() => handleSelectRoute(route.href)}
                      onKeyDown={(e) => {
                        if (e.key === "Enter" || e.key === " ") {
                          e.preventDefault();
                          handleSelectRoute(route.href);
                        }
                      }}
                      className="px-4 py-3 hover:bg-gray-100 cursor-pointer focus:bg-gray-100 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:ring-offset-2"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <p className="font-medium text-sm">{route.label}</p>
                          <p className="text-xs text-gray-500 mt-1">
                            {route.group} • {route.href}
                          </p>
                        </div>
                      </div>
                    </li>
                  ))}
                </ul>
              </div>
            )}

            {!searchQuery.trim() && (
              <div className="text-sm text-gray-500">
                <p className="mb-2">Start typing to search for pages...</p>
                <p className="text-xs">
                  You can search by page name, group name, or URL path.
                </p>
              </div>
            )}
          </div>
        </DialogContent>
      </Dialog>
    </>
  );
}
