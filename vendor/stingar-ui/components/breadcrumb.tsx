"use client";

import {Link} from "@mui/material";
import Breadcrumb from "@mui/material/Breadcrumbs";
import {usePathname} from "next/navigation";
import NavigateNextIcon from "@mui/icons-material/NavigateNext";

type Routes = Array<{
  group: string;
  items: Array<{label: string; icon: string; href: string}>;
}>;

function generateBreadcrumbs(routes: Routes, pathname: string) {
  const pathSegments = pathname.split("/").filter((segment) => segment);
  const breadcrumbs = [];

  // Find the matching route
  const matchingRoute = routes.find((route) =>
    route.items.some((item) => pathname.startsWith(item.href))
  );

  // Add "Home" breadcrumb if the path is not in a group or the group is empty
  if (!matchingRoute || matchingRoute.group === "") {
    breadcrumbs.push({label: "Home", href: "/dashboard"});
  } else {
    // Make group breadcrumb clickable - navigate to first item in group
    const firstItemInGroup = matchingRoute.items[0];
    breadcrumbs.push({
      label: matchingRoute.group,
      href: firstItemInGroup ? firstItemInGroup.href : "#"
    });
  }

  // Find the matching item in the route
  const matchingItem = matchingRoute
    ? matchingRoute.items.find((item) => item.href.includes(pathSegments[0]))
    : null;

  if (matchingItem) {
    breadcrumbs.push({label: matchingItem.label, href: matchingItem.href});

    // Check if there's a segment after /sessions, /deployments, or /sensors
    const viewPaths = ["/sessions", "/deployments", "/sensors"];
    if (viewPaths.includes(matchingItem.href) && pathSegments.length > 1) {
      breadcrumbs.push({label: "View", href: pathname});
    }
  }

  // Handle the last segment if it's not already covered
  const lastSegment = pathSegments[pathSegments.length - 1];
  if (
    lastSegment &&
    lastSegment !== matchingItem?.href.slice(1) &&
    !breadcrumbs.some((crumb) => crumb.label === "View")
  ) {
    breadcrumbs.push({label: lastSegment, href: pathname});
  }

  return breadcrumbs;
}

export function Breadcrumbs({routes}: {routes: Routes}) {
  const pathname = usePathname();
  const breadcrumbs = generateBreadcrumbs(routes, pathname);
  return (
    <Breadcrumb
      separator={<NavigateNextIcon fontSize="small" />}
      aria-label="breadcrumb"
    >
      {breadcrumbs.map((crumb, i) => {
        // Make all breadcrumbs clickable, except if href is "#" (placeholder)
        const isClickable = crumb.href !== "#";
        return isClickable ? (
          <Link key={i} underline="hover" color="inherit" href={crumb.href}>
            {crumb.label}
          </Link>
        ) : (
          <span key={i}>{crumb.label}</span>
        );
      })}
    </Breadcrumb>
  );
}
