import {SidebarTrigger} from "@/components/ui/sidebar";
import AccountMenu from "./account-menu";
import Image from "next/image";
import { NavbarSearch } from "./navbar-search";

export function NavBar({
  routes,
}: {
  routes: Array<{
    excludeSidebar?: boolean;
    group: string;
    items: Array<{label: string; icon: string; href: string}>;
  }>;
}) {
  return (
    <header className="flex items-center w-full justify-between p-8 h-[64px] bg-[#363636]" role="banner">
      <SidebarTrigger className="ml-4 mr-8 md:hidden" />
      <div className="w-full flex items-center gap-4">
        <Image
          src="/images/stingar_label_icon.svg"
          alt="STINGAR Logo"
          width={45}
          height={40}
        />
        <span className="text-white text-lg font-bold w-full">
          Forewarned Demo
        </span>
      </div>
      <div className="flex items-center justify-end w-full gap-2">
        <NavbarSearch routes={routes} />
        <AccountMenu />
      </div>
    </header>
  );
}
