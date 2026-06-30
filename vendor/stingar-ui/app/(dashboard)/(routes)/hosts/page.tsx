"use client";

import AddHostDialogButton from "@/components/dialogs/add-host";
import AddKeysDialogButton from "@/components/dialogs/add-keys";
import AuthKeysTable from "@/components/tables/authkeys-table";
import HostsTable from "@/components/tables/hosts-table";

export default function Hosts() {
  return (
    <div className="flex flex-col gap-11 overflow-x-hidden max-w-full">
      <div>
        <div className="flex items-center justify-between">
          <h1 className="text-xl font-bold">Manage Hosts</h1>
          <AddHostDialogButton />
        </div>
        <div className="flex flex-col gap-8 mt-4">
          <div className="w-full max-w-full overflow-x-auto">
            <HostsTable />
          </div>
        </div>
      </div>
      <div>
        <div className="flex items-center justify-between">
          <h2 className="text-xl font-bold">Manage Keys</h2>
          <AddKeysDialogButton />
        </div>
        <div className="flex flex-col gap-8 mt-4">
          <div className="w-full max-w-full overflow-x-auto">
            <AuthKeysTable />
          </div>
        </div>
      </div>
    </div>
  );
}
