"use client";

import DeploymentsTable from "@/components/tables/deployments-table";

export default function Deployments() {
  return (
    <div className="flex flex-col max-h-full w-full overflow-x-hidden max-w-full">
      <h1 className="pb-4 text-xl font-bold">Honeypot Deployments</h1>
      <div className="w-full max-w-full overflow-x-auto">
        <DeploymentsTable />
      </div>
    </div>
  );
}
