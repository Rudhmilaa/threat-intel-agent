"use client";

import SensorsTable from "@/components/tables/sensors-table";

export default function Sensors() {
  return (
    <div className="flex flex-col max-h-full w-full overflow-x-hidden max-w-full">
      <h1 className="pb-4 text-xl font-bold">Manage Honeypots</h1>
      <div className="w-full max-w-full overflow-x-auto">
        <SensorsTable />
      </div>
    </div>
  );
}
