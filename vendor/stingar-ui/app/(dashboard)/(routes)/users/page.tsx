"use client";

import React from "react";
import { Stack, Typography, Button } from "@mui/material";
import UsersTable from "@/components/tables/users-table";
import AddUserDialogButton from "@/components/dialogs/add-user";

function Users() {
  return (
    <div className="flex flex-col max-h-full w-full overflow-x-hidden max-w-full">
      <div className="flex items-center justify-between pb-4">
        <h1 className="text-xl font-bold">Users</h1>
        <AddUserDialogButton />
      </div>
      <div className="w-full max-w-full overflow-x-auto">
        <UsersTable />
      </div>
    </div>
  );
}

export default Users;

