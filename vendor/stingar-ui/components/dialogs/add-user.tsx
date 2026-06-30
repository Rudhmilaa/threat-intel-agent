"use client";

import { useState } from "react";
import { Button } from "@mui/material";
import {
  Dialog,
  DialogContent,
  DialogTitle,
} from "@/components/ui/dialog";
import { PlusIcon } from "lucide-react";
import { AddUserForm } from "@/app/(dashboard)/(routes)/users/form";
import { useUsers } from "@/components/hooks/hooks";

function AddUserDialogButton({
  className,
  variant = "contained",
}: {
  className?: string;
  variant?: "outlined" | "contained" | "text";
}) {
  const { mutate } = useUsers();
  const [open, setOpen] = useState(false);

  const handleClickOpen = () => {
    setOpen(true);
  };

  const handleClose = () => {
    setOpen(false);
  };

  const handleSuccess = () => {
    handleClose();
    mutate();
  };

  return (
    <>
      <Button variant={variant} onClick={handleClickOpen}>
        <PlusIcon size="18" />
        <span className="ml-2">Add User</span>
      </Button>
      <Dialog open={open} onOpenChange={setOpen}>
        <DialogTitle>Add New User</DialogTitle>
        <DialogContent>
          <AddUserForm onSuccess={handleSuccess} />
        </DialogContent>
      </Dialog>
    </>
  );
}

export default AddUserDialogButton;
