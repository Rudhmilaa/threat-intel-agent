import React from "react";
import {Button} from "@/components/ui/button";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {toast} from "sonner";
import {useBlocklist} from "@/components/hooks/hooks";
import {deleteBlockedIP} from "@/lib/actions";

export default function DeleteBlockedIpsDialog({
  open,
  setOpen,
}: {
  open: boolean;
  setOpen: (open: boolean) => void;
}) {
  const {mutate} = useBlocklist();
  const handleDeleteIps = () => {
    deleteBlockedIP(-1)
      .then((data) => {
        toast.success(`Deleted ${data.count} address(es).`);
        mutate();
      })
      .catch((err) => {
        toast.error("Unabled to delete addresses: " + err.message);
      });

    setOpen(false);
  };
  return (
    <AlertDialog open={open} onOpenChange={setOpen}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Clear Blocklist</AlertDialogTitle>
          <AlertDialogDescription>
            This action cannot be undone. This will permanently delete all
            blocked IPs.
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button variant="destructive" onClick={handleDeleteIps}>
            Delete
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
