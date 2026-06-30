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
import {Label} from "../ui/label";
import {toast} from "sonner";
import {useHosts} from "@/components/hooks/hooks";
import {deleteHost} from "@/lib/actions";

function DeleteHostDialog({id, name}: {id: number; name: string}) {
  const [open, setOpen] = React.useState(false);
  const {mutate} = useHosts();
  const handleDialogOpenChange = (isOpen: boolean) => {
    if (!isOpen) {
      // Dialog is closing, do anything here.
    }
    setOpen(isOpen);
  };

  const handleDeleteHost = () => {
    deleteHost(id.toString())
      .then(() => {
        toast.success(`Host '${name}' deleted.`);
        mutate();
      })
      .catch((error) => {
        toast.error(`Failed to delete host '${name}'`);
      });
    handleDialogOpenChange(false);
  };
  return (
    <AlertDialog open={open} onOpenChange={handleDialogOpenChange}>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>Delete Honeypot Host?</AlertDialogTitle>
          <AlertDialogDescription>
            This action cannot be undone. This will permanently delete honeypot
            host: <Label className="font-bold">{name}</Label>
          </AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel>Cancel</AlertDialogCancel>
          <Button variant="destructive" onClick={handleDeleteHost}>
            Delete
          </Button>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}

export default DeleteHostDialog;
