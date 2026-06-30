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
import {useHosts, useKeys} from "@/components/hooks/hooks";
import {deleteKey} from "@/lib/actions";
import {GridActionsCellItem, GridActionsCellItemProps} from "@mui/x-data-grid";

export default function DeleteKeyDialog({
  keyId,
  keyName,
  ...props
}: GridActionsCellItemProps & {keyId: number; keyName: string}) {
  const [open, setOpen] = React.useState(false);
  const {mutate} = useKeys();
  const {hosts, isLoading} = useHosts();
  const handleDeletekey = () => {
    // Check if key is in use
    const inUse = hosts?.some((host) => host.authkeyId === keyId);
    if (inUse) {
      toast.error("Cannot delete: '" + keyName + "'. Key is in use.");
      setOpen(false);
      return;
    }

    deleteKey(keyId.toString())
      .then(() => {
        toast.success("Key '" + keyName + "' deleted.");
        mutate();
      })
      .catch((error) => {
        toast.error("Error deleting key: " + error.message);
      });
    setOpen(false);
  };

  if (isLoading) {
    return null;
  }
  return (
    <>
      <GridActionsCellItem {...props} onClick={() => setOpen(true)} />
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Authentication Key?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete
              authentication key: <Label className="font-bold">{keyName}</Label>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button variant="destructive" onClick={handleDeletekey}>
              Delete
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
