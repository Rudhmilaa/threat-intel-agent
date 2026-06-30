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
import {useUsers} from "@/components/hooks/hooks";
import {deleteUser} from "@/lib/actions";
import {GridActionsCellItem, GridActionsCellItemProps} from "@mui/x-data-grid";

export default function DeleteUserDialog({
  userId,
  username,
  ...props
}: GridActionsCellItemProps & {userId: number; username: string}) {
  const [open, setOpen] = React.useState(false);
  const {mutate} = useUsers();
  const handleDeleteUser = () => {
    deleteUser(userId.toString())
      .then(() => {
        toast.success("User '" + username + "' deleted.");
        mutate();
      })
      .catch((error) => {
        toast.error("Error deleting user: " + error.message);
      });
    setOpen(false);
  };

  return (
    <>
      <GridActionsCellItem {...props} onClick={() => setOpen(true)} />
      <AlertDialog open={open} onOpenChange={setOpen}>
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete User?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete user:{" "}
              <Label className="font-bold">{username}</Label>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button variant="destructive" onClick={handleDeleteUser}>
              Delete
            </Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
