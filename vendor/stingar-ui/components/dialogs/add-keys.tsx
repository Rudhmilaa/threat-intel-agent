import {useState} from "react";
import {Button} from "@mui/material";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {Input} from "../ui/input";
import {cn} from "@/lib/utils";
import {toast} from "sonner";
import {useKeys} from "@/components/hooks/hooks";
import {createKey} from "@/lib/actions";
import {AuthKey} from "@/models/authKeys";
import {PlusIcon} from "lucide-react";

function AddKeysDialogButton({
  className,
  color = "primary",
  variant = "contained",
}: {
  className?: string;
  color?: "primary" | "neutral";
  variant?: "outlined" | "contained" | "text";
}) {
  const {keys, mutate} = useKeys();

  const [open, setOpen] = useState(false);
  const handleDialogOpenChange = (isOpen: boolean) => {
    if (!isOpen) {
      // Dialog is closing, do anything here.
      setKeyName("");
    }
    setOpen(isOpen);
  };

  const [keyName, setKeyName] = useState("");
  const handleAddkey = () => {
    if (keyName.trim().length > 0) {
      const exists = keys?.find((key) => key.name === keyName);
      if (exists) {
        toast.error("Key with name '" + keyName + "' already exists.");
        return;
      }

      createKey(keyName)
        .then((key) => {
          mutate();
          toast.success("Successfully added key: " + key.name);
        })
        .catch((err) => {
          toast.error("Failed to add key: " + keyName);
        });
    }
    handleDialogOpenChange(false);
  };
  return (
    <>
      <Button variant={variant} color={color} onClick={() => setOpen(true)}>
        <PlusIcon size="18" />
        <span className="ml-2">Add Key</span>
      </Button>
      <Dialog open={open} onOpenChange={handleDialogOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Authentication Key</DialogTitle>
            <DialogDescription>
              Please provide the name of the new authentication key.
            </DialogDescription>
          </DialogHeader>
          <div>
            <Input
              className={cn("w-full rounded-md shadow-sm sm:text-sm")}
              placeholder="Enter key name"
              value={keyName}
              onChange={(e) => setKeyName(e.target.value)}
            />
          </div>
          <DialogFooter>
            <Button
              disabled={keyName.trim().length === 0}
              onClick={() => {
                handleAddkey();
              }}
            >
              Add Key
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default AddKeysDialogButton;
