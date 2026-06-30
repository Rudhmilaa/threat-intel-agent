import React, {useState} from "react";
import {Button, TextField} from "@mui/material";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import {Label} from "../ui/label";
import {Input} from "../ui/input";
import Tooltip from "@mui/material";

import {newHost} from "@/models/hosts";
import {AuthKeyCombobox} from "../authkey-combobox";
import {Copy, PlusIcon} from "lucide-react";
import AddKeysDialogButton from "./add-keys";
import {toast} from "sonner";
import {useHosts, useKeys} from "@/components/hooks/hooks";
import {createHost} from "@/lib/actions";

type newHost = {
  address: string;
  sshPort: string;
  username: string;
  authkeyId: string;
};

function AddHostDialogButton({className}: {className?: string}) {
  const {keys, isLoading, error} = useKeys();
  const {mutate} = useHosts();
  const [open, setOpen] = useState(false);
  const handleDialogOpenChange = (isOpen: boolean) => {
    if (!isOpen) {
      // Dialog is closing, do anything here.
      setHost({
        address: "",
        sshPort: "",
        username: "",
        authkeyId: "",
      });
    }
    setOpen(isOpen);
  };

  // Host configurations
  const [host, setHost] = useState<newHost>({
    address: "",
    sshPort: "",
    username: "",
    authkeyId: "",
  });

  // Add host
  const handleAddHost = () => {
    // TODO: Validate inputs
    const data = {
      address: host.address,
      sshPort: parseInt(host.sshPort),
      username: host.username,
      authkeyId: parseInt(host.authkeyId),
    };
    createHost(data)
      .then((host) => {
        toast.success("Successfully added new host: " + host.address);
        mutate();
      })
      .catch((err) => {
        toast.error("Failed to add new host");
      });
    handleDialogOpenChange(false);
  };

  const copyToClipboard = async () => {
    try {
      const key = keys?.find((k) => k.id === parseInt(host.authkeyId));
      if (!key) {
        toast.error("Failed to copy public key to clipboard: no key selected.");
        return;
      }
      await navigator.clipboard.writeText(key.publicKey);
      toast.success(`Public key '${key.name}' copied to clipboard.`);
    } catch (err) {
      toast.error("Failed to copy public key to clipboard.");
    }
  };
  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <PlusIcon size={20} />
        <span className="ml-2">Add Host</span>
      </Button>
      <Dialog open={open} onOpenChange={handleDialogOpenChange}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Add Honeypot Host</DialogTitle>
            <DialogDescription>
              Please enter the host configuration details.
            </DialogDescription>
          </DialogHeader>
          <div className="grid items-center w-full gap-4">
            <div>
              <TextField
                className="w-full"
                label="Hostname/IP"
                value={host.address}
                onChange={(e) => setHost({...host, address: e.target.value})}
              />
            </div>
            <div>
              <TextField
                className="w-full"
                label="SSH Port"
                value={host.sshPort}
                onChange={(e) => {
                  const {value} = e.target;
                  // This regular expression allows only numbers or an empty string
                  if (value === "" || /^[0-9]+$/.test(value)) {
                    setHost({...host, sshPort: value});
                  }
                }}
              />
            </div>
            <div>
              <TextField
                className="w-full"
                label="Username"
                value={host.username}
                onChange={(e) => setHost({...host, username: e.target.value})}
              />
            </div>
            <div className="flex items-center gap-2">
              <AuthKeyCombobox
                className="flex-1 border-black"
                onValueChange={(val) => setHost({...host, authkeyId: val})}
              />
              <Button
                variant="outlined"
                onClick={copyToClipboard}
                color="neutral"
              >
                <Copy />
              </Button>
              <AddKeysDialogButton
                variant="outlined"
                color="neutral"
                className="ml-4"
              />
            </div>
          </div>
          <DialogFooter className="mt-4">
            <Button
              disabled={
                host.address.trim().length === 0 ||
                host.sshPort.trim().length === 0 ||
                host.username.trim().length === 0 ||
                host.authkeyId.trim().length === 0
              }
              onClick={() => {
                handleAddHost();
              }}
            >
              Add Host
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

export default AddHostDialogButton;
