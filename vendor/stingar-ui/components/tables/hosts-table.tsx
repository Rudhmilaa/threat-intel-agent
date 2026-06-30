"use client";

import { useState, useMemo } from "react";
import Button from "@mui/material/Button";
import { Tooltip } from "@mui/material";
import {
  DataGrid,
  GridActionsCellItem,
  GridActionsCellItemProps,
  GridColDef,
  GridRowParams,
} from "@mui/x-data-grid";
import { useHosts, useKeys } from "../hooks/hooks";
import { useHighZoom, useVeryHighZoom } from "../hooks/use-zoom-level";
import { useViewportSize } from "../hooks/use-viewport";
import {
  AlertDialog,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from "@/components/ui/alert-dialog";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { Label } from "../ui/label";
import { deleteHost, updateHost } from "@/lib/actions";
import { toast } from "sonner";
import { useRouter } from "next/navigation";
import { TextField } from "@mui/material";
import { AuthKeyCombobox } from "../authkey-combobox";
import AddKeysDialogButton from "../dialogs/add-keys";
import { Copy } from "lucide-react";

function DeleteHostActionItem({
  hostId,
  hostName,
  ...props
}: GridActionsCellItemProps & { hostId: number; hostName: string }) {
  const [open, setOpen] = useState(false);
  const { mutate } = useHosts();

  const handleDeleteHost = () => {
    deleteHost(hostId.toString())
      .then(() => {
        toast.success(`Host '${hostName}' deleted.`);
        mutate();
      })
      .catch((error) => {
        toast.error(`Failed to delete host '${hostName}'`);
      });
    setOpen(false);
  };
  return (
    <>
      <GridActionsCellItem {...props} onClick={() => setOpen(true)} />
      <AlertDialog
        open={open}
        onOpenChange={() => {
          setOpen(false);
        }}
      >
        <AlertDialogContent>
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Honeypot Host?</AlertDialogTitle>
            <AlertDialogDescription>
              This action cannot be undone. This will permanently delete
              honeypot host: <Label className="font-bold">{hostName}</Label>
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel>Cancel</AlertDialogCancel>
            <Button onClick={handleDeleteHost}>Delete</Button>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}

type newHost = {
  address: string;
  sshPort: string;
  username: string;
  authkeyId: string;
};

function UpdateHostActionItem({
  host,
  ...props
}: GridActionsCellItemProps & { host: any }) {
  const [open, setOpen] = useState(false);
  const { keys, isLoading, error } = useKeys();
  const { mutate } = useHosts();
  // Host configurations
  const [newHost, setNewHost] = useState<newHost>({
    address: host.address,
    sshPort: String(host.sshPort),
    username: host.username,
    authkeyId: String(host.authkeyId),
  });
  const handleDialogOpenChange = (isOpen: boolean) => {
    if (!isOpen) {
      // Dialog is closing, do anything here.
      setNewHost({
        address: "",
        sshPort: "",
        username: "",
        authkeyId: "",
      });
    }
    setOpen(isOpen);
  };
  const copyToClipboard = async () => {
    try {
      const key = keys?.find((k) => k.id === parseInt(newHost.authkeyId));
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
  const handleUpdateHost = () => {
    // TODO: Validate inputs
    const data = {
      address: newHost.address,
      sshPort: parseInt(newHost.sshPort),
      username: newHost.username,
      authkeyId: parseInt(newHost.authkeyId),
    };
    updateHost(String(host.id), data)
      .then((host) => {
        toast.success("Successfully updated host: " + host.address);
        mutate();
        handleDialogOpenChange(false);
      })
      .catch((err) => {
        toast.error("Failed to update host");
      });
  };
  return (
    <>
      <GridActionsCellItem {...props} onClick={() => setOpen(true)} />
      <Dialog open={open} onOpenChange={handleDialogOpenChange}>
        <DialogContent
          onKeyDown={(event) => {
            event.stopPropagation(); // Prevent focus from leaving the dialog
          }}
        >
          <DialogHeader>
            <DialogTitle>Update Honeypot Host</DialogTitle>
            <DialogDescription>
              Please enter the host configuration details.
            </DialogDescription>
          </DialogHeader>
          <div className="grid items-center w-full gap-4">
            <div>
              <TextField
                className="w-full"
                label="Hostname/IP"
                value={newHost.address}
                onChange={(e) =>
                  setNewHost({ ...newHost, address: e.target.value })
                }
              />
            </div>
            <div>
              <TextField
                className="w-full"
                label="SSH Port"
                value={newHost.sshPort}
                onChange={(e) => {
                  const { value } = e.target;
                  // This regular expression allows only numbers or an empty string
                  if (value === "" || /^[0-9]+$/.test(value)) {
                    setNewHost({ ...newHost, sshPort: value });
                  }
                }}
              />
            </div>
            <div>
              <TextField
                className="w-full"
                label="Username"
                value={newHost.username}
                onChange={(e) => {
                  const updatedValue = e.target.value;
                  setNewHost((prevState) => ({
                    ...prevState,
                    username: updatedValue,
                  }));
                }}
              />
            </div>
            <div className="flex items-center gap-2">
              <AuthKeyCombobox
                className="flex-1 border-black"
                defaultValue={host.authkeyId.toString()}
                onValueChange={(val) =>
                  setNewHost({ ...newHost, authkeyId: val })
                }
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
                newHost.address.trim().length === 0 ||
                newHost.sshPort.trim().length === 0 ||
                newHost.username.trim().length === 0 ||
                newHost.authkeyId.trim().length === 0
              }
              onClick={() => {
                handleUpdateHost();
              }}
            >
              Update Host
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </>
  );
}

const getColumns = (isHighZoom: boolean, isVeryHighZoom: boolean, viewportSize: 'mobile' | 'tablet' | 'desktop', UpdateHostActionItem: any, DeleteHostActionItem: any): GridColDef[] => {
  const allColumns: GridColDef[] = [
    { 
      field: "uuid", 
      headerName: "UUID", 
      flex: 1, 
      minWidth: isHighZoom ? 80 : 100, 
      headerAlign: "left", 
      align: "left",
      renderCell: (params) => {
        const value = params.value || "N/A";
        return (
          <Tooltip title={value} arrow placement="top">
            <div
              style={{
                width: '100%',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {value}
            </div>
          </Tooltip>
        );
      },
    },
    {
      field: "created",
      headerName: (viewportSize === 'mobile' && isVeryHighZoom) ? "DATE" : "Created",
      flex: 1,
      minWidth: isHighZoom ? 80 : 100,
      headerAlign: "left",
      align: "left",
      type: "date",
      valueFormatter: (params) => new Date(params as string).toLocaleDateString(),
    },
    { 
      field: "address", 
      headerName: isHighZoom ? "Host" : "Hostname/IP", 
      flex: 1, 
      minWidth: isHighZoom ? 100 : 120, 
      headerAlign: "left", 
      align: "left",
      renderCell: (params) => {
        const value = params.value || "N/A";
        return (
          <Tooltip title={value} arrow placement="top">
            <div
              style={{
                width: '100%',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {value}
            </div>
          </Tooltip>
        );
      },
    },
    { 
      field: "username", 
      headerName: isHighZoom ? "User" : "Username", 
      flex: 1, 
      minWidth: isHighZoom ? 80 : 100, 
      headerAlign: "left", 
      align: "left",
      renderCell: (params) => {
        const value = params.value || "N/A";
        return (
          <Tooltip title={value} arrow placement="top">
            <div
              style={{
                width: '100%',
                overflow: 'hidden',
                textOverflow: 'ellipsis',
                whiteSpace: 'nowrap',
              }}
            >
              {value}
            </div>
          </Tooltip>
        );
      },
    },
    { 
      field: "sshPort", 
      headerName: isHighZoom ? "Port" : "SSH Port", 
      flex: 0.8, 
      minWidth: isHighZoom ? 60 : 80, 
      headerAlign: "left", 
      align: "left" 
    },
    { 
      field: "authkeyId", 
      headerName: isHighZoom ? "Key ID" : "AuthKey ID", 
      flex: 0.9, 
      minWidth: isHighZoom ? 70 : 100, 
      headerAlign: "left", 
      align: "left",
    },
    {
      field: "actions",
      type: "actions",
      headerName: "Actions",
      flex: 0.8,
      minWidth: isHighZoom ? 70 : 100,
      headerAlign: "left",
      align: "left",
      getActions: (params: GridRowParams) => [
        <UpdateHostActionItem
          key="update"
          label="Update"
          showInMenu
          host={params.row}
          closeMenuOnClick={false}
        />,
        <DeleteHostActionItem
          key="delete"
          label="Delete"
          showInMenu
          hostId={params.row.id as number}
          hostName={params.row.address as string}
          closeMenuOnClick={false}
        />,
      ],
    },
  ];

  // Mobile viewport: Always show only 3 columns (Created, Host, Actions) regardless of zoom
  if (viewportSize === 'mobile') {
    return allColumns.filter(col => 
      col.field === "created" || 
      col.field === "address" || 
      col.field === "actions"
    );
  }

  // Tablet viewport: Reduce columns based on zoom
  if (viewportSize === 'tablet') {
    // At 150%+ zoom, show only 3 columns
    if (isVeryHighZoom) {
      return allColumns.filter(col => 
        col.field === "created" || 
        col.field === "address" || 
        col.field === "actions"
      );
    }
    // At 125%+ zoom, reduce columns (hide UUID, AuthKey ID)
    if (isHighZoom) {
      return allColumns.filter(col => 
        col.field !== "uuid" && col.field !== "authkeyId"
      );
    }
    // At 100% zoom, show most columns (hide UUID)
    return allColumns.filter(col => col.field !== "uuid");
  }

  // Desktop viewport: Show all columns at 100%, reduce based on zoom
  // At 150%+ zoom, show only 3 columns
  if (isVeryHighZoom) {
    return allColumns.filter(col => 
      col.field === "created" || 
      col.field === "address" || 
      col.field === "actions"
    );
  }
  
  // At 125%+ zoom, reduce columns (hide UUID, AuthKey ID)
  if (isHighZoom) {
    return allColumns.filter(col => 
      col.field !== "uuid" && col.field !== "authkeyId"
    );
  }
  
  // At 100% zoom, show all columns
  return allColumns;
};

export default function HostsTable() {
  const { hosts, isLoading, error } = useHosts();
  const router = useRouter();
  const isHighZoom = useHighZoom();
  const isVeryHighZoom = useVeryHighZoom();
  const viewportSize = useViewportSize();

  // Memoize columns based on zoom level and viewport size
  const columns = useMemo(
    () => getColumns(isHighZoom, isVeryHighZoom, viewportSize, UpdateHostActionItem, DeleteHostActionItem),
    [isHighZoom, isVeryHighZoom, viewportSize]
  );

  // Handle row selection
  const handleRowSelectionChange = (params: GridRowParams) => {
    router.push(`/hosts/view/${params.row.id}`);
  };

  return (
    <div style={{ height: 300, width: "100%", overflow: "auto" }} className="data-grid-container">
      <DataGrid
        rows={hosts ?? []}
        columns={columns}
        loading={isLoading}
        initialState={{
          sorting: {
            sortModel: [{ field: "created", sort: "desc" }],
          },
        }}
        sx={{
          "& .MuiDataGrid-cell": {
            minWidth: 0,
            maxWidth: "none",
            overflow: "hidden",
            textOverflow: "ellipsis",
            justifyContent: "flex-start",
            paddingLeft: isHighZoom ? "8px !important" : "16px !important",
            paddingRight: isHighZoom ? "8px !important" : "16px !important",
            display: "flex",
            alignItems: "center",
            fontSize: isHighZoom ? "0.875rem" : "1rem",
          },
          "& .MuiDataGrid-columnHeader": {
            minWidth: 0,
            maxWidth: "none",
            justifyContent: "flex-start",
            paddingLeft: isHighZoom ? "8px !important" : "16px !important",
            paddingRight: isHighZoom ? "8px !important" : "16px !important",
            display: "flex",
            alignItems: "center",
            "& .MuiDataGrid-columnHeaderTitleContainer": {
              padding: "0 !important",
              margin: 0,
              justifyContent: "flex-start",
              display: "flex",
              alignItems: "center",
              width: "100%",
            },
            "& .MuiDataGrid-columnHeaderTitle": {
              textAlign: "left",
              padding: "0 !important",
              margin: 0,
              lineHeight: "1.5",
              fontSize: isHighZoom ? "0.875rem" : "1rem",
            },
          },
          // Ensure sort icon doesn't affect alignment - position it absolutely
          "& .MuiDataGrid-iconButtonContainer": {
            marginLeft: isHighZoom ? "2px" : "4px",
            position: "relative",
            flexShrink: 0,
          },
          // Ensure column separators align
          "& .MuiDataGrid-columnSeparator": {
            display: "none",
          },
        }}
      />
    </div>
  );
}
