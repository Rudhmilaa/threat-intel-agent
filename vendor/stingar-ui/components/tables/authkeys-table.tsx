import * as React from "react";
import { DataGrid, GridColDef, GridRowParams } from "@mui/x-data-grid";
import Paper from "@mui/material/Paper";
import { useHosts, useKeys } from "../hooks/hooks";
import { Copy, LucideMoreVertical, SearchIcon, Trash } from "lucide-react";
import { Button } from "@mui/material";
import { toast } from "sonner";
import DeleteKeyDialog from "../dialogs/delete-key";
import { useHighZoom, useVeryHighZoom } from "../hooks/use-zoom-level";
import { useMemo } from "react";

const getColumns = (isHighZoom: boolean, isVeryHighZoom: boolean, DeleteKeyDialog: any): GridColDef[] => {
  const allColumns: GridColDef[] = [
    { 
      field: "id", 
      headerName: "ID", 
      flex: 0.5, 
      minWidth: isHighZoom ? 40 : 50, 
      headerAlign: "left", 
      align: "left",
    },
    { 
      field: "name", 
      headerName: "Name", 
      flex: 1, 
      minWidth: isHighZoom ? 80 : 100, 
      headerAlign: "left", 
      align: "left" 
    },
    {
      field: "publicKey",
      headerName: isHighZoom ? "Key" : "Public Key",
      flex: 2,
      minWidth: isHighZoom ? 120 : 150,
      headerAlign: "left",
      align: "left",
      renderCell: (params) => (
        <div className="flex items-center justify-start gap-4">
          <span className="truncate">{params.value}</span>
          <Button
            variant="text"
            size={isHighZoom ? "small" : "medium"}
            onClick={async () => {
              try {
                await navigator.clipboard.writeText(params.value);
                toast.success(
                  `Public key '${params.row.name}' copied to clipboard.`
                );
              } catch (err) {
                console.error("Failed to copy: ", err);
                // Handle the error here
                toast.error("Failed to copy public key to clipboard.");
              }
            }}
          >
            <Copy size={isHighZoom ? 16 : 20} />
          </Button>
        </div>
      ),
    },
    {
      field: "hosts",
      headerName: "Hosts",
      flex: 1,
      minWidth: isHighZoom ? 60 : 80,
      headerAlign: "left",
      align: "left",
      type: "number",
    },
    {
      field: "actions",
      type: "actions",
      headerName: isHighZoom ? "Act" : "Actions",
      sortable: false,
      filterable: false,
      hideable: false,
      flex: 1,
      minWidth: isHighZoom ? 70 : 100,
      headerAlign: "left",
      align: "left",
      getActions: (params: GridRowParams) => [
        <DeleteKeyDialog
          key="delete"
          label="Delete"
          showInMenu
          keyId={params.row.id as number}
          keyName={params.row.name as string}
          closeMenuOnClick={false}
        />,
      ],
    },
  ];

  // Filter out columns to hide at very high zoom
  if (isVeryHighZoom) {
    return allColumns.filter(col => col.field !== "id" && col.field !== "hosts");
  }
  
  return allColumns;
};

export default function AuthKeysTable() {
  const isHighZoom = useHighZoom();
  const isVeryHighZoom = useVeryHighZoom();
  const { keys, isLoading, error } = useKeys();
  const { hosts, isLoading: isHostLoading, error: hostError } = useHosts();

  const columns = useMemo(() => getColumns(isHighZoom, isVeryHighZoom, DeleteKeyDialog), [isHighZoom, isVeryHighZoom]);

  // Add a column to display the number of hosts that use the key

  var data: any = [];
  if (keys) {
    const k = keys.forEach((key) => {
      const h = hosts?.filter((host) => host.authkeyId === key.id).length;
      data.push({ ...key, hosts: h });
    });
  }
  return (
    <div style={{ height: 300, width: "100%", overflow: "auto" }} className="data-grid-container">
      <DataGrid
        rows={data ?? []}
        loading={isLoading || isHostLoading}
        columns={columns}
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
