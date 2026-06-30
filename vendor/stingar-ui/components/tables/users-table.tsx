import * as React from "react";
import {DataGrid, GridColDef, GridRowParams} from "@mui/x-data-grid";
import Paper from "@mui/material/Paper";
import {Tooltip} from "@mui/material";
import {useKeys, useUsers} from "../hooks/hooks";
import {Copy, LucideMoreVertical, SearchIcon, Trash} from "lucide-react";
import {Button} from "@mui/material";
import {toast} from "sonner";
import DeleteKeyDialog from "../dialogs/delete-key";
import DeleteUserDialog from "../dialogs/delete-user";
import { useHighZoom, useVeryHighZoom } from "../hooks/use-zoom-level";
import { useMemo } from "react";

const getColumns = (isHighZoom: boolean, isVeryHighZoom: boolean, DeleteUserDialog: any): GridColDef[] => {
  const allColumns: GridColDef[] = [
    {
      field: "created",
      headerName: "Created",
      flex: 1,
      minWidth: isHighZoom ? 80 : 100,
      headerAlign: "left",
      align: "left",
      filterable: false,
      sortable: false,
      valueFormatter: (params) => {
        return new Date(params as string).toLocaleDateString();
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
      field: "email",
      headerName: "Email",
      flex: 1,
      minWidth: isHighZoom ? 120 : 150,
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
      field: "actions",
      type: "actions",
      headerName: isHighZoom ? "Act" : "Actions",
      sortable: false,
      filterable: false,
      hideable: false,
      flex: 0.8,
      minWidth: isHighZoom ? 70 : 100,
      headerAlign: "left",
      align: "left",
      getActions: (params: GridRowParams) => [
        <DeleteUserDialog
          key="delete"
          label="Delete"
          disabled={params.row.username === "admin"}
          showInMenu
          userId={params.row.id as number}
          username={params.row.username as string}
          closeMenuOnClick={false}
        />,
      ],
    },
  ];

  // Filter out columns to hide at very high zoom
  if (isVeryHighZoom) {
    return allColumns.filter(col => col.field !== "created");
  }
  
  return allColumns;
};

export default function UsersTable() {
  const isHighZoom = useHighZoom();
  const isVeryHighZoom = useVeryHighZoom();
  const {users, isLoading, error} = useUsers();
  const columns = useMemo(() => getColumns(isHighZoom, isVeryHighZoom, DeleteUserDialog), [isHighZoom, isVeryHighZoom]);
  return (
    <div style={{width: "100%", overflow: "auto"}} className="data-grid-container">
      <DataGrid 
        rows={users ?? []} 
        loading={isLoading} 
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
