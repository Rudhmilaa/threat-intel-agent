import React, { useMemo } from "react";
import {useDeployments} from "@/components/hooks/hooks";
import {DataGrid, GridColDef, GridRowParams} from "@mui/x-data-grid";
import {Chip, Tooltip} from "@mui/material";
import {useRouter} from "next/navigation";
import {statusMap} from "@/models/deployments";
import { useHighZoom, useVeryHighZoom } from "../hooks/use-zoom-level";
import { useViewportSize } from "../hooks/use-viewport";

const getColumns = (isHighZoom: boolean, isVeryHighZoom: boolean, viewportSize: 'mobile' | 'tablet' | 'desktop'): GridColDef[] => {
  const allColumns: GridColDef[] = [
    {
      field: "created",
      headerName: isHighZoom ? "DATE" : "Deployed",
      flex: 1,
      minWidth: isHighZoom ? 100 : 140,
      headerAlign: "left",
      align: "left",
      type: "date",
      valueFormatter: (params) => {
        const date = new Date(params as string);
        return isHighZoom ? date.toLocaleDateString() : date.toLocaleString();
      },
    },
    {
      field: "status",
      headerName: isHighZoom ? "STATUS" : "Status",
      flex: 0.8,
      minWidth: isHighZoom ? 80 : 100,
      headerAlign: "left",
      align: "left",
      valueGetter: (params: number) => {
        return statusMap[params] || "Unknown";
      },
      renderCell: (params) => {
        const status = params.row.status;
        const chipWidth = isHighZoom ? 70 : 90;
        switch (status) {
          case 0:
            return <Chip label="Submitted" color="secondary" sx={{width: chipWidth}} />;
          case 1:
            return <Chip label="Deploying" color="primary" sx={{width: chipWidth}} />;
          case 2:
            return <Chip label="Deployed" color="success" sx={{width: chipWidth}} />;
          case -1:
            return <Chip label="Failed" color="error" sx={{width: chipWidth}} />;
          default:
            return <Chip label="Unknown" sx={{width: chipWidth}} />;
        }
      },
    },
    {
      field: "address", 
      headerName: isHighZoom ? "HOST" : "Host", 
      flex: 1, 
      minWidth: isHighZoom ? 90 : 110, 
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
    {field: "hpType", headerName: "Type", flex: 1, minWidth: isHighZoom ? 60 : 90, headerAlign: "left", align: "left"},
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
      field: "uuid", 
      headerName: "UUID", 
      flex: 1, 
      minWidth: isHighZoom ? 150 : 200, 
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
  ];

  // Mobile viewport: Always show only 3 columns (DATE, STATUS, HOST) regardless of zoom
  if (viewportSize === 'mobile') {
    return allColumns.filter(col => 
      col.field === "created" || 
      col.field === "status" || 
      col.field === "address"
    );
  }

  // Tablet viewport: Reduce columns based on zoom
  if (viewportSize === 'tablet') {
    // At 150%+ zoom, show only 3 columns
    if (isVeryHighZoom) {
      return allColumns.filter(col => 
        col.field === "created" || 
        col.field === "status" || 
        col.field === "address"
      );
    }
    // At 125%+ zoom, reduce columns (hide UUID, Type, Username)
    if (isHighZoom) {
      return allColumns.filter(col => 
        col.field === "created" || 
        col.field === "status" || 
        col.field === "address"
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
      col.field === "status" || 
      col.field === "address"
    );
  }
  
  // At 125%+ zoom, reduce columns (hide UUID, Type, Username)
  if (isHighZoom) {
    return allColumns.filter(col => 
      col.field === "created" || 
      col.field === "status" || 
      col.field === "address"
    );
  }
  
  // At 100% zoom, show all columns
  return allColumns;
};

export default function DeploymentsTable() {
  const router = useRouter();
  const isHighZoom = useHighZoom();
  const isVeryHighZoom = useVeryHighZoom();
  const viewportSize = useViewportSize();
  const {deployments, isLoading, error} = useDeployments();

  const columns = useMemo(() => getColumns(isHighZoom, isVeryHighZoom, viewportSize), [isHighZoom, isVeryHighZoom, viewportSize]);

  const handleRowSelectionChange = (params: GridRowParams) => {
    router.push(`/deployments/${params.row.uuid}`);
  };
  return (
    <div style={{width: "100%", overflow: "auto"}} className="data-grid-container">
      <DataGrid
        rows={deployments ?? []}
        columns={columns}
        loading={isLoading}
        onRowClick={handleRowSelectionChange}
        initialState={{
          sorting: {
            sortModel: [{field: "created", sort: "desc"}],
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
