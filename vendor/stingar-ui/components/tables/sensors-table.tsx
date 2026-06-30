import React, { useMemo } from "react";
import { useSensors } from "@/components/hooks/hooks";
import { format, sub } from "date-fns";
import { DataGrid, GridColDef, GridRowParams } from "@mui/x-data-grid";
import { Chip, Tooltip } from "@mui/material";
import { useRouter } from "next/navigation";
import { useHighZoom, useVeryHighZoom } from "../hooks/use-zoom-level";
import { useViewportSize } from "../hooks/use-viewport";

const getColumns = (isHighZoom: boolean, isVeryHighZoom: boolean, viewportSize: 'mobile' | 'tablet' | 'desktop'): GridColDef[] => {
  const allColumns: GridColDef[] = [
    { 
      field: "uuid", 
      headerName: "UUID", 
      flex: 1, 
      minWidth: isHighZoom ? 120 : 180, 
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
      field: "honeypot", 
      headerName: isHighZoom ? "TYPE" : "HP Type", 
      flex: 1, 
      minWidth: isHighZoom ? 60 : 90, 
      headerAlign: "left", 
      align: "left" 
    },
    { 
      field: "hostname", 
      headerName: isHighZoom ? "HOST" : "Hostname/IP", 
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
    {
      field: "asn",
      headerName: "ASN",
      flex: 0.8,
      minWidth: isHighZoom ? 50 : 70,
      headerAlign: "left",
      align: "left",
    },
    {
      field: "created",
      headerName: isHighZoom ? "Deployed" : "Deployed",
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
      field: "updated",
      headerName: isHighZoom ? "STATUS" : "Status",
      type: "date",
      flex: 0.9,
      minWidth: isHighZoom ? 80 : 100,
      headerAlign: "left",
      align: "left",
      renderCell: (params) => {
        if (!params.row.updated) {
          <Tooltip title="No health checks posted">
            <Chip label="Unknown" color="primary"></Chip>
          </Tooltip>;
        }
        // Healthy if last seen within 2hr
        const isHealthy =
          params.row.updated.getTime() >= sub(new Date(), { hours: 2 }).getTime();

        if (isHealthy) {
          return (
            <Tooltip title={`Last seen ${format(params.row.updated, "Pp")}`}>
              <Chip label="Healthy" color="success" />
            </Tooltip>
          );
        } else {
          return (
            <Tooltip title={`Last seen ${format(params.row.updated, "Pp")}`}>
              <Chip label="Unhealthy" color="error" />
            </Tooltip>
          );
        }
      },
    },
  ];

  // Mobile viewport: Always show only 3 columns (TYPE, HOST, STATUS) regardless of zoom
  if (viewportSize === 'mobile') {
    return allColumns.filter(col => 
      col.field === "honeypot" || 
      col.field === "hostname" || 
      col.field === "updated"
    );
  }

  // Tablet viewport: Reduce columns based on zoom
  if (viewportSize === 'tablet') {
    // At 150%+ zoom, show only 3 columns
    if (isVeryHighZoom) {
      return allColumns.filter(col => 
        col.field === "honeypot" || 
        col.field === "hostname" || 
        col.field === "updated"
      );
    }
    // At 125%+ zoom, reduce columns (hide UUID, ASN)
    if (isHighZoom) {
      return allColumns.filter(col => col.field !== "uuid" && col.field !== "asn");
    }
    // At 100% zoom, show most columns (hide UUID)
    return allColumns.filter(col => col.field !== "uuid");
  }

  // Desktop viewport: Show all columns at 100%, reduce based on zoom
  // At 150%+ zoom, show only 3 columns
  if (isVeryHighZoom) {
    return allColumns.filter(col => 
      col.field === "honeypot" || 
      col.field === "hostname" || 
      col.field === "updated"
    );
  }
  
  // At 125%+ zoom, reduce columns (hide UUID, ASN)
  if (isHighZoom) {
    return allColumns.filter(col => col.field !== "uuid" && col.field !== "asn");
  }
  
  // At 100% zoom, show all columns
  return allColumns;
};

export default function SensorsTable() {
  const router = useRouter();
  const isHighZoom = useHighZoom();
  const isVeryHighZoom = useVeryHighZoom();
  const viewportSize = useViewportSize();
  const { sensors, count, isLoading, error } = useSensors({
    start_at: 1,
    rows_per_page: 1000, // ES index.max_result_window default is 10000. API will return at most 10000 results.
  });

  const columns = useMemo(() => getColumns(isHighZoom, isVeryHighZoom, viewportSize), [isHighZoom, isVeryHighZoom, viewportSize]);

  const handleRowSelectionChange = (params: GridRowParams) => {
    router.push(`/sensors/${params.row.uuid}`);
  };
  return (
    <div style={{ width: "100%", overflow: "auto" }} className="data-grid-container">
      <DataGrid
        rows={sensors ?? []}
        columns={columns}
        loading={isLoading}
        onRowClick={handleRowSelectionChange}
        initialState={{
          sorting: {
            sortModel: [{ field: "updated", sort: "desc" }],
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
