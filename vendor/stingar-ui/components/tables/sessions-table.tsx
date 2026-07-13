import * as React from "react";
import { DataGrid, GridColDef, GridRowParams } from "@mui/x-data-grid";
import { Tooltip } from "@mui/material";
import { useSessions } from "../hooks/hooks";
import { useRouter } from "next/navigation";
import { formatLocationWithFlag } from "@/lib/geo-utils";
import { useState, useCallback, useRef, useEffect, useMemo } from "react";
import { getOutcomeSortValue, OutcomeCategoryBadge } from "./outcome-category-badge";
import { useHighZoom, useVeryHighZoom } from "../hooks/use-zoom-level";
import { useViewportSize } from "../hooks/use-viewport";

// Base column definitions
const getColumns = (isHighZoom: boolean, isVeryHighZoom: boolean, viewportSize: 'mobile' | 'tablet' | 'desktop'): GridColDef[] => {
  // Calculate minWidth values based on zoom and viewport
  const getMinWidth = (base: number, highZoom: number, veryHighZoom: number, mobileVeryHighZoom: number) => {
    if (viewportSize === 'mobile' && isVeryHighZoom) return mobileVeryHighZoom;
    if (isVeryHighZoom) return veryHighZoom;
    if (isHighZoom) return highZoom;
    return base;
  };

  // Determine header name for timestamp column based on zoom and viewport
  const getTimestampHeaderName = () => {
    if (isVeryHighZoom) return "DATE";
    if (isHighZoom) {
      // On mobile at 125%+, show "DATE", otherwise show "Date & Time"
      if (viewportSize === 'mobile') return "DATE";
      return "Date & Time";
    }
    return "Date & Time";
  };

  const allColumns: GridColDef[] = [
    {
      field: "@timestamp",
      headerName: getTimestampHeaderName(),
      flex: isVeryHighZoom ? 0.7 : 1,
      minWidth: getMinWidth(140, 100, 80, 70),
      headerAlign: "left",
      align: "left",
      type: "dateTime",
      valueFormatter: (params) => {
        if (!params) return "N/A";
        try {
          const date = new Date(params as string);
          // At 200% zoom, show shorter date format to save space
          return isVeryHighZoom 
            ? date.toLocaleDateString() 
            : date.toLocaleString();
        } catch {
          return "N/A";
        }
      },
    },
    {
      field: "app",
      headerName: isVeryHighZoom ? "Type" : "Honeypot Type",
      flex: isVeryHighZoom ? 0.6 : 1,
      minWidth: getMinWidth(90, 70, 50, 40),
      headerAlign: "left",
      align: "left",
      valueFormatter: (params) => params || "N/A"
    },
    {
      field: "protocol",
      headerName: isHighZoom ? "Protocol" : "Protocol",
      flex: 1,
      minWidth: isHighZoom ? 60 : 90,
      headerAlign: "left",
      align: "left",
      valueFormatter: (params) => params || "N/A",
    },
    {
      field: "sensor",
      headerName: "Host",
      flex: 1,
      minWidth: getMinWidth(110, 90, 70, 60),
      headerAlign: "left",
      align: "left",
      valueGetter: (value, row) => row.sensor?.hostname || "N/A",
      renderCell: (params) => {
        const value = params.value || "N/A";
        const cellWidth = params.colDef.computedWidth || params.colDef.minWidth || 110;
        const isTruncated = typeof value === 'string' && value.length > 0;
        
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
      field: "srcIp",
      headerName: isHighZoom ? "SOURCE" : "Source Address",
      flex: 1,
      minWidth: getMinWidth(120, 100, 90, 75),
      headerAlign: "left",
      align: "left",
      valueGetter: (value, row) => {
        const ip = row?.srcIp ?? row?.src_ip ?? value ?? "";
        const port = row?.srcPort ?? row?.src_port;
        if (viewportSize === "desktop" && port != null && port !== "") {
          return `${ip}:${port}`;
        }
        return ip || "N/A";
      },
      renderCell: (params) => {
        const ip = params.row?.srcIp ?? params.row?.src_ip ?? params.value ?? "";
        const port = params.row?.srcPort ?? params.row?.src_port;
        const displayValue =
          viewportSize === "desktop" && port != null && port !== ""
            ? `${ip}:${port}`
            : ip || "N/A";

        return (
          <Tooltip title={displayValue} arrow placement="top">
            <div
              style={{
                width: "100%",
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
              }}
            >
              {displayValue}
            </div>
          </Tooltip>
        );
      },
    },
    {
      field: "geoData",
      headerName: isHighZoom ? "Location" : "Location",
      flex: 1,
      minWidth: isHighZoom ? 80 : 110,
      headerAlign: "left",
      align: "left",
      valueGetter: (value, row) => {
        const geoData = row.geoData;
        return formatLocationWithFlag(geoData);
      },
    },
    {
      field: "outcome_category",
      headerName: (viewportSize === 'mobile' && isVeryHighZoom) ? "OUT" : "OUTCOME",
      flex: isVeryHighZoom ? 0.7 : 0.9,
      minWidth: getMinWidth(100, 80, 70, 60),
      headerAlign: "left",
      align: "left",
      sortable: true,
      sortComparator: (_v1, _v2, param1, param2) => {
        try {
          const row1 = param1.api.getRow(param1.id);
          const row2 = param2.api.getRow(param2.id);
          return getOutcomeSortValue(row2) - getOutcomeSortValue(row1);
        } catch {
          return 0;
        }
      },
      renderCell: (params) => (
        <div className="flex items-center h-full">
          <OutcomeCategoryBadge row={params.row} />
        </div>
      ),
    },
  ];

  // Mobile viewport: Always show only 3 columns (DATE, SOURCE, OUTCOME) regardless of zoom
  if (viewportSize === 'mobile') {
    return allColumns.filter(col => 
      col.field === "@timestamp" || 
      col.field === "srcIp" || 
      col.field === "outcome_category"
    );
  }

  // Tablet viewport: Reduce columns based on zoom
  if (viewportSize === 'tablet') {
    // At 150%+ zoom, show only 3 columns
    if (isVeryHighZoom) {
      return allColumns.filter(col => 
        col.field === "@timestamp" || 
        col.field === "srcIp" || 
        col.field === "outcome_category"
      );
    }
    // At 125%+ zoom, reduce columns (hide Protocol, Location)
    if (isHighZoom) {
      return allColumns.filter(col => 
        col.field !== "protocol" && col.field !== "geoData"
      );
    }
    // At 100% zoom, show most columns (hide Protocol)
    return allColumns.filter(col => col.field !== "protocol");
  }

  // Desktop viewport: Show all columns at 100%, reduce based on zoom
  // At 150%+ zoom, show only 3 columns
  if (isVeryHighZoom) {
    return allColumns.filter(col => 
      col.field === "@timestamp" || 
      col.field === "srcIp" || 
      col.field === "outcome_category"
    );
  }
  
  // At 125%+ zoom, hide Protocol column (show 6 columns)
  if (isHighZoom) {
    return allColumns.filter(col => col.field !== "protocol");
  }
  
  // At 100% zoom, show all columns
  return allColumns;
};

interface SessionsTableProps {
  srcIpFilter?: string | null;
  fromDate?: string | null;
  toDate?: string | null;
}

export default function SessionsTable({ srcIpFilter = null, fromDate = null, toDate = null }: SessionsTableProps) {
  const router = useRouter();
  const isHighZoom = useHighZoom();
  const isVeryHighZoom = useVeryHighZoom();
  const viewportSize = useViewportSize();
  const [paginationModel, setPaginationModel] = useState({
    page: 0,
    pageSize: 100,
  });

  // Track the current request to prevent race conditions
  const currentRequestRef = useRef<string | null>(null);
  const [isChangingPage, setIsChangingPage] = useState(false);

  const sessionParams = useMemo(
    () => ({
      start_at: paginationModel.page * paginationModel.pageSize + 1,
      rows_per_page: paginationModel.pageSize,
      show_data: true,
      ...(srcIpFilter ? { src_ip: srcIpFilter } : {}),
      ...(fromDate ? { from_date: fromDate } : {}),
      ...(toDate ? { to_date: toDate } : {}),
    }),
    [paginationModel.page, paginationModel.pageSize, srcIpFilter, fromDate, toDate]
  );

  const { sessions, count, isLoading, error } = useSessions(sessionParams);

  // Reset to page 0 when filter changes
  useEffect(() => {
    setPaginationModel((prev) => (prev.page === 0 ? prev : { ...prev, page: 0 }));
  }, [srcIpFilter, fromDate, toDate]);

  // Memoize columns based on zoom level and viewport size
  const columns = useMemo(() => getColumns(isHighZoom, isVeryHighZoom, viewportSize), [isHighZoom, isVeryHighZoom, viewportSize]);

  const handleRowSelectionChange = (params: GridRowParams) => {
    router.push(`/sessions/${params.row.id}`);
  };

  const handlePaginationModelChange = useCallback((newModel: any) => {
    // Create a unique request ID for this pagination change
    const requestId = `${newModel.page}-${newModel.pageSize}-${Date.now()}`;
    currentRequestRef.current = requestId;

    setIsChangingPage(true);

    // Use a small delay to prevent rapid successive calls
    const timeoutId = setTimeout(() => {
      // Only update if this is still the most recent request
      if (currentRequestRef.current === requestId) {
        setPaginationModel(newModel);
        setIsChangingPage(false);
      }
    }, 50);

    // Cleanup function to clear timeout if component unmounts
    return () => clearTimeout(timeoutId);
  }, []);

  // Cleanup effect
  useEffect(() => {
    return () => {
      currentRequestRef.current = null;
    };
  }, []);

  return (
    <div
      className="data-grid-container min-w-0"
      style={{
        width: "100%",
        overflowX: viewportSize === "mobile" ? "hidden" : "auto",
        overflowY: "auto",
      }}
    >
      <DataGrid
        rows={sessions ?? []}
        columns={columns}
        loading={isLoading || isChangingPage}
        onRowClick={handleRowSelectionChange}
        pagination
        paginationMode="server"
        rowCount={count ?? 0}
        paginationModel={paginationModel}
        onPaginationModelChange={handlePaginationModelChange}
        pageSizeOptions={[25, 50, 100, 200]}
        initialState={{
          sorting: {
            sortModel: [{ field: "startTime", sort: "desc" }],
          },
        }}
        sx={{
          width: "100%",
          maxWidth: "100%",
          "& .MuiDataGrid-main": {
            overflowX: viewportSize === "mobile" ? "hidden" : "auto",
          },
          "& .MuiDataGrid-virtualScroller": {
            overflowX: viewportSize === "mobile" ? "hidden" : "auto",
          },
          "& .MuiDataGrid-cell": {
            minWidth: 0,
            maxWidth: "none",
            overflow: "hidden",
            textOverflow: "ellipsis",
            justifyContent: "flex-start",
            // Reduce padding further for mobile at 200% zoom
            paddingLeft: (viewportSize === 'mobile' && isVeryHighZoom) ? "2px !important" : (isVeryHighZoom ? "4px !important" : (isHighZoom ? "8px !important" : "16px !important")),
            paddingRight: (viewportSize === 'mobile' && isVeryHighZoom) ? "2px !important" : (isVeryHighZoom ? "4px !important" : (isHighZoom ? "8px !important" : "16px !important")),
            display: "flex",
            alignItems: "center",
            fontSize: (viewportSize === 'mobile' && isVeryHighZoom) ? "0.75rem" : (isVeryHighZoom ? "0.8125rem" : (isHighZoom ? "0.875rem" : "1rem")),
          },
          "& .MuiDataGrid-columnHeader": {
            minWidth: 0,
            maxWidth: "none",
            justifyContent: "flex-start",
            // Reduce padding further for mobile at 200% zoom
            paddingLeft: (viewportSize === 'mobile' && isVeryHighZoom) ? "2px !important" : (isVeryHighZoom ? "4px !important" : (isHighZoom ? "8px !important" : "16px !important")),
            paddingRight: (viewportSize === 'mobile' && isVeryHighZoom) ? "2px !important" : (isVeryHighZoom ? "4px !important" : (isHighZoom ? "8px !important" : "16px !important")),
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
              fontSize: (viewportSize === 'mobile' && isVeryHighZoom) ? "0.75rem" : (isVeryHighZoom ? "0.8125rem" : (isHighZoom ? "0.875rem" : "1rem")),
            },
          },
          // Ensure sort icon doesn't affect alignment - position it absolutely
          "& .MuiDataGrid-iconButtonContainer": {
            marginLeft: (viewportSize === 'mobile' && isVeryHighZoom) ? "1px" : (isVeryHighZoom ? "2px" : (isHighZoom ? "2px" : "4px")),
            position: "relative",
            flexShrink: 0,
          },
          // Ensure column separators align
          "& .MuiDataGrid-columnSeparator": {
            display: "none",
          },
          // At 200% zoom on mobile, further reduce whitespace in DATE and TYPE columns
          "& .MuiDataGrid-columnHeader[data-field='@timestamp']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "70px !important" : (isVeryHighZoom ? "80px !important" : "140px !important"),
            flex: isVeryHighZoom ? "0.7 !important" : "1 !important",
          },
          "& .MuiDataGrid-cell[data-field='@timestamp']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "70px !important" : (isVeryHighZoom ? "80px !important" : "140px !important"),
            flex: isVeryHighZoom ? "0.7 !important" : "1 !important",
          },
          "& .MuiDataGrid-columnHeader[data-field='app']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "40px !important" : (isVeryHighZoom ? "50px !important" : "90px !important"),
            flex: isVeryHighZoom ? "0.6 !important" : "1 !important",
          },
          "& .MuiDataGrid-cell[data-field='app']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "40px !important" : (isVeryHighZoom ? "50px !important" : "90px !important"),
            flex: isVeryHighZoom ? "0.6 !important" : "1 !important",
          },
          // Ensure Host and Source columns have appropriate minWidth on mobile at 200% zoom
          "& .MuiDataGrid-columnHeader[data-field='sensor']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "60px !important" : (isVeryHighZoom ? "70px !important" : "110px !important"),
          },
          "& .MuiDataGrid-cell[data-field='sensor']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "60px !important" : (isVeryHighZoom ? "70px !important" : "110px !important"),
          },
          "& .MuiDataGrid-columnHeader[data-field='srcIp']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "75px !important" : (isVeryHighZoom ? "90px !important" : "120px !important"),
          },
          "& .MuiDataGrid-cell[data-field='srcIp']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "75px !important" : (isVeryHighZoom ? "90px !important" : "120px !important"),
          },
          // Ensure outcome column stays visible at high zoom
          "& .MuiDataGrid-columnHeader[data-field='outcome_category']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "55px !important" : (isVeryHighZoom ? "60px !important" : (isHighZoom ? "70px !important" : "100px !important")),
            flex: isVeryHighZoom ? "0.7 !important" : "0.9 !important",
          },
          "& .MuiDataGrid-cell[data-field='outcome_category']": {
            minWidth: (viewportSize === 'mobile' && isVeryHighZoom) ? "55px !important" : (isVeryHighZoom ? "60px !important" : (isHighZoom ? "70px !important" : "100px !important")),
            flex: isVeryHighZoom ? "0.7 !important" : "0.9 !important",
          },
        }}
      />
    </div>
  );
}
