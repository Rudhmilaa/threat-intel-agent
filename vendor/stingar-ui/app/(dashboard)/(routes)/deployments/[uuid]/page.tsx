"use client";

import { useDeploymentLogs, useDeployments } from "@/components/hooks/hooks";
import { Button, Typography } from "@mui/material";
import Grid from "@mui/material/Grid2";
import { useParams } from "next/navigation";
import React from "react";
import { statusMap } from "@/models/deployments";
import { DataGrid, GridColDef } from "@mui/x-data-grid";
import AutorenewIcon from "@mui/icons-material/Autorenew";
import { getDeploymentCompose, getDeploymentEnv } from "@/lib/actions";
import { toast } from "sonner";

const DeploymentDetails = ({ deployment }: { deployment: any }) => {
  const labelValuePairs = [
    { label: "Created", value: deployment?.created?.toLocaleString() || "N/A" },
    { label: "Status", value: statusMap[deployment?.status] || "N/A" },
    { label: "Honeypot Type", value: deployment?.hpType || "N/A" },
    { label: "Host", value: deployment?.address || "N/A" },
    { label: "UUID", value: deployment?.uuid || "N/A" },
    { label: "HP Settings", value: deployment?.hpOptions || "N/A" },
  ];
  return (
    <Grid container spacing={6}>
      {labelValuePairs.map((pair, index) => (
        <React.Fragment key={index}>
          <Grid spacing={1} direction="row">
            <Typography variant="subtitle2" color="textSecondary">
              {pair.label}
            </Typography>
            <Typography variant="body1">{pair.value}</Typography>
          </Grid>
        </React.Fragment>
      ))}
    </Grid>
  );
};

const TruncatedText = ({
  text,
  maxLength = 100,
}: {
  text: string;
  maxLength: number;
}) => {
  const [isExpanded, setIsExpanded] = React.useState(false);
  const containerRef = React.useRef<HTMLDivElement>(null);

  if (!text || text.length <= maxLength) {
    return <span>{text}</span>;
  }

  const truncatedText = isExpanded
    ? text.slice(0, 1000)
    : `${text.slice(0, maxLength)}...`;

  return (
    <div ref={containerRef} className="inline-block max-w-full">
      <span className="mr-2 whitespace-pre-wrap">{truncatedText}</span>
      <button
        onClick={(e) => {
          e.stopPropagation();
          setIsExpanded(!isExpanded);
        }}
        className="text-blue-500 hover:text-blue-700 text-sm font-medium"
      >
        {isExpanded ? "Show less" : "Show more"}
      </button>
    </div>
  );
};

const columns: GridColDef[] = [
  {
    field: "ts",
    headerName: "Timestamp",
    flex: 1,
    type: "date",
    valueFormatter: (params) => new Date(params as string).toLocaleString(),
  },
  { field: "event", headerName: "Event", flex: 1 },
  { field: "msg", headerName: "Message", flex: 1 },
  {
    field: "errorMsg",
    headerName: "Error",
    flex: 1,
    valueGetter: (params: any) => {
      return params ? "View logs for more info" : "-";
    },
  },
];

export default function DeploymentsView() {
  const { uuid } = useParams();
  const { deployments, error, isLoading, mutate } = useDeployments();
  const deployment = deployments?.find((sensor: any) => sensor.uuid === uuid);
  const {
    logs,
    error: logsError,
    isLoading: logsLoading,
    mutate: logsMutate,
  } = useDeploymentLogs(String(uuid));

  const handleDownload = async () => {
    try {
      // Fetch the data from the endpoint
      const data = { details: deployment, logs: logs };

      // Convert the data to a JSON string
      const jsonString = JSON.stringify(data, null, 2);

      // Create a blob with the JSON data
      const blob = new Blob([jsonString], { type: "application/json" });

      // Create a URL for the blob
      const url = window.URL.createObjectURL(blob);

      // Create a temporary anchor element
      const link = document.createElement("a");
      link.href = url;
      link.download = `deployment-${deployment?.uuid}.json`;

      // Append to body, click, and remove
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      // Clean up the URL
      window.URL.revokeObjectURL(url);
    } catch (error) {
      console.error("Error downloading file:", error);
      // You might want to handle the error appropriately here
      alert("Failed to download file");
    }
  };

  const handleDownloadCompose = async () => {
    try {
      const compose = await getDeploymentCompose(String(deployment?.id));

      // Create a URL for the blob
      const url = window.URL.createObjectURL(compose);

      // Create a temporary anchor element
      const link = document.createElement("a");
      link.href = url;
      link.download = "docker-compose.yml";

      // Append to body, click, and remove
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      // Clean up the URL
      window.URL.revokeObjectURL(url);
    } catch (error) {
      toast.error("Failed to download file");
    }
  };

  const handleDownloadEnv = async () => {
    try {
      const env = await getDeploymentEnv(String(deployment?.id));

      // Create a URL for the blob
      const url = window.URL.createObjectURL(env);

      // Create a temporary anchor element
      const link = document.createElement("a");
      link.href = url;
      link.download = "stingar-hp.env";

      // Append to body, click, and remove
      document.body.appendChild(link);
      link.click();
      document.body.removeChild(link);

      // Clean up the URL
      window.URL.revokeObjectURL(url);
    } catch (error) {
      toast.error("Failed to download file");
    }
  };

  const handleDownloadInstallScript = async () => {
    await handleDownloadCompose();
    await handleDownloadEnv();
  };

  return (
    <div>
      <div className="flex justify-between items-center">
        <h1 className="mb-4 text-xl font-bold">Deployment Details</h1>
        <div className="flex">
          <Button
            onClick={() => {
              logsMutate(undefined, { revalidate: true });
              mutate(undefined, { revalidate: true });
            }}
            disabled={logsLoading || isLoading}
            size="small"
          >
            <AutorenewIcon
              className={isLoading || logsLoading ? "animate-spin" : ""}
            />
          </Button>
        </div>
      </div>
      <DeploymentDetails deployment={deployment} />
      <div className="flex justify-between items-center mt-16 mb-4">
        <h2 className="text-xl font-bold">Deployment Logs</h2>
        <div className="flex gap-4">
          <Button size="small" onClick={handleDownloadInstallScript}>
            Download Install Script
          </Button>
          <Button
            onClick={() => handleDownload()}
            disabled={logsLoading}
            size="small"
          >
            Download Deployment Info
          </Button>
        </div>
      </div>
      <div className="flex flex-col pb-4">
        <DataGrid
          rows={logs ?? []}
          columns={columns}
          density="compact"
          loading={isLoading}
          isRowSelectable={() => false}
        />
      </div>
    </div>
  );
}
