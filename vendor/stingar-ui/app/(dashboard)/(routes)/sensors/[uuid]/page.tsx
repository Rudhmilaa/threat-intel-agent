"use client";

import {useSensors} from "@/components/hooks/hooks";
import {Paper, Stack, styled, Typography} from "@mui/material";
import Grid from "@mui/material/Grid2";
import {useParams} from "next/navigation";
import React from "react";

const Item = styled(Paper)(({theme}) => ({
  backgroundColor: "#fff",
  ...theme.typography.body2,
  padding: theme.spacing(1),
  textAlign: "center",
  color: theme.palette.text.secondary,
  ...theme.applyStyles("dark", {
    backgroundColor: "#1A2027",
  }),
}));

const SensorDetails = ({sensor}: {sensor: any}) => {
  const labelValuePairs = [
    {label: "Hostname", value: sensor?.hostname || "N/A"},
    {label: "Honeypot Type", value: sensor?.honeypot || "N/A"},
    {label: "UUID", value: sensor?.uuid || "N/A"},
    {label: "ASN", value: sensor?.asn || "N/A"},
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

export default function SensorsView() {
  const {uuid} = useParams();
  const {sensors, error, isLoading, mutate} = useSensors();

  const sensor = sensors?.find((sensor: any) => sensor.uuid === uuid);
  return (
    <div className="flex flex-col h-full w-full">
      <h1 className="mb-4 text-xl font-bold">Honeypot Details</h1>
      <SensorDetails sensor={sensor} />
      <h2 className="mt-16 mb-4  text-xl font-bold">Honeypot Stats</h2>
      <div className="flex flex-col w-full h-full pt-4">
        <iframe
          src="/kibana/app/dashboards#/view/sensor_dashboard?embed=true&_g=(filters%3A!()%2CrefreshInterval%3A(pause%3A!t%2Cvalue%3A0)%2Ctime%3A(from%3Anow-30d%2Cto%3Anow))&hide-filter-bar=true"
          height="100%"
        ></iframe>
      </div>
    </div>
  );
}
