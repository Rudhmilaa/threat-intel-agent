"use client";

import { useSession } from "@/components/hooks/hooks";
import { Paper, Typography, Button } from "@mui/material";
import Grid from "@mui/material/Grid2";
import { useParams } from "next/navigation";
import React, { useEffect, useState } from "react";
import AnsiUp from 'ansi_up';
import { struct } from '@/lib/struct';
import { formatCountryWithFlag } from '@/lib/geo-utils';

// TTY Playback Constants
const OP_OPEN = 1, OP_CLOSE = 2, OP_WRITE = 3, OP_EXEC = 4;
const TYPE_INPUT = 1, TYPE_OUTPUT = 2, TYPE_INTERACT = 3;
const BACKSPACE = new Uint8Array([27, 91, 49, 80]);
const CONTROL = 27;

function useTTYPlayback() {
  const [isPlaying, setIsPlaying] = useState(false);
  const [output, setOutput] = useState("");

  const sleep = (ms: number) => new Promise(resolve => setTimeout(resolve, ms));

  const checkControlChars = (data: ArrayBuffer, outText: string) => {
    let view = new Uint8Array(data);
    if (view[0] === BACKSPACE[0] && view[1] === BACKSPACE[1] &&
      view[2] === BACKSPACE[2] && view[3] === BACKSPACE[3]) {
      return outText.substr(0, outText.length - 9);
    }
    return outText;
  };

  const fromHexString = (hexString: string) =>
    new Uint8Array(hexString.match(/.{1,2}/g)?.map(byte => parseInt(byte, 16)) || []);

  const playlog = async (ttylog: string) => {
    if (isPlaying) return;
    setIsPlaying(true);

    try {
      const ansiUp = new AnsiUp();
      const s = struct('<iIiiII');
      const ssize = s.size;
      let currtty = 0;
      let ttyBytes = fromHexString(ttylog);
      let outText = "";

      let i = 0;
      while (i + ssize <= ttyBytes.length) {
        const headerBuffer = ttyBytes.buffer.slice(
          ttyBytes.byteOffset + i,
          ttyBytes.byteOffset + i + ssize
        );

        const [op, tty, length, dir, sec, usec] = s.unpack(headerBuffer);

        if (op === 0 || length === 0) {
          i += ssize;
          continue;
        }

        i += ssize;

        if (i + length <= ttyBytes.length) {
          const dataArray = ttyBytes.slice(i, i + length);
          i += length;

          if (currtty === 0) currtty = tty;

          if (tty === currtty && op === OP_WRITE && dir === TYPE_OUTPUT) {
            try {
              const text = new TextDecoder().decode(dataArray);
              const processedText = text.replace(/\r(?!\n)/g, '\r\n')
                .replace(/([^\r])\n/g, '$1\r\n');
              outText += processedText;
              setOutput(ansiUp.ansi_to_html(outText));
              await sleep(50);
            } catch (e) {
              console.error('Decode error:', e);
            }
          }
        }
      }

    } catch (error) {
      console.error('Error playing TTY log:', error);
    } finally {
      setIsPlaying(false);
    }
  };

  return { playlog, isPlaying, output };
}

const SessionOverview = ({ session }: { session: any }) => {
  const labelValuePairs = [
    {
      label: "Created",
      value: session?.startTime?.toLocaleString() || "N/A"
    },
    {
      label: "Honeypot Type",
      value: session?.app || "N/A"
    },
    {
      label: "Protocol",
      value: session?.protocol || "N/A"
    },
    {
      label: "Source IP:Port",
      value: session?.srcIp && session?.srcPort
        ? `${session.srcIp}:${session.srcPort}`
        : "N/A",
    },
    {
      label: "Destination IP:Port",
      value: session?.dstIp && session?.dstPort
        ? `${session.dstIp}:${session.dstPort}`
        : "N/A",
    },
    {
      label: "Host Attacked",
      value: session?.sensor?.hostname || "N/A"
    },
    {
      label: "ASN",
      value: session?.sensor?.asn || "N/A"
    },
    {
      label: "Country",
      value: formatCountryWithFlag(session?.geoData?.country || session?.geoData?.geoCc)
    },
    {
      label: "City",
      value: session?.geoData?.city || session?.geoData?.geoCity || "N/A"
    },
    {
      label: "Coordinates",
      value: session?.geoData?.latitude && session?.geoData?.longitude
        ? `${session.geoData.latitude}, ${session.geoData.longitude}`
        : session?.geoData?.coordinates || "N/A"
    },
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

const SessionDetails = ({ session }: { session: any }) => {
  const { playlog, isPlaying, output } = useTTYPlayback();

  useEffect(() => {
    //console.log("Session data:", session);
    //console.log("TTY log exists:", !!session?.hpData?.ttylog);
  }, [session]);

  // Early return if no session
  if (!session) {
    return null;
  }

  return (
    <div className="flex flex-col gap-4">
      <Paper
        elevation={4}
        sx={{
          backgroundColor: "black",
          padding: 2,
          maxHeight: 400,
          overflow: "auto",
          wordWrap: "break-word",
        }}
      >
        <pre style={{ fontFamily: "monospace", margin: 0, color: "white" }}>
          {JSON.stringify(session, null, 2)}
        </pre>
      </Paper>

      {session.hpData && session.hpData.ttylog && (
        <div className="tty-playback-container mt-4">
          <h3 className="text-lg font-semibold mb-2">TTY Log</h3>
          <Button
            variant="contained"
            onClick={() => playlog(session.hpData.ttylog)}
            disabled={isPlaying}
            className="mb-4"
          >
            {isPlaying ? 'Playing...' : 'Play TTY Log'}
          </Button>
          <div
            id="tty_playback"
            className="tty-terminal bg-black text-green-500 p-4 rounded-md font-mono h-[250px] overflow-y-auto"
            dangerouslySetInnerHTML={{ __html: output }}
          />
        </div>
      )}
    </div>
  );
};

export default function SessionView() {
  const { id } = useParams();
  const { session, error, isLoading, mutate } = useSession(String(id));

  const details =
    isLoading || error ? { isLoading: isLoading, error: error } : session;
  return (
    <div className="max-w-7xl">
      <h1 className="mb-4 text-xl font-bold">Attack Overview</h1>
      <SessionOverview session={session} />
      <h2 className="mt-16 mb-4  text-xl font-bold">Details</h2>
      <SessionDetails session={details} />
    </div>
  );
}
