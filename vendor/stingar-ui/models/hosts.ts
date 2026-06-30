import { v4 } from "uuid";
import { z } from 'zod';

const iOSDateSchema = z.string().transform((dateString) => {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
      throw new Error("Invalid date format");
    }
    return date;
  });

// TODO: Return authkeyName from API
export const HostSchema = z.object({
    id: z.number(),
    uuid: z.string(),
    address: z.string(),
    sshPort: z.number(),
    username: z.string(),
    authkeyId: z.number(),
    created: iOSDateSchema,
    updated: iOSDateSchema.or(z.null())
});
export const HostArraySchema = z.array(HostSchema);

export type Host = {
    id: number;
    uuid: string;
    address: string;
    sshPort: number;
    username: string;
    authkeyId: number;
    authkeyName: string;
    created: Date;
    updated: Date | null;
};

export const newHost = (): Host => (
{
    id: 0,
    uuid: v4(),
    address: "",
    sshPort: 2222,
    username: "",
    authkeyId: 0,
    authkeyName: "",
    created: new Date(),
    updated: null,
});  