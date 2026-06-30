import { z } from "zod";

const iOSDateSchema = z.string().transform((dateString) => {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
      throw new Error("Invalid date format");
    }
    return date;
  });

export const DeploymentSchema = z.object({
    id: z.number(),
    uuid: z.string(),
    status: z.number(),
    address: z.string(),
    sshPort: z.number(),
    username: z.string(),
    authkeyId: z.number(),
    hpType: z.string(),
    hpOptions: z.string(),
    created: iOSDateSchema,
    updated: iOSDateSchema.or(z.null()),
    tags: z.array(z.string()),
});
export const DeploymentArraySchema = z.array(DeploymentSchema);

export type Deployments = {
    id: number;
    uuid: string;
    status: number;
    address: string;
    sshPort: number;
    username: string;
    authkeyId: number;
    hpType: string;
    hpOptions: string;
    created: Date;
    updated: Date | null;
    tags: string[];
}

export const statusMap: {[key: number]: string} = {
  0: "Submitted",
  1: "Deploying",
  2: "Deployed",
  [-1]: "Failed",
};