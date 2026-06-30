import { z } from 'zod';

const iOSDateSchema = z.string().transform((dateString) => {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
      throw new Error("Invalid date format");
    }
    return date;
  });

// TODO: Return authkeyName from API
export const BlocklistSchema = z.object({
    id: z.number(),
    created: iOSDateSchema,
    address: z.string(),
});
export const BlocklistArraySchema = z.array(BlocklistSchema);

export type BlockedIP = {
    id: number;
    created: Date;
    address: string;
};

export const SettingsSchema = z.object({
    id: z.number(),
    honeycombHost: z.string(),
    honeycombProviderId: z.string(),
    honeycombToken: z.string(),
    honeycombEnabled: z.boolean(),
});

export type Settings = {
    id: number;
    honeycombHost: string;
    honeycombProviderId: string;
    honeycombToken: string;
    honeycombEnabled: boolean;
};
