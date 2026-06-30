import { z } from 'zod';

const iOSDateSchema = z.string().transform((dateString) => {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
      throw new Error("Invalid date format");
    }
    return date;
  });

export const SensorSchema = z.object({
    id: z.string(),
    uuid: z.string(),
    hostname: z.string(),
    honeypot: z.string(),
    ip: z.string(),
    created: iOSDateSchema,
    updated: iOSDateSchema.or(z.null()),
    tags: z.object({}),
    asn: z.string(),
});
export const SensorArraySchema = z.array(SensorSchema);


export type Sensor = {
    id: string;
    uuid: string;
    hostname: string;
    honeypot: string;
    ip: string;
    created: Date;
    updated: Date | null;
    tags: object;
    asn: string;
}