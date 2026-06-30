import { z } from 'zod';

const iOSDateSchema = z.string().transform((dateString) => {
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
        throw new Error("Invalid date format");
    }
    return date;
});

// Helper function for safe date parsing with fallback
const safeDateSchema = z.string().optional().transform((dateString) => {
    if (!dateString) return new Date(); // Default to current date
    const date = new Date(dateString);
    if (isNaN(date.getTime())) {
        return new Date(); // Fallback to current date
    }
    return date;
});

export const SessionSchema = z.object({
    id: z.string().default(""),
    app: z.string().default(""),
    srcIp: z.string().default(""),
    srcPort: z.number().or(z.null()).default(null),
    dstIp: z.string().default(""),
    dstPort: z.number().or(z.null()).default(null),
    startTime: safeDateSchema.default(new Date().toISOString()),
    endTime: safeDateSchema.default(new Date().toISOString()),
    protocol: z.string().or(z.null()).default(null),
    "@timestamp": safeDateSchema.default(new Date().toISOString()),
    fluentdTag: z.string().default(""),
    sensor: z.object({
        hostname: z.string().default(""),
        uuid: z.string().default(""),
        asn: z.string().or(z.null()).default(null),
        tags: z.record(z.any()).default({})
    }).default({
        hostname: "",
        uuid: "",
        asn: null,
        tags: {}
    }),
    hpData: z.record(z.any()).default({}),
    outcome_category: z.string().optional(),
    outcome_summary: z.record(z.any()).optional(),
    // Geo fields extracted from hpData for easier access
    geoData: z.object({
        geopoint: z.any().optional(),
        geoPoint: z.any().optional(),
        country: z.string().optional(),
        city: z.string().optional(),
        coordinates: z.any().optional(),
        latitude: z.number().optional(),
        longitude: z.number().optional(),
        // Additional geo fields that might be present
        location: z.any().optional(),
        geo: z.any().optional(),
        geoip: z.any().optional(),
        geolocation: z.any().optional(),
        // Original field names for debugging
        geoCity: z.string().optional(),
        geoCc: z.string().optional()
    }).default({})
});
export const SessionArraySchema = z.array(SessionSchema);

export type Session = {
    id: string;
    app: string;
    srcIp: string;
    srcPort: number | null;
    dstIp: string;
    dstPort: number | null;
    startTime: Date;
    endTime: Date;
    protocol: string | null;
    "@timestamp": Date;
    fluentdTag: string;
    sensor: {
        hostname: string;
        uuid: string;
        asn: string | null;
        tags: object;
    };
    hpData: object;
    outcome_category?: string;
    outcome_summary?: Record<string, unknown>;
    geoData: {
        geopoint?: any;
        geoPoint?: any;
        country?: string;
        city?: string;
        coordinates?: any;
        latitude?: number;
        longitude?: number;
        // Additional geo fields that might be present
        location?: any;
        geo?: any;
        geoip?: any;
        geolocation?: any;
        // Original field names for debugging
        geoCity?: string;
        geoCc?: string;
    };
}