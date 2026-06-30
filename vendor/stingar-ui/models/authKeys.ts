import { z } from 'zod';

export const AuthKeySchema = z.object({
  id: z.number(),
  name: z.string(),
  publicKey: z.string(), // snake_case as expected from API
  // created_at: z.date(), // snake_case
});

export const AuthKeysArraySchema = z.array(AuthKeySchema);


export type AuthKey = {
    id: number;
    name: string;
    publicKey: string;
    // createdAt: Date;
};