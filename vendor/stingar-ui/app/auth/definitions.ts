import { z } from 'zod';

export const LoginFormSchema = z.object({
  username: z.string().trim().min(1, "Username is required"),
  password: z.string().trim().min(1, "Password is required"),
});

export type LoginFormValues = z.infer<typeof LoginFormSchema>;

export const UpdatePasswordSchema = z.object({
  password: z
    .string()
    .min(8, { message: 'Be at least 8 characters long' })
    .regex(/[a-zA-Z]/, { message: 'Contain at least one letter.' })
    .regex(/[0-9]/, { message: 'Contain at least one number.' })
    .regex(/[^a-zA-Z0-9]/, {
      message: 'Contain at least one special character.',
    })
    .trim(),
});

export type FormState =
  | {
    errors?: {
      username?: string[];
      password?: string[];
    };
    message?: string;
    status?: 'success' | 'error';
  }
  | undefined;

export type SessionPayload = {
  userId: string | number;
  expiresAt: Date;
};