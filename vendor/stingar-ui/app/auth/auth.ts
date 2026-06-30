'use server';

import { isRedirectError } from 'next/dist/client/components/redirect-error';
import { LoginFormSchema } from '@/app/auth/definitions';
import { createSession, deleteSession } from '@/app/auth/session';
import { authUser } from '@/lib/actions';

export async function login(
  prevState: { errors?: { username?: string; password?: string }; message?: string } | undefined,
  formData: FormData,
) {
  const validatedFields = LoginFormSchema.safeParse({
    username: formData.get("username"),
    password: formData.get("password"),
  });

  if (!validatedFields.success) {
    const errors: { username?: string; password?: string } = {};
    validatedFields.error.errors.forEach((error) => {
      if (error.path[0] === "username") {
        errors.username = error.message;
      } else if (error.path[0] === "password") {
        errors.password = error.message;
      }
    });
    return { errors };
  }

  const { username, password } = validatedFields.data;

  try {
    const result = await authUser({ username, password });
    if (result.error) {
      // For authentication failures, highlight both fields and show the error message
      if (result.isAuthFailure) {
        return {
          errors: {
            username: result.error,
            password: result.error
          }
        };
      }

      // Check if error is related to username or password (for other error types)
      const errorLower = result.error.toLowerCase();
      // Only map to specific field if error clearly indicates which field
      if (errorLower.includes("username") && !errorLower.includes("password") && !errorLower.includes("or")) {
        return { errors: { username: result.error } };
      } else if (errorLower.includes("password") && !errorLower.includes("username") && !errorLower.includes("or")) {
        return { errors: { password: result.error } };
      }

      // Default: show as general message
      return { message: result.error };
    }

    // Create session (no redirect - client will navigate to avoid Server Action redirect handling issues)
    await createSession(String(result.id), false);

    return { success: true };
  } catch (error) {
    if (isRedirectError(error)) {
      throw error;
    }
    const msg = error instanceof Error ? error.message : "An error occurred during login";
    console.error("Login error:", msg);
    if (msg.includes("PASSPHRASE")) {
      return { message: "Server configuration error: PASSPHRASE is not set. Contact your administrator." };
    }
    return { message: "An error occurred during login" };
  }
}

export async function logout() {
  await deleteSession();
}