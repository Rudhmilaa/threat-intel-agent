"use client";

import { Button } from "@mui/material";
import { login } from "@/app/auth/auth";
import { useFormStatus } from "react-dom";
import TextField from "@mui/material/TextField";
import { useActionState, useEffect } from "react";
import { useRouter } from "next/navigation";
import { styled } from "@mui/material/styles";
import { AlertCircle } from "lucide-react";

const StyledTextField = styled(TextField)(({ theme }) => ({
  "& .MuiOutlinedInput-root": {
    "& .MuiOutlinedInput-notchedOutline": {
      borderColor: "white", // Default border color
    },
    "&:hover .MuiOutlinedInput-notchedOutline": {
      borderColor: "white", // Hover border color
    },
    "&.Mui-focused .MuiOutlinedInput-notchedOutline": {
      borderColor: "white", // Focus border color
    },
  },
  "& .MuiInputLabel-root": {
    color: "white", // Label color
  },
  "& .MuiInputLabel-root.Mui-focused": {
    color: "white", // Focused label color
  },
  "& .MuiInputBase-input": {
    color: "white", // Input text color
    "&:-webkit-autofill": {
      boxShadow: "0 0 0px 1000px #363636 inset !important", // Match background color
      WebkitTextFillColor: "white", // Autofill text color
    },
  },
}));

export function LoginForm() {
  const [state, action] = useActionState(login, undefined);
  const router = useRouter();

  useEffect(() => {
    if ((state as { success?: boolean })?.success) {
      router.refresh();
      router.push("/dashboard");
    }
  }, [state, router]);

  return (
    <form action={action}>
      <div className="flex flex-col gap-2 pt-2">
        <div>
          <StyledTextField
            className="w-full"
            id="username"
            type="text"
            name="username"
            label="Username"
            autoComplete="username"
            aria-describedby={state?.errors?.username ? "username-error" : undefined}
            aria-invalid={!!state?.errors?.username}
            error={!!state?.errors?.username}
          />
          {state?.errors?.username && (
            <div
              id="username-error"
              role="alert"
              aria-live="polite"
              className="mt-2"
            >
              <p className="text-sm text-red-500 flex items-center gap-1">
                <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                <span>{state.errors.username}</span>
              </p>
              {(state.errors.username.toLowerCase().includes("required") || 
                state.errors.username.toLowerCase().includes("username is required")) && (
                <p className="text-xs text-gray-400 mt-1 ml-5">
                  Suggestion: Enter your username. Usernames are case-sensitive.
                </p>
              )}
              {(state.errors.username.toLowerCase().includes("authentication failed") || 
                state.errors.username.toLowerCase().includes("incorrect username or password")) && (
                <p className="text-xs text-gray-400 mt-1 ml-5">
                  Suggestion: Check that both your username and password are correct. Both are case-sensitive. Make sure Caps Lock is off.
                </p>
              )}
              {(state.errors.username.toLowerCase().includes("invalid") && 
                !state.errors.username.toLowerCase().includes("authentication failed") &&
                !state.errors.username.toLowerCase().includes("incorrect username or password")) && (
                <p className="text-xs text-gray-400 mt-1 ml-5">
                  Suggestion: Check that your username is spelled correctly. Usernames are case-sensitive.
                </p>
              )}
            </div>
          )}
        </div>
        <div className="mt-4">
          <StyledTextField
            className="w-full"
            id="password"
            type="password"
            name="password"
            label="Password"
            autoComplete="current-password"
            aria-describedby={state?.errors?.password ? "password-error" : undefined}
            aria-invalid={!!state?.errors?.password}
            error={!!state?.errors?.password}
          />
          {state?.errors?.password && (
            <div
              id="password-error"
              role="alert"
              aria-live="polite"
              className="mt-2"
            >
              <p className="text-sm text-red-500 flex items-center gap-1">
                <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                <span>{state.errors.password}</span>
              </p>
              {(state.errors.password.toLowerCase().includes("required") || 
                state.errors.password.toLowerCase().includes("password is required")) && (
                <p className="text-xs text-gray-400 mt-1 ml-5">
                  Suggestion: Enter your password. Passwords are case-sensitive.
                </p>
              )}
              {(state.errors.password.toLowerCase().includes("authentication failed") || 
                state.errors.password.toLowerCase().includes("incorrect username or password")) && (
                <p className="text-xs text-gray-400 mt-1 ml-5">
                  Suggestion: Check that both your username and password are correct. Both are case-sensitive. Make sure Caps Lock is off.
                </p>
              )}
              {(state.errors.password.toLowerCase().includes("incorrect") || 
                state.errors.password.toLowerCase().includes("invalid") ||
                state.errors.password.toLowerCase().includes("wrong")) && 
                !state.errors.password.toLowerCase().includes("authentication failed") &&
                !state.errors.password.toLowerCase().includes("incorrect username or password") && (
                <p className="text-xs text-gray-400 mt-1 ml-5">
                  Suggestion: Check that your password is spelled correctly. Passwords are case-sensitive. Make sure Caps Lock is off.
                </p>
              )}
            </div>
          )}
        </div>
        {state?.message && !(state as { success?: boolean }).success && (
          <p
            className="text-sm text-red-500 ml-2 flex items-center gap-1"
            role="alert"
            aria-live="polite"
          >
            <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
            <span>{state.message}</span>
          </p>
        )}

        <div className="mt-4">
          <LoginButton />
        </div>
      </div>
    </form>
  );
}

export function LoginButton() {
  const { pending } = useFormStatus();

  return (
    <Button
      aria-disabled={pending}
      variant="contained"
      type="submit"
      className="w-full"
      sx={{ boxShadow: "none" }}
    >
      {pending ? "Submitting..." : "Login"}
    </Button>
  );
}
