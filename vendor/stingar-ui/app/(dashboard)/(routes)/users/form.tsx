"use client";

import { useState } from "react";
import { Button, TextField } from "@mui/material";
import { createUser } from "@/lib/actions";
import { AlertCircle } from "lucide-react";

export function AddUserForm({ onSuccess }: { onSuccess: () => void }) {
  const [formData, setFormData] = useState({
    username: "",
    email: "",
    password: "",
  });
  const [error, setError] = useState("");
  const [fieldErrors, setFieldErrors] = useState<{
    username?: string;
    email?: string;
    password?: string;
  }>({});
  const [loading, setLoading] = useState(false);

  const handleChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
    // Clear field error when user starts typing
    if (fieldErrors[name as keyof typeof fieldErrors]) {
      setFieldErrors((prev) => ({ ...prev, [name]: undefined }));
    }
    if (error) {
      setError("");
    }
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError("");
    setFieldErrors({});

    // Client-side validation
    const errors: typeof fieldErrors = {};
    if (!formData.username.trim()) {
      errors.username = "Username is required";
    }
    if (!formData.email.trim()) {
      errors.email = "Email is required";
    } else {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
      if (!emailRegex.test(formData.email)) {
        errors.email = "Invalid email format";
      }
    }
    if (!formData.password.trim()) {
      errors.password = "Password is required";
    } else if (formData.password.length < 8) {
      errors.password = "Password must be at least 8 characters long";
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      setLoading(false);
      return;
    }

    try {
      const result = await createUser(formData);
      if (result.error) {
        setError(result.error);
        // Try to parse field-specific errors from server response
        if (result.error.toLowerCase().includes("username")) {
          setFieldErrors((prev) => ({ ...prev, username: result.error }));
        } else if (result.error.toLowerCase().includes("email")) {
          setFieldErrors((prev) => ({ ...prev, email: result.error }));
        } else if (result.error.toLowerCase().includes("password")) {
          setFieldErrors((prev) => ({ ...prev, password: result.error }));
        }
      } else {
        onSuccess();
      }
    } catch (err: any) {
      setError(err.message || "An error occurred while creating the user.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <form onSubmit={handleSubmit} className="mt-8 space-y-6">
      <div className="space-y-4">
        <div>
          <TextField
            label="Username"
            name="username"
            value={formData.username}
            onChange={handleChange}
            required
            fullWidth
            autoComplete="username"
            error={!!fieldErrors.username}
            aria-describedby={fieldErrors.username ? "username-error" : undefined}
            aria-invalid={!!fieldErrors.username}
          />
          {fieldErrors.username && (
            <div
              id="username-error"
              role="alert"
              aria-live="polite"
              className="mt-2"
            >
              <p className="text-sm text-red-500 flex items-center gap-1">
                <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                <span>{fieldErrors.username}</span>
              </p>
              {fieldErrors.username.includes("required") && (
                <p className="text-xs text-gray-600 mt-1 ml-5">
                  Suggestion: Enter a unique username for the new user.
                </p>
              )}
            </div>
          )}
        </div>
        <div>
          <TextField
            label="Email"
            name="email"
            type="email"
            value={formData.email}
            onChange={handleChange}
            required
            fullWidth
            autoComplete="email"
            error={!!fieldErrors.email}
            aria-describedby={fieldErrors.email ? "email-error" : undefined}
            aria-invalid={!!fieldErrors.email}
          />
          {fieldErrors.email && (
            <div
              id="email-error"
              role="alert"
              aria-live="polite"
              className="mt-2"
            >
              <p className="text-sm text-red-500 flex items-center gap-1">
                <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                <span>{fieldErrors.email}</span>
              </p>
              {fieldErrors.email.includes("required") && (
                <p className="text-xs text-gray-600 mt-1 ml-5">
                  Suggestion: Enter an email address for the new user.
                </p>
              )}
              {fieldErrors.email.includes("Invalid") && (
                <p className="text-xs text-gray-600 mt-1 ml-5">
                  Suggestion: Use a valid email format, for example: user@example.com
                </p>
              )}
            </div>
          )}
        </div>
        <div>
          <TextField
            label="Password"
            name="password"
            type="password"
            value={formData.password}
            onChange={handleChange}
            required
            fullWidth
            autoComplete="new-password"
            error={!!fieldErrors.password}
            aria-describedby={fieldErrors.password ? "password-error" : undefined}
            aria-invalid={!!fieldErrors.password}
          />
          {fieldErrors.password && (
            <div
              id="password-error"
              role="alert"
              aria-live="polite"
              className="mt-2"
            >
              <p className="text-sm text-red-500 flex items-center gap-1">
                <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                <span>{fieldErrors.password}</span>
              </p>
              {fieldErrors.password.includes("required") && (
                <p className="text-xs text-gray-600 mt-1 ml-5">
                  Suggestion: Enter a password for the new user.
                </p>
              )}
              {fieldErrors.password.includes("8 characters") && (
                <p className="text-xs text-gray-600 mt-1 ml-5">
                  Suggestion: Use at least 8 characters. Consider using a mix of letters, numbers, and special characters for better security.
                </p>
              )}
            </div>
          )}
        </div>
        {error && !Object.keys(fieldErrors).length && (
          <div className="text-sm text-red-500 mt-2 flex items-center gap-1" role="alert">
            <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        )}
        <Button
          type="submit"
          variant="contained"
          fullWidth
          disabled={loading}
          className="mt-4"
        >
          {loading ? "Creating User..." : "Create User"}
        </Button>
      </div>
    </form>
  );
}
