"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { Button, TextField } from "@mui/material";
import { setInitialAdminPassword } from "@/lib/actions";
import { AlertCircle } from "lucide-react";

interface InitialAdminFormProps {
    adminUser: {
        id: string;
        username: string;
    };
    origin: string;
}

export function InitialAdminForm({ adminUser, origin }: InitialAdminFormProps) {
    const router = useRouter();
    const [loading, setLoading] = useState(false);
    const [error, setError] = useState("");
    const [password, setPassword] = useState("");
    const [passwordConfirmation, setPasswordConfirmation] = useState("");
    const [passwordError, setPasswordError] = useState("");
    const [passwordConfirmationError, setPasswordConfirmationError] = useState("");

    const handleSubmit = async (e: React.FormEvent) => {
        e.preventDefault();
        setError("");
        setPasswordError("");
        setPasswordConfirmationError("");
        setLoading(true);

        // Validate password
        if (!password) {
            setPasswordError("Password is required");
            setLoading(false);
            return;
        }
        if (password.length < 8) {
            setPasswordError("Password must be at least 8 characters long");
            setLoading(false);
            return;
        }

        // Validate password confirmation
        if (!passwordConfirmation) {
            setPasswordConfirmationError("Password confirmation is required");
            setLoading(false);
            return;
        }

        if (password !== passwordConfirmation) {
            setError("Passwords didn't match. Admin password was not set.");
            setPasswordConfirmationError("Passwords do not match");
            setLoading(false);
            return;
        }

        try {
            const result = await setInitialAdminPassword({
                id: adminUser.id,
                username: adminUser.username,
                password,
                password_confirmation: passwordConfirmation
            });

            if (result.error) {
                setError(result.error);
            } else {
                // After successful password setup, redirect to login
                router.push('/login');
            }
        } catch (error: any) {
            console.error("Error setting admin password:", error);
            setError(error.message || "Failed to set admin password");
        } finally {
            setLoading(false);
        }
    };

    return (
        <form onSubmit={handleSubmit} className="mt-8 space-y-6">
            {error && (
                <div className="text-red-500 text-sm text-center flex items-center justify-center gap-1" role="alert">
                    <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                    <span>{error}</span>
                </div>
            )}
            <div className="space-y-4">
                <div>
                    <TextField
                        label="Password"
                        type="password"
                        value={password}
                        onChange={(e) => {
                            setPassword(e.target.value);
                            setPasswordError("");
                        }}
                        required
                        fullWidth
                        disabled={loading}
                        autoComplete="new-password"
                        error={!!passwordError}
                        aria-describedby={passwordError ? "password-error" : undefined}
                        aria-invalid={!!passwordError}
                    />
                    {passwordError && (
                        <div
                            id="password-error"
                            role="alert"
                            aria-live="polite"
                            className="mt-2"
                        >
                            <p className="text-sm text-red-500 flex items-center gap-1">
                                <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                                <span>{passwordError}</span>
                            </p>
                            {passwordError.includes("required") && (
                                <p className="text-xs text-gray-600 mt-1 ml-5">
                                    Suggestion: Enter a password to secure your admin account.
                                </p>
                            )}
                            {passwordError.includes("8 characters") && (
                                <p className="text-xs text-gray-600 mt-1 ml-5">
                                    Suggestion: Use at least 8 characters. Consider using a mix of letters, numbers, and special characters for better security.
                                </p>
                            )}
                        </div>
                    )}
                </div>
                <div>
                    <TextField
                        label="Confirm Password"
                        type="password"
                        value={passwordConfirmation}
                        onChange={(e) => {
                            setPasswordConfirmation(e.target.value);
                            setPasswordConfirmationError("");
                        }}
                        required
                        fullWidth
                        disabled={loading}
                        autoComplete="new-password"
                        error={!!passwordConfirmationError || !!error}
                        aria-describedby={passwordConfirmationError || error ? "password-confirmation-error" : undefined}
                        aria-invalid={!!passwordConfirmationError || !!error}
                    />
                    {(passwordConfirmationError || (error && error.includes("didn't match"))) && (
                        <div
                            id="password-confirmation-error"
                            role="alert"
                            aria-live="polite"
                            className="mt-2"
                        >
                            {passwordConfirmationError && (
                                <p className="text-sm text-red-500 flex items-center gap-1">
                                    <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                                    <span>{passwordConfirmationError}</span>
                                </p>
                            )}
                            {passwordConfirmationError?.includes("required") && (
                                <p className="text-xs text-gray-600 mt-1 ml-5">
                                    Suggestion: Re-enter your password to confirm it matches.
                                </p>
                            )}
                            {error && error.includes("didn't match") && (
                                <p className="text-sm text-red-500 flex items-center gap-1">
                                    <AlertCircle className="h-4 w-4 flex-shrink-0" aria-hidden="true" />
                                    <span>{error}</span>
                                </p>
                            )}
                            {(passwordConfirmationError?.includes("do not match") || (error?.includes("didn't match"))) && (
                                <p className="text-xs text-gray-600 mt-1 ml-5">
                                    Suggestion: Make sure both password fields contain the exact same password. Check for typos or extra spaces.
                                </p>
                            )}
                        </div>
                    )}
                </div>
            </div>
            <Button
                type="submit"
                variant="contained"
                fullWidth
                disabled={loading}
                className="mt-4"
            >
                {loading ? "Setting Password..." : "Set Password"}
            </Button>
        </form>
    );
} 