"use client";

import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@mui/material";
import { Alert, AlertTitle } from "@mui/material";
import { Loader2 } from "lucide-react";
import { useStoreRegistration } from "@/lib/hooks/use-store-registration";

export function StoreRegistration() {
    const { isRegistered, isRegistering, error, registerInstance } = useStoreRegistration();

    if (isRegistered) {
        return (
            <Alert 
                severity="success" 
                className="mb-4"
                role="status"
                aria-live="polite"
                aria-atomic="true"
            >
                <AlertTitle>Successfully connected to HP App Store</AlertTitle>
            </Alert>
        );
    }

    return (
        <Card className="mb-4">
            <CardHeader>
                <CardTitle>HP App Store Registration</CardTitle>
                <CardDescription>
                    Register your STINGAR instance to access the honeypot store
                </CardDescription>
            </CardHeader>
            <CardContent>
                {error && (
                    <Alert severity="error" className="mb-4">
                        <AlertTitle>Registration Error</AlertTitle>
                        {error}
                    </Alert>
                )}

                <div className="space-y-4">
                    <p className="text-sm text-muted-foreground">
                        Your STINGAR instance needs to be registered with the HP App Store to access honeypot configurations.
                        This will automatically generate an API key and store it securely.
                    </p>

                    <Button
                        onClick={registerInstance}
                        disabled={isRegistering}
                        variant="contained"
                        fullWidth
                        startIcon={isRegistering ? <Loader2 className="h-4 w-4 animate-spin" /> : null}
                    >
                        {isRegistering ? 'Registering...' : 'Register Instance'}
                    </Button>
                </div>
            </CardContent>
        </Card>
    );
}

