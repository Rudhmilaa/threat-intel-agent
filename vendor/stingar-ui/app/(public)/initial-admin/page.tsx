"use client";

export const dynamic = "force-dynamic";

import { Suspense, useEffect, useState, useCallback } from "react";
import { checkAdminUser } from "@/lib/actions";
import { InitialAdminForm } from "./form";
import { useSearchParams, useRouter } from "next/navigation";
import Image from "next/image";
import stingarLogo from "@/public/images/stingar_label.svg";

function InitialAdminContent() {
    const router = useRouter();
    const [loading, setLoading] = useState(true);
    const [statusMessage, setStatusMessage] = useState("");
    const [adminUser, setAdminUser] = useState<any>(null);
    const [error, setError] = useState("");
    const searchParams = useSearchParams();
    const origin = searchParams.get("origin") || "/";

    const runCheck = useCallback(async () => {
        setLoading(true);
        setError("");
        setStatusMessage("");
        const maxAttempts = 5;
        const retryDelayMs = 4000;

        for (let attempt = 1; attempt <= maxAttempts; attempt++) {
            const result = await checkAdminUser();
            const { admin, errorType } = result;

            if (admin && admin.hasPassword) {
                router.push('/login');
                return;
            }
            if (admin && !admin.hasPassword) {
                setAdminUser(admin);
                return;
            }
            if (errorType === 'not_found') {
                setError("Admin user not found in database. Please contact system administrator.");
                return;
            }

            const shouldRetry = (errorType === 'unauthorized' || errorType === 'network' || errorType === 'server_error') && attempt < maxAttempts;
            if (shouldRetry) {
                setStatusMessage(`Backend starting... retrying in a moment (${attempt} of ${maxAttempts})`);
                await new Promise((r) => setTimeout(r, retryDelayMs));
                continue;
            }

            if (errorType === 'unauthorized') {
                setError("Unable to connect to the API. The API key may not be configured yet. Please wait a moment for the backend to finish starting, then click Retry.");
            } else if (errorType === 'server_error') {
                setError("The backend is temporarily unavailable. Please wait a moment and click Retry.");
            } else {
                setError("Unable to reach the backend. Please ensure the platform is running, then click Retry.");
            }
            return;
        }
    }, [router]);

    const handleRetry = useCallback(() => {
        runCheck().finally(() => setLoading(false));
    }, [runCheck]);

    useEffect(() => {
        runCheck().finally(() => setLoading(false));
    }, [runCheck]);

    if (loading && !error) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen p-4 bg-[#363636]">
                <p className="text-gray-300">Loading...</p>
                {statusMessage && <p className="text-gray-400 text-sm mt-2">{statusMessage}</p>}
            </div>
        );
    }

    if (error) {
        return (
            <div className="flex flex-col items-center justify-center min-h-screen p-4 bg-[#363636]">
                <p className="text-red-500 text-center mb-4">{error}</p>
                <button
                    onClick={handleRetry}
                    className="px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700"
                >
                    Retry
                </button>
            </div>
        );
    }

    return (
        <div className="flex items-center justify-center min-h-screen p-4 bg-[#363636]">
            <div className="w-1/3">
                <div className="flex justify-center mb-14">
                    <Image src={stingarLogo} alt="Logo" width={270} />
                </div>
                <div className="mt-6">
                    <div className="text-center mb-8">
                        <h1 className="text-2xl font-semibold text-white mb-2">Welcome to STINGAR</h1>
                        <p className="text-gray-300">This is your first time logging in. Please set up your admin account password below.</p>
                    </div>
                    <InitialAdminForm adminUser={adminUser} origin={origin} />
                </div>
            </div>
        </div>
    );
}

export default function Page() {
    return (
        <Suspense fallback={<div className="flex items-center justify-center min-h-screen p-4 bg-[#363636]">Loading...</div>}>
            <InitialAdminContent />
        </Suspense>
    );
} 