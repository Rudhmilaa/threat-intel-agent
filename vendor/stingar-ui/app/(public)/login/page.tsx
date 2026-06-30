"use client";

import { LoginForm } from "@/app/(public)/login/form";
import Image from "next/image";
import stingarLogo from "@/public/images/stingar_label.svg";
import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { checkAdminUser } from "@/lib/actions";
import { usePageTitle } from "@/lib/hooks/use-page-title";

export default function Page() {
  const router = useRouter();
  const [loading, setLoading] = useState(true);
  usePageTitle("Login");

    useEffect(() => {
    const checkAdmin = async () => {
      try {
        const { admin } = await checkAdminUser();
        if (admin && !admin.hasPassword) {
          router.push('/initial-admin');
        }
      } catch (error) {
        if (process.env.NODE_ENV === 'development') {
          console.debug("API backend not available (expected in local dev):", error);
        } else {
          console.error("Error checking admin user:", error);
        }
      } finally {
        setLoading(false);
      }
    };

    checkAdmin();
  }, [router]);

  if (loading) {
    return <div className="flex items-center justify-center min-h-screen p-4 bg-[#363636]">Loading...</div>;
  }

  return (
    <div className="flex items-center justify-center min-h-screen p-4 bg-[#363636] py-12">
      <div className="w-full max-w-md">
        <div className="flex justify-center mb-10">
          <Image src={stingarLogo} alt="STINGAR Logo" width={270} priority />
        </div>
        <div className="mt-6 pt-2">
          <LoginForm />
        </div>
      </div>
    </div>
  );
}
