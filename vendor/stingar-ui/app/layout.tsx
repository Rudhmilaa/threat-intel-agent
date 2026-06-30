import type { Metadata } from "next";
import { Inter, Montserrat, Space_Grotesk } from "next/font/google";
import "./globals.css";
import { Providers } from "./providers";
import { Toaster } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";
import { initializeDebugControls } from "@/lib/debug-controls";

const inter = Inter({ subsets: ["latin"] });
const monterrat = Montserrat({ subsets: ["latin"] });
const spaceGrotesk = Space_Grotesk({
  subsets: ["latin"],
  weight: ["300", "400", "500", "600", "700"],
  display: "swap",
});

export const metadata: Metadata = {
  title: "STINGAR",
  description: "Shared Threat Intelligence for Higher Education & Research",
};

export default function RootLayout({ children }: { children: React.ReactNode }) {
  // Initialize debug controls in development
  if (process.env.NODE_ENV === 'development') {
    initializeDebugControls();
  }

  return (
    <html lang="en">
      <body>
        <Providers>
          <a 
            href="#main-content" 
            className="sr-only focus:not-sr-only focus:absolute focus:top-0 focus:left-0 focus:z-[9999] focus:p-4 focus:bg-blue-600 focus:text-white focus:font-bold focus:rounded-br-md focus:shadow-lg"
          >
            Skip to main content
          </a>
          {children}
          <Toaster />
        </Providers>
      </body>
    </html>
  );
}
