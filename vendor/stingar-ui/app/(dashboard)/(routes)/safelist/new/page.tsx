"use client";

import { useState, useTransition } from "react";
import { usePageTitle } from "@/lib/hooks/use-page-title";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import NextLink from "next/link";
import { ArrowLeft } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { createSafelistEntry } from "@/lib/mellis-actions";

function detectType(value: string): string {
  const v = value.trim();
  if (/^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(v)) return "cidr4";
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(v)) return "ipv4";
  if (v.includes(":") && v.includes("/")) return "cidr6";
  if (v.includes(":")) return "ipv6";
  return "domain";
}

export default function NewSafelistEntryPage() {
  usePageTitle("Safelist: Add entry");
  const router = useRouter();
  const [isPending, startTransition] = useTransition();

  const [value, setValue] = useState("");
  const [label, setLabel] = useState("");
  const [error, setError] = useState<string | null>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!value.trim()) {
      setError("IP, CIDR, or domain is required.");
      return;
    }
    startTransition(async () => {
      try {
        await createSafelistEntry({
          type: detectType(value),
          value: value.trim(),
          label: label.trim() || null,
          source: "manual",
        });
        router.push("/safelist");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Failed to create entry");
      }
    });
  };

  return (
    <div className="flex flex-col gap-6 max-w-2xl">
      <NextLink href="/safelist">
        <Button variant="ghost" size="sm" className="gap-1">
          <ArrowLeft className="h-4 w-4" aria-hidden />
          Back to Safelist
        </Button>
      </NextLink>

      <h1 className="text-xl font-bold text-left">Safelist: Add entry</h1>

      <form onSubmit={handleSubmit}>
        <Card>
          <CardHeader>
            <CardTitle>New safelist entry (never block)</CardTitle>
          </CardHeader>
          <CardContent className="flex flex-col gap-4">
            {error && (
              <p className="text-sm text-destructive" role="alert">
                {error}
              </p>
            )}
            <div>
              <Label htmlFor="value">IP, CIDR, or Domain *</Label>
              <Input
                id="value"
                value={value}
                onChange={(e) => {
                  setValue(e.target.value);
                  setError(null);
                }}
                placeholder="e.g. 10.0.0.0/8 or 192.168.1.1"
                className="font-mono"
                aria-required="true"
                aria-invalid={!!error}
              />
            </div>
            <div>
              <Label htmlFor="label">Label (optional)</Label>
              <Input
                id="label"
                value={label}
                onChange={(e) => setLabel(e.target.value)}
                placeholder="e.g. Trusted scanner"
              />
            </div>
            <div className="flex gap-2">
              <Button type="submit" disabled={isPending}>
                {isPending ? "Saving..." : "Save"}
              </Button>
              <NextLink href="/safelist">
                <Button type="button" variant="outline">Cancel</Button>
              </NextLink>
            </div>
          </CardContent>
        </Card>
      </form>
    </div>
  );
}
